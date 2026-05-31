#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""TruffleHog secret scanning for explicitly supplied AWS S3 buckets."""

import hashlib
import json
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Dict, Iterable, List, Optional

from modules.base import ModuleResult, ScannerModule, ScanTarget
from modules.s3_bucket_impact import S3BucketImpactModule


class TruffleHogS3Module(ScannerModule):
    name = "trufflehog_s3"
    description = "Runs TruffleHog secret detection against supplied AWS S3 buckets"
    _warning_lock = threading.Lock()
    _warnings = set()

    def scan(self, target: ScanTarget, timeout: int, sample_size: int) -> Iterable[ModuleResult]:
        bucket = S3BucketImpactModule()._bucket_from_target(target)
        binary = shutil.which("trufflehog")
        if not bucket:
            return
        if not binary:
            self._warn_once("missing_binary", "trufflehog binary was not found in PATH; trufflehog_s3 scan skipped")
            return

        started = time.time()
        command = [binary, "s3", f"--bucket={bucket}", "--json", "--no-update"]
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
                timeout=max(300, timeout * 60),
            )
        except subprocess.TimeoutExpired:
            self._warn_once("timeout", "trufflehog_s3 scan timed out; increase --timeout for large buckets")
            return
        except OSError:
            self._warn_once("execution_error", "trufflehog_s3 could not execute the trufflehog binary")
            return

        findings = self._parse_json_lines(completed.stdout, bucket, sample_size)
        if not findings:
            if completed.returncode != 0:
                self._warn_once("nonzero_exit", "trufflehog_s3 scan exited with an error; no findings were recorded")
            return

        verified_count = sum(1 for item in findings if item["verified"])
        detectors = sorted({item["detector"] for item in findings})
        severity_score = 95 if verified_count else 20
        yield ModuleResult(
            module=self.name,
            url=f"s3://{bucket}",
            host=bucket,
            scheme="s3",
            accessible=True,
            severity_score=severity_score,
            detected_rules=["verified_secret"] if verified_count else ["unverified_secret"],
            sample_data={
                "secret_detectors": {
                    "category": "CRITICAL" if verified_count else "MEDIUM",
                    "description": "TruffleHog secret detectors matched redacted material",
                    "matched": detectors,
                    "severity": 10 if verified_count else 5,
                },
            },
            response_time=time.time() - started,
            details={
                "bucket": bucket,
                "notification_priority": "urgent" if verified_count else "medium",
                "trufflehog_findings": findings,
                "trufflehog_verified_count": verified_count,
                "trufflehog_unverified_count": len(findings) - verified_count,
                "trufflehog_exit_code": completed.returncode,
                "evidence": [
                    f"trufflehog:findings={len(findings)}",
                    f"trufflehog:verified={verified_count}",
                    f"trufflehog:unverified={len(findings) - verified_count}",
                ],
            },
        )

    def _parse_json_lines(self, stdout: str, bucket: str, sample_size: int) -> List[Dict]:
        findings = []
        seen = set()
        limit = max(1, min(sample_size, 1000))
        for line in stdout.splitlines():
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue

            finding = self._sanitize_finding(payload, bucket)
            key = (finding["detector"], finding["object_key"], finding["fingerprint"], finding["verified"])
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
            if len(findings) >= limit:
                break
        return findings

    def _sanitize_finding(self, payload: Dict, bucket: str) -> Dict:
        raw = str(payload.get("RawV2") or payload.get("Raw") or "")
        redacted = self._redact(raw or str(payload.get("Redacted") or ""))
        metadata = payload.get("SourceMetadata") or {}
        return {
            "detector": str(payload.get("DetectorName") or payload.get("DetectorType") or "unknown"),
            "decoder": str(payload.get("DecoderName") or "unknown"),
            "verified": bool(payload.get("Verified")),
            "bucket": self._find_metadata_value(metadata, "bucket") or bucket,
            "object_key": self._redact_key(self._find_metadata_value(metadata, "key") or "unknown"),
            "redacted": redacted[:240],
            "fingerprint": hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()[:16],
        }

    def _find_metadata_value(self, value, wanted_key: str) -> Optional[str]:
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key).lower() == wanted_key and item:
                    return str(item)
                found = self._find_metadata_value(item, wanted_key)
                if found:
                    return found
        elif isinstance(value, list):
            for item in value:
                found = self._find_metadata_value(item, wanted_key)
                if found:
                    return found
        return None

    def _redact(self, raw: str) -> str:
        if not raw:
            return "<redacted>"
        if len(raw) <= 8:
            return "<redacted>"
        return f"{raw[:4]}...{raw[-4:]}"

    def _redact_key(self, key: str) -> str:
        return re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key)=([^/&\s]+)", r"\1=<redacted>", key)

    def _warn_once(self, key: str, message: str):
        with self._warning_lock:
            if key in self._warnings:
                return
            self._warnings.add(key)
        print(f"[!] {message}", file=sys.stderr, flush=True)
