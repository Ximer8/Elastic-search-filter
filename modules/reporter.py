#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Evidence-backed report generation for confirmed scanner findings."""

import html
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List


CRITICAL_SCORE = 30
REPORTABLE_SCORE = 10
SCREENSHOT_SEVERITY = "critical"
CONFIRMED_S3_RULES = {
    "public_bucket_listing",
    "public_object_read",
    "secrets",
    "private_keys",
    "database_backups",
    "logs",
    "pii_named",
    "source_code",
}
CONFIRMED_ES_RULES = {
    "credentials",
    "passwords",
    "pii",
    "medical",
    "financial",
    "support_chats",
    "internal_notes",
    "production",
    "cloud_metadata",
    "backups",
    "cicd",
    "auth_logs",
    "ransomware_note",
}
CONFIRMED_LARAVEL_RULES = {
    "laravel_debug",
    "server_error_debug",
    "stack_trace",
    "env_secrets",
}


def write_critical_reports(results: List[dict], output_dir: str, screenshots: bool = True, verbose: bool = False) -> List[str]:
    os.makedirs(output_dir, exist_ok=True)
    written = []
    reportable = [result for result in results if is_reportable_critical_finding(result)]

    if verbose:
        print(f"[*] Generating evidence reports: {len(reportable)} finding(s)", flush=True)

    for idx, result in enumerate(reportable, 1):
        severity = severity_bucket(result)
        module = result.get("module", "unknown")
        target = result.get("url") or result.get("host") or result.get("bucket") or "unknown"
        if verbose:
            print(f"[*] Report {idx}/{len(reportable)} [{severity}] {module}: {target}", flush=True)

        report_dir = os.path.join(output_dir, severity, _report_dir_name(result))
        os.makedirs(report_dir, exist_ok=True)

        files = {
            "report": os.path.join(report_dir, "report.md"),
            "evidence": os.path.join(report_dir, "evidence.json"),
            "snapshot_html": os.path.join(report_dir, "proof_snapshot.html"),
            "snapshot_svg": os.path.join(report_dir, "proof_snapshot.svg"),
            "screenshot": os.path.join(report_dir, "proof_screenshot.png"),
        }

        _write_text(files["report"], build_report(result))
        _write_json(files["evidence"], build_evidence_bundle(result))
        _write_text(files["snapshot_html"], build_proof_snapshot_html(result))
        _write_text(files["snapshot_svg"], build_proof_snapshot_svg(result))
        if screenshots and severity == SCREENSHOT_SEVERITY:
            if verbose:
                print(f"    screenshots: {files['screenshot']} (+ impact/validation)", flush=True)
            write_proof_screenshot(files["snapshot_html"], files["screenshot"], result)
        elif verbose:
            print("    screenshot: skipped for non-critical severity", flush=True)
        if verbose:
            print(f"    written: {report_dir}", flush=True)
        written.append(report_dir)

    return written


def is_reportable_critical_finding(result: Dict) -> bool:
    module = result.get("module")
    if module == "s3_bucket_impact":
        return is_confirmed_s3(result)
    if module == "elasticsearch":
        return is_confirmed_elasticsearch(result)
    if module == "laravel_debug":
        return is_confirmed_laravel_debug(result)
    if module == "trufflehog_s3":
        return is_confirmed_trufflehog_s3(result)
    return False


def severity_bucket(result: Dict) -> str:
    score = result.get("severity_score", 0)
    if score >= 50:
        return "critical"
    if score >= 30:
        return "high"
    if score >= 10:
        return "medium"
    return "low"


def is_reportable_critical_s3(result: Dict) -> bool:
    return is_confirmed_critical_s3(result) and (result.get("environment") or "").lower() == "production"


def is_confirmed_critical_s3(result: Dict) -> bool:
    return is_confirmed_s3(result) and result.get("severity_score", 0) >= CRITICAL_SCORE


def is_confirmed_s3(result: Dict) -> bool:
    if result.get("severity_score", 0) < REPORTABLE_SCORE:
        return False

    if not result.get("accessible"):
        return False

    if result.get("severity_score", 0) < CRITICAL_SCORE:
        rules = set(result.get("detected_rules") or [])
        return "bucket_public_head" in rules and bool(result.get("status_codes"))

    rules = set(result.get("detected_rules") or [])
    status_codes = result.get("status_codes") or {}
    checked_objects = result.get("checked_objects") or []

    confirmed_listing = (
        "public_bucket_listing" in rules
        and status_codes.get("list_objects") == 200
        and result.get("listed_objects", 0) > 0
    )
    confirmed_public_read = (
        "public_object_read" in rules
        and any(item.get("public_read") and item.get("status") == 200 for item in checked_objects)
    )
    confirmed_sensitive_listing = bool(rules & CONFIRMED_S3_RULES) and confirmed_listing

    return confirmed_listing or confirmed_public_read or confirmed_sensitive_listing


def is_confirmed_critical_elasticsearch(result: Dict) -> bool:
    return is_confirmed_elasticsearch(result) and result.get("severity_score", 0) >= CRITICAL_SCORE


def is_confirmed_elasticsearch(result: Dict) -> bool:
    if result.get("severity_score", 0) < REPORTABLE_SCORE:
        return False
    if not result.get("accessible"):
        return False

    rules = set(result.get("detected_rules") or [])
    if not rules or not (rules & CONFIRMED_ES_RULES):
        return False

    has_es_identity = bool(result.get("cluster_name") or result.get("version"))
    has_indices_metadata = result.get("indices_count", 0) > 0
    return has_es_identity or has_indices_metadata


def is_confirmed_laravel_debug(result: Dict) -> bool:
    if result.get("severity_score", 0) < REPORTABLE_SCORE:
        return False
    if not result.get("accessible"):
        return False

    rules = set(result.get("detected_rules") or [])
    if "laravel_debug" not in rules or not (rules & CONFIRMED_LARAVEL_RULES):
        return False

    evidence = [str(item).lower() for item in result.get("evidence") or []]
    has_laravel_signal = any(item.startswith("laravel:") for item in evidence)
    has_debug_signal = any(item.startswith(("debug:", "secret:")) for item in evidence)
    status_codes = result.get("status_codes") or {}
    has_http_evidence = any(int(code or 0) >= 200 for code in status_codes.values())
    return has_laravel_signal and has_debug_signal and has_http_evidence


def is_confirmed_trufflehog_s3(result: Dict) -> bool:
    if result.get("severity_score", 0) < REPORTABLE_SCORE:
        return False
    return result.get("trufflehog_verified_count", 0) > 0 and any(
        item.get("verified") for item in result.get("trufflehog_findings") or []
    )


def build_report(result: Dict) -> str:
    if result.get("module") == "elasticsearch":
        return build_elasticsearch_report(result)
    if result.get("module") == "laravel_debug":
        return build_laravel_debug_report(result)
    if result.get("module") == "trufflehog_s3":
        return build_trufflehog_s3_report(result)
    return build_s3_report(result)


def build_evidence_bundle(result: Dict) -> Dict:
    if result.get("module") == "elasticsearch":
        return build_elasticsearch_evidence_bundle(result)
    if result.get("module") == "laravel_debug":
        return build_laravel_debug_evidence_bundle(result)
    if result.get("module") == "trufflehog_s3":
        return build_trufflehog_s3_evidence_bundle(result)

    return {
        "generated_at": _now_iso(),
        "module": result.get("module"),
        "bucket": result.get("bucket"),
        "url": result.get("url"),
        "region": result.get("region") or "unknown",
        "severity_score": result.get("severity_score", 0),
        "priority": result.get("notification_priority") or "unknown",
        "detected_rules": result.get("detected_rules") or [],
        "confirmation": {
            "confirmed_critical": is_confirmed_critical_s3(result),
            "confirmed": is_confirmed_s3(result),
            "reportable": is_confirmed_s3(result),
            "reporting_gate": "confirmed S3 finding with anonymous HTTP evidence",
            "basis": _confirmation_basis(result),
            "status_codes": result.get("status_codes") or {},
        },
        "sample_data": _redact_sample_data(result.get("sample_data") or {}),
        "checked_objects": _redact_checked_objects(result.get("checked_objects") or []),
        "evidence": result.get("evidence") or [],
        "environment": result.get("environment") or "unknown",
        "environment_confidence": result.get("environment_confidence", 0),
        "notes": [
            "Object contents were not downloaded by this reporter.",
            "Evidence is based on anonymous HTTP responses and object names returned by S3 listing.",
            "PNG screenshots are generated only for findings in the critical severity folder.",
        ],
        "anonymous_validation": _anonymous_validation(result),
    }


def build_laravel_debug_evidence_bundle(result: Dict) -> Dict:
    return {
        "generated_at": _now_iso(),
        "module": result.get("module"),
        "url": result.get("url"),
        "host": result.get("host"),
        "port": result.get("port"),
        "scheme": result.get("scheme"),
        "accessible": bool(result.get("accessible")),
        "severity": severity_bucket(result),
        "severity_score": result.get("severity_score", 0),
        "priority": result.get("notification_priority") or "unknown",
        "detected_rules": result.get("detected_rules") or [],
        "confirmation": {
            "confirmed": is_confirmed_laravel_debug(result),
            "reportable": is_confirmed_laravel_debug(result),
            "reporting_gate": "confirmed Laravel debug exposure with Laravel and debug/secret evidence",
            "basis": _laravel_confirmation_basis(result),
            "status_codes": result.get("status_codes") or {},
        },
        "sample_data": _redact_sample_data(result.get("sample_data") or {}),
        "evidence": result.get("evidence") or [],
        "checked_paths": result.get("checked_paths") or [],
        "owner": result.get("owner") or {},
        "false_positive_confidence": result.get("false_positive_confidence", 0),
        "environment": result.get("environment") or "unknown",
        "environment_confidence": result.get("environment_confidence", 0),
        "environment_signals": result.get("environment_signals") or [],
        "response_time": result.get("response_time", 0.0),
        "notes": [
            "This reporter documents Laravel debug exposure evidence and does not store full page bodies.",
            "PNG screenshots are generated only for findings in the critical severity folder.",
        ],
        "anonymous_validation": _anonymous_validation(result),
    }


def build_elasticsearch_evidence_bundle(result: Dict) -> Dict:
    return {
        "generated_at": _now_iso(),
        "module": result.get("module"),
        "url": result.get("url"),
        "host": result.get("host"),
        "port": result.get("port"),
        "scheme": result.get("scheme"),
        "cluster_name": result.get("cluster_name") or "unknown",
        "version": result.get("version") or "unknown",
        "indices_count": result.get("indices_count", 0),
        "accessible": bool(result.get("accessible")),
        "severity_score": result.get("severity_score", 0),
        "detected_rules": result.get("detected_rules") or [],
        "confirmation": {
            "confirmed_critical": is_confirmed_critical_elasticsearch(result),
            "reportable": is_confirmed_elasticsearch(result),
            "reporting_gate": "confirmed Elasticsearch finding with identity metadata and detection rules",
            "basis": _elasticsearch_confirmation_basis(result),
        },
        "sample_data": _redact_sample_data(result.get("sample_data") or {}),
        "environment": result.get("environment") or "unknown",
        "environment_confidence": result.get("environment_confidence", 0),
        "environment_signals": result.get("environment_signals") or [],
        "response_time": result.get("response_time", 0.0),
        "notes": [
            "This reporter uses scanner metadata and keyword matches; it does not dump full Elasticsearch documents.",
            "Evidence is based on successful unauthenticated Elasticsearch identification plus critical detection rules.",
            "PNG screenshots are generated for confirmed critical Elasticsearch report packages.",
        ],
        "anonymous_validation": _anonymous_validation(result),
    }


def build_trufflehog_s3_evidence_bundle(result: Dict) -> Dict:
    return {
        "generated_at": _now_iso(),
        "module": result.get("module"),
        "bucket": result.get("bucket") or result.get("host"),
        "url": result.get("url"),
        "severity_score": result.get("severity_score", 0),
        "priority": result.get("notification_priority") or "unknown",
        "confirmation": {
            "confirmed": is_confirmed_trufflehog_s3(result),
            "reportable": is_confirmed_trufflehog_s3(result),
            "reporting_gate": "at least one TruffleHog detector result with Verified=true",
            "basis": _trufflehog_confirmation_basis(result),
        },
        "verified_count": result.get("trufflehog_verified_count", 0),
        "unverified_count": result.get("trufflehog_unverified_count", 0),
        "findings": result.get("trufflehog_findings") or [],
        "notes": [
            "Raw secrets are never stored by this integration.",
            "Findings include only detector metadata, redacted previews, source object keys, and fingerprints.",
            "PNG screenshots are generated only for findings in the critical severity folder.",
        ],
        "verification": _anonymous_validation(result),
    }


def build_trufflehog_s3_report(result: Dict) -> str:
    bucket = result.get("bucket") or result.get("host") or "unknown"
    findings = result.get("trufflehog_findings") or []
    lines = [
        f"# Confirmed TruffleHog Secret Exposure: {bucket}",
        "",
        "## Summary",
        f"- Bucket: `{bucket}`",
        f"- URL: `{result.get('url', '')}`",
        f"- Severity score: `{result.get('severity_score', 0)}/100`",
        f"- Priority: `{result.get('notification_priority') or 'unknown'}`",
        f"- Verified secrets: `{result.get('trufflehog_verified_count', 0)}`",
        f"- Unverified matches: `{result.get('trufflehog_unverified_count', 0)}`",
        f"- Generated: `{_now_iso()}`",
        "",
        "## Confirmation",
    ]
    lines.extend(f"- {item}" for item in _trufflehog_confirmation_basis(result))
    lines.extend([
        "",
        "## Impact",
        "- TruffleHog reported at least one verified secret in the supplied S3 bucket.",
        "- Treat verified credentials as compromised until they are revoked, rotated, and reviewed.",
        "",
        "## Verified Findings",
    ])
    for item in findings:
        if item.get("verified"):
            lines.append(
                f"- `{item.get('detector')}` in `{item.get('object_key')}`: "
                f"`{item.get('redacted')}` (fingerprint `{item.get('fingerprint')}`)"
            )
    lines.extend([
        "",
        "## Verification",
    ])
    lines.extend(_anonymous_validation_lines(result))
    lines.extend([
        "",
        "## Evidence",
        "- Evidence files: `evidence.json`, `proof_snapshot.html`, `proof_snapshot.svg`",
    ])
    lines.extend(_screenshot_report_lines(result))
    lines.extend([
        "",
        "## Recommended Remediation",
        "1. Revoke or rotate every verified credential immediately.",
        "2. Remove secrets from S3 objects and publish sanitized replacements where needed.",
        "3. Review bucket policy, object ACLs, IAM access, version history, and access logs.",
        "4. Investigate use of each credential before and after exposure.",
        "5. Run TruffleHog again after remediation and confirm that verified results are gone.",
        "",
        "## False Positive Controls",
        "This report package is generated only when TruffleHog returns at least one detector result with `Verified=true`. Raw secrets are intentionally excluded from all generated artifacts.",
    ])
    return "\n".join(lines) + "\n"


def build_s3_report(result: Dict) -> str:
    bucket = result.get("bucket") or result.get("host") or "unknown"
    priority = result.get("notification_priority") or "unknown"
    rules = result.get("detected_rules") or []
    checked_public = [
        item for item in result.get("checked_objects") or []
        if item.get("public_read") and item.get("status") == 200
    ]
    sensitive = _sensitive_examples(result.get("sample_data") or {})
    basis = _confirmation_basis(result)

    lines = [
        f"# Confirmed Critical S3 Exposure: {bucket}",
        "",
        "## Summary",
        f"- Bucket: `{bucket}`",
        f"- URL: `{result.get('url', '')}`",
        f"- Region: `{result.get('region') or 'unknown'}`",
        f"- Priority: `{priority}`",
        f"- Severity score: `{result.get('severity_score', 0)}/100`",
        f"- Environment: `{result.get('environment') or 'unknown'}`",
        f"- Generated: `{_now_iso()}`",
        "",
        "## Confirmation",
    ]

    for item in basis:
        lines.append(f"- {item}")

    lines.extend([
        "",
        "## Impact",
    ])

    if "public_bucket_listing" in rules:
        lines.append(
            f"- Anonymous users can list object names in the bucket. "
            f"The scan observed `{result.get('listed_objects', 0)}` listed object(s)."
        )
    if checked_public:
        lines.append(
            f"- Anonymous users can read at least `{len(checked_public)}` sampled object(s), "
            "confirmed with HTTP `HEAD` responses returning `200`."
        )
    if sensitive:
        lines.append(
            "- Listed object names indicate likely sensitive material: "
            + "; ".join(f"`{item}`" for item in sensitive[:10])
        )

    lines.extend([
        "- Exposure may allow reconnaissance, data discovery, direct public access to objects, and accelerated credential or backup incident response if sensitive names are present.",
        "",
        "## Anonymous Validation",
    ])
    lines.extend(_anonymous_validation_lines(result))
    lines.extend([
        "",
        "## Evidence",
        f"- Bucket HEAD status: `{(result.get('status_codes') or {}).get('bucket_head', 0)}`",
        f"- ListObjectsV2 status: `{(result.get('status_codes') or {}).get('list_objects', 0)}`",
        f"- Evidence files: `evidence.json`, `proof_snapshot.html`, `proof_snapshot.svg`",
    ])
    lines.extend(_screenshot_report_lines(result))
    lines.extend([
        "",
        "### Public Object Checks",
    ])

    if checked_public:
        for item in checked_public[:20]:
            lines.append(
                f"- `{item.get('key', '')}`: HTTP `{item.get('status')}`, "
                f"Content-Length `{item.get('content_length') or 'unknown'}`"
            )
    else:
        lines.append("- No public object `HEAD 200` checks were recorded in the sampled objects.")

    lines.extend([
        "",
        "### Matched Rules",
    ])
    for rule in rules:
        lines.append(f"- `{rule}`")

    lines.extend([
        "",
        "## Recommended Remediation",
        "1. Enable S3 Block Public Access at both account and bucket level unless this bucket is intentionally public.",
        "2. Remove public bucket policies and public object ACLs that grant anonymous `s3:ListBucket` or `s3:GetObject`.",
        "3. Review IAM principals with access to this bucket and apply least privilege.",
        "4. Move secrets, private keys, backups, logs, database dumps, and PII out of publicly reachable storage.",
        "5. Rotate credentials if object names or internal review confirm exposed secrets, keys, dumps, or backups.",
        "6. Enable CloudTrail data events or S3 server access logs to investigate access during the exposure window.",
        "",
        "## Validation After Fix",
        "Run the scanner again against this bucket. The finding should no longer report `public_bucket_listing` or `public_object_read`, and ListObjectsV2 should no longer return HTTP `200` to anonymous requests.",
        "",
        "## False Positive Controls",
        "This report is generated only when the scanner records an S3 result with anonymous HTTP proof: public listing with returned keys, public object `HEAD 200`, sensitive object names from a confirmed public listing, or lower-severity bucket exposure evidence. The reporter does not mark blocked buckets or name-only business context as confirmed exposure.",
    ])

    return "\n".join(lines) + "\n"


def build_elasticsearch_report(result: Dict) -> str:
    rules = result.get("detected_rules") or []
    matched = _rule_matches(result.get("sample_data") or {})
    basis = _elasticsearch_confirmation_basis(result)

    lines = [
        f"# Confirmed Critical Elasticsearch Exposure: {result.get('host')}",
        "",
        "## Summary",
        f"- URL: `{result.get('url', '')}`",
        f"- Host: `{result.get('host', '')}`",
        f"- Port: `{result.get('port', '')}`",
        f"- Scheme: `{result.get('scheme', '')}`",
        f"- Cluster: `{result.get('cluster_name') or 'unknown'}`",
        f"- Version: `{result.get('version') or 'unknown'}`",
        f"- Indices observed: `{result.get('indices_count', 0)}`",
        f"- Severity score: `{result.get('severity_score', 0)}/100`",
        f"- Environment: `{result.get('environment') or 'unknown'}`",
        f"- Generated: `{_now_iso()}`",
        "",
        "## Confirmation",
    ]

    for item in basis:
        lines.append(f"- {item}")

    lines.extend([
        "",
        "## Impact",
        "- The Elasticsearch endpoint is reachable and identified as Elasticsearch without the scanner recording an authentication requirement.",
        "- Critical content indicators were observed in collected metadata or sampled search responses.",
    ])

    if result.get("indices_count", 0) > 0:
        lines.append(f"- The scanner observed `{result.get('indices_count', 0)}` index/indices, which may expose searchable business data.")
    if matched:
        lines.append("- Matched indicators include: " + "; ".join(f"`{item}`" for item in matched[:12]))
    if "ransomware_note" in rules:
        lines.append("- Ransomware-note indicators were observed; treat this as urgent incident-response context.")

    lines.extend([
        "",
        "## Anonymous Validation",
    ])
    lines.extend(_anonymous_validation_lines(result))
    lines.extend([
        "",
        "## Evidence",
        f"- Accessible: `{bool(result.get('accessible'))}`",
        f"- Cluster name: `{result.get('cluster_name') or 'unknown'}`",
        f"- Version: `{result.get('version') or 'unknown'}`",
        f"- Indices count: `{result.get('indices_count', 0)}`",
        f"- Evidence files: `evidence.json`, `proof_snapshot.html`, `proof_snapshot.svg`",
    ])
    lines.extend(_screenshot_report_lines(result))
    lines.extend([
        "",
        "### Matched Rules",
    ])
    for rule in rules:
        info = (result.get("sample_data") or {}).get(rule) or {}
        matches = ", ".join(str(item) for item in (info.get("matched") or [])[:8])
        lines.append(f"- `{rule}`: {info.get('description', 'matched critical indicator')} ({matches or 'no keyword sample'})")

    lines.extend([
        "",
        "## Recommended Remediation",
        "1. Block public network access to Elasticsearch. Restrict access with security groups, firewall rules, VPN, private networking, or an authenticated reverse proxy.",
        "2. Enable Elasticsearch security features, authentication, and role-based access control.",
        "3. Disable unauthenticated access to `_search`, `_cat/indices`, `_cluster/health`, and `_cluster/state`.",
        "4. Review index contents for secrets, credentials, personal data, financial data, medical data, backups, and logs.",
        "5. Rotate credentials and tokens if credential-like indicators were observed.",
        "6. Review access logs and cloud/network telemetry for access during the exposure window.",
        "7. Snapshot and preserve forensic evidence before destructive remediation if ransomware indicators were observed.",
        "",
        "## Validation After Fix",
        "Run the scanner again against this endpoint. The finding should no longer report `accessible=True`, critical detection rules, or unauthenticated metadata/search access.",
        "",
        "## False Positive Controls",
        "This report is generated only when the scanner records a critical Elasticsearch result that is accessible, contains critical detection rules, and includes Elasticsearch identity evidence such as cluster/version metadata or index metadata.",
    ])

    return "\n".join(lines) + "\n"


def build_laravel_debug_report(result: Dict) -> str:
    rules = result.get("detected_rules") or []
    matched = _rule_matches(result.get("sample_data") or {})
    basis = _laravel_confirmation_basis(result)
    owner = result.get("owner") or {}

    lines = [
        f"# Confirmed Laravel Debug Exposure: {result.get('host')}",
        "",
        "## Summary",
        f"- URL: `{result.get('url', '')}`",
        f"- Host: `{result.get('host', '')}`",
        f"- Port: `{result.get('port') or 'default'}`",
        f"- Scheme: `{result.get('scheme', '')}`",
        f"- Severity: `{severity_bucket(result)}`",
        f"- Severity score: `{result.get('severity_score', 0)}/100`",
        f"- Priority: `{result.get('notification_priority') or 'unknown'}`",
        f"- Environment: `{result.get('environment') or 'unknown'}`",
        f"- False-positive confidence: `{result.get('false_positive_confidence', 0)}%`",
        f"- Generated: `{_now_iso()}`",
        "",
        "## Confirmation",
    ]

    for item in basis:
        lines.append(f"- {item}")

    lines.extend([
        "",
        "## Impact",
        "- A Laravel debug or exception page is exposed to unauthenticated users.",
        "- Debug pages can disclose framework internals, stack traces, filesystem paths, environment names, application configuration, and operational metadata.",
    ])

    if "env_secrets" in rules:
        lines.append("- Environment variable or secret indicators were observed in debug output; credential rotation may be required.")
    if "stack_trace" in rules:
        lines.append("- Stack trace data can speed up exploit development and reveal code paths or package versions.")
    if result.get("environment") == "production":
        lines.append("- The finding appears to affect production, increasing urgency and business impact.")
    if matched:
        lines.append("- Matched indicators include: " + "; ".join(f"`{item}`" for item in matched[:12]))

    lines.extend([
        "",
        "## Anonymous Validation",
    ])
    lines.extend(_anonymous_validation_lines(result))
    lines.extend([
        "",
        "## Evidence",
        f"- Checked paths: `{', '.join(result.get('checked_paths') or [])}`",
        f"- Status codes: `{', '.join(f'{key}={value}' for key, value in (result.get('status_codes') or {}).items())}`",
        f"- Evidence files: `evidence.json`, `proof_snapshot.html`, `proof_snapshot.svg`",
    ])
    lines.extend(_screenshot_report_lines(result))

    contacts = owner.get("contacts") or []
    if contacts:
        lines.extend([
            "",
            "## Suggested Owner Contact",
            f"- Contacts: `{', '.join(contacts[:5])}`",
            f"- Owner confidence: `{owner.get('confidence', 0)}%`",
        ])

    lines.extend([
        "",
        "### Matched Rules",
    ])
    for rule in rules:
        info = (result.get("sample_data") or {}).get(rule) or {}
        matches = ", ".join(str(item) for item in (info.get("matched") or [])[:8])
        lines.append(f"- `{rule}`: {info.get('description', 'matched Laravel debug indicator')} ({matches or 'no keyword sample'})")

    lines.extend([
        "",
        "## Recommended Remediation",
        "1. Disable debug mode in deployed environments: set `APP_DEBUG=false`.",
        "2. Set the correct environment value, for example `APP_ENV=production` for production deployments.",
        "3. Clear and rebuild Laravel configuration cache after changing `.env`: `php artisan config:clear` and `php artisan config:cache`.",
        "4. Ensure exception pages are not publicly exposed and route production errors to generic error views.",
        "5. Restrict access to debug tooling, logs, and admin endpoints at the network or authentication layer.",
        "6. Rotate exposed credentials if env secret indicators were observed.",
        "7. Review web server and application logs for access to the exposed debug page.",
        "",
        "## Validation After Fix",
        "Run the scanner again against this URL. The finding should no longer report `laravel_debug`, `stack_trace`, or `env_secrets`, and debug pages should not expose Laravel markers.",
        "",
        "## False Positive Controls",
        "This report is generated only when the scanner records Laravel markers plus debug or secret evidence. A generic HTTP 500 page alone is not enough.",
    ])

    return "\n".join(lines) + "\n"


def write_proof_screenshot(html_path: str, png_path: str, finding: Dict = None) -> bool:
    if finding and _write_pil_screenshot(finding, png_path):
        return True

    browser = _find_screenshot_browser()
    if not browser:
        _write_text(
            os.path.join(os.path.dirname(png_path), "screenshot_error.txt"),
            "No supported headless browser found. Install firefox or chromium to generate PNG screenshots.\n",
        )
        return False

    url = Path(html_path).resolve().as_uri()
    command = _screenshot_command(browser, png_path, url)
    try:
        completed = subprocess.run(command, check=False, capture_output=True, text=True, timeout=45)
    except (OSError, subprocess.TimeoutExpired) as exc:
        _write_text(
            os.path.join(os.path.dirname(png_path), "screenshot_error.txt"),
            f"Screenshot generation failed: {exc}\n",
        )
        return False

    if completed.returncode != 0 or not os.path.exists(png_path):
        _write_text(
            os.path.join(os.path.dirname(png_path), "screenshot_error.txt"),
            "Screenshot generation failed.\n"
            f"Command: {' '.join(command)}\n"
            f"Exit code: {completed.returncode}\n"
            f"stderr: {completed.stderr[:4000]}\n",
        )
        return False

    return True


def screenshot_paths(primary_path: str) -> Dict[str, str]:
    directory = os.path.dirname(primary_path)
    return {
        "overview": primary_path,
        "impact": os.path.join(directory, "proof_screenshot_impact.png"),
        "validation": os.path.join(directory, "proof_screenshot_validation.png"),
    }


def build_proof_snapshot_html(result: Dict) -> str:
    if result.get("module") == "elasticsearch":
        return build_elasticsearch_snapshot_html(result)
    if result.get("module") == "laravel_debug":
        return build_laravel_debug_snapshot_html(result)
    if result.get("module") == "trufflehog_s3":
        return build_trufflehog_s3_snapshot_html(result)

    evidence = build_evidence_bundle(result)
    rows = []
    for item in evidence["checked_objects"][:20]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(item.get('key', ''))}</td>"
            f"<td>{html.escape(str(item.get('status', '')))}</td>"
            f"<td>{html.escape(str(item.get('public_read', '')))}</td>"
            f"<td>{html.escape(str(item.get('content_length') or 'unknown'))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>S3 Evidence Snapshot - {html.escape(str(evidence["bucket"]))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #172026; background: #f7f9fb; }}
    main {{ max-width: 1080px; margin: 0 auto; background: #fff; border: 1px solid #d9e0e7; padding: 28px; }}
    h1 {{ font-size: 26px; margin: 0 0 18px; }}
    h2 {{ font-size: 18px; margin-top: 26px; }}
    code {{ background: #eef2f5; padding: 2px 5px; border-radius: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ border: 1px solid #d9e0e7; padding: 8px; text-align: left; font-size: 13px; }}
    th {{ background: #eef2f5; }}
    .badge {{ display: inline-block; padding: 4px 8px; background: #9f1d20; color: #fff; font-weight: bold; }}
  </style>
</head>
<body>
<main>
  <h1>Confirmed Critical S3 Exposure</h1>
  <p><span class="badge">CONFIRMED</span></p>
  <p>Bucket: <code>{html.escape(str(evidence["bucket"]))}</code></p>
  <p>URL: <code>{html.escape(str(evidence["url"]))}</code></p>
  <p>Severity: <code>{html.escape(str(evidence["severity_score"]))}/100</code></p>
  <p>Generated: <code>{html.escape(evidence["generated_at"])}</code></p>

  <h2>Confirmation Basis</h2>
  <ul>
    {''.join(f'<li>{html.escape(item)}</li>' for item in evidence["confirmation"]["basis"])}
  </ul>

  <h2>HTTP Status Codes</h2>
  <p>Bucket HEAD: <code>{html.escape(str(evidence["confirmation"]["status_codes"].get("bucket_head", 0)))}</code></p>
  <p>ListObjectsV2: <code>{html.escape(str(evidence["confirmation"]["status_codes"].get("list_objects", 0)))}</code></p>

  <h2>Sampled Object Checks</h2>
  <table>
    <thead><tr><th>Key</th><th>Status</th><th>Public Read</th><th>Content-Length</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</main>
</body>
</html>
"""


def build_elasticsearch_snapshot_html(result: Dict) -> str:
    evidence = build_elasticsearch_evidence_bundle(result)
    rows = []
    for rule, data in evidence["sample_data"].items():
        rows.append(
            "<tr>"
            f"<td>{html.escape(rule)}</td>"
            f"<td>{html.escape(str(data.get('description') or ''))}</td>"
            f"<td>{html.escape(', '.join(str(item) for item in (data.get('matched') or [])[:8]))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Elasticsearch Evidence Snapshot - {html.escape(str(evidence["host"]))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #172026; background: #f7f9fb; }}
    main {{ max-width: 1080px; margin: 0 auto; background: #fff; border: 1px solid #d9e0e7; padding: 28px; }}
    h1 {{ font-size: 26px; margin: 0 0 18px; }}
    h2 {{ font-size: 18px; margin-top: 26px; }}
    code {{ background: #eef2f5; padding: 2px 5px; border-radius: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ border: 1px solid #d9e0e7; padding: 8px; text-align: left; font-size: 13px; }}
    th {{ background: #eef2f5; }}
    .badge {{ display: inline-block; padding: 4px 8px; background: #9f1d20; color: #fff; font-weight: bold; }}
  </style>
</head>
<body>
<main>
  <h1>Confirmed Critical Elasticsearch Exposure</h1>
  <p><span class="badge">CONFIRMED</span></p>
  <p>URL: <code>{html.escape(str(evidence["url"]))}</code></p>
  <p>Cluster: <code>{html.escape(str(evidence["cluster_name"]))}</code></p>
  <p>Version: <code>{html.escape(str(evidence["version"]))}</code></p>
  <p>Indices: <code>{html.escape(str(evidence["indices_count"]))}</code></p>
  <p>Severity: <code>{html.escape(str(evidence["severity_score"]))}/100</code></p>
  <p>Generated: <code>{html.escape(evidence["generated_at"])}</code></p>

  <h2>Confirmation Basis</h2>
  <ul>
    {''.join(f'<li>{html.escape(item)}</li>' for item in evidence["confirmation"]["basis"])}
  </ul>

  <h2>Matched Critical Rules</h2>
  <table>
    <thead><tr><th>Rule</th><th>Description</th><th>Matched Indicators</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</main>
</body>
</html>
"""


def build_laravel_debug_snapshot_html(result: Dict) -> str:
    evidence = build_laravel_debug_evidence_bundle(result)
    rows = []
    for rule, data in evidence["sample_data"].items():
        rows.append(
            "<tr>"
            f"<td>{html.escape(rule)}</td>"
            f"<td>{html.escape(str(data.get('description') or ''))}</td>"
            f"<td>{html.escape(', '.join(str(item) for item in (data.get('matched') or [])[:8]))}</td>"
            "</tr>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Laravel Debug Evidence Snapshot - {html.escape(str(evidence["host"]))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #172026; background: #f7f9fb; }}
    main {{ max-width: 1080px; margin: 0 auto; background: #fff; border: 1px solid #d9e0e7; padding: 28px; }}
    h1 {{ font-size: 26px; margin: 0 0 18px; }}
    h2 {{ font-size: 18px; margin-top: 26px; }}
    code {{ background: #eef2f5; padding: 2px 5px; border-radius: 4px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th, td {{ border: 1px solid #d9e0e7; padding: 8px; text-align: left; font-size: 13px; }}
    th {{ background: #eef2f5; }}
    .badge {{ display: inline-block; padding: 4px 8px; background: #9f1d20; color: #fff; font-weight: bold; }}
  </style>
</head>
<body>
<main>
  <h1>Confirmed Laravel Debug Exposure</h1>
  <p><span class="badge">{html.escape(str(evidence["severity"]).upper())}</span></p>
  <p>URL: <code>{html.escape(str(evidence["url"]))}</code></p>
  <p>Severity: <code>{html.escape(str(evidence["severity_score"]))}/100</code></p>
  <p>Environment: <code>{html.escape(str(evidence["environment"]))}</code></p>
  <p>Priority: <code>{html.escape(str(evidence["priority"]))}</code></p>
  <p>Generated: <code>{html.escape(evidence["generated_at"])}</code></p>

  <h2>Confirmation Basis</h2>
  <ul>
    {''.join(f'<li>{html.escape(item)}</li>' for item in evidence["confirmation"]["basis"])}
  </ul>

  <h2>Matched Rules</h2>
  <table>
    <thead><tr><th>Rule</th><th>Description</th><th>Matched Indicators</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</main>
</body>
</html>
"""


def build_trufflehog_s3_snapshot_html(result: Dict) -> str:
    evidence = build_trufflehog_s3_evidence_bundle(result)
    rows = []
    for item in evidence["findings"]:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('detector', '')))}</td>"
            f"<td>{html.escape(str(item.get('object_key', '')))}</td>"
            f"<td>{html.escape(str(item.get('verified', '')))}</td>"
            f"<td>{html.escape(str(item.get('redacted', '')))}</td>"
            f"<td>{html.escape(str(item.get('fingerprint', '')))}</td>"
            "</tr>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>TruffleHog S3 Evidence Snapshot - {html.escape(str(evidence["bucket"]))}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 32px; color: #172026; background: #f7f9fb; }}
main {{ background: #fff; border: 1px solid #d9e0e7; padding: 28px; }}
table {{ width: 100%; border-collapse: collapse; }} th, td {{ border: 1px solid #d9e0e7; padding: 8px; text-align: left; }}
th {{ background: #eef2f5; }} .badge {{ background: #9f1d20; color: #fff; padding: 4px 8px; font-weight: bold; }}
</style></head><body><main>
<h1>Confirmed TruffleHog Secret Exposure</h1><p><span class="badge">VERIFIED</span></p>
<p>Bucket: <code>{html.escape(str(evidence["bucket"]))}</code></p>
<p>Verified secrets: <code>{html.escape(str(evidence["verified_count"]))}</code></p>
<p>Generated: <code>{html.escape(evidence["generated_at"])}</code></p>
<table><thead><tr><th>Detector</th><th>Object Key</th><th>Verified</th><th>Redacted</th><th>Fingerprint</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</main></body></html>
"""


def build_proof_snapshot_svg(result: Dict) -> str:
    if result.get("module") == "elasticsearch":
        return build_elasticsearch_snapshot_svg(result)
    if result.get("module") == "laravel_debug":
        return build_laravel_debug_snapshot_svg(result)
    if result.get("module") == "trufflehog_s3":
        return build_trufflehog_s3_snapshot_svg(result)

    evidence = build_evidence_bundle(result)
    bucket = _svg_text(str(evidence["bucket"]))
    basis = evidence["confirmation"]["basis"][:6]
    rows = [
        f'<text x="40" y="{190 + idx * 28}" font-size="16" fill="#172026">{_svg_text(item)}</text>'
        for idx, item in enumerate(basis)
    ]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="620" viewBox="0 0 1200 620">
  <rect width="1200" height="620" fill="#f7f9fb"/>
  <rect x="24" y="24" width="1152" height="572" fill="#ffffff" stroke="#d9e0e7"/>
  <text x="40" y="72" font-family="Arial, sans-serif" font-size="32" font-weight="700" fill="#172026">Confirmed Critical S3 Exposure</text>
  <rect x="40" y="96" width="132" height="32" fill="#9f1d20"/>
  <text x="56" y="118" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#ffffff">CONFIRMED</text>
  <text x="40" y="158" font-family="Arial, sans-serif" font-size="20" fill="#172026">Bucket: {bucket}</text>
  {''.join(rows)}
  <text x="40" y="430" font-family="Arial, sans-serif" font-size="18" fill="#172026">Severity: {_svg_text(str(evidence["severity_score"]))}/100</text>
  <text x="40" y="462" font-family="Arial, sans-serif" font-size="18" fill="#172026">Bucket HEAD: {_svg_text(str(evidence["confirmation"]["status_codes"].get("bucket_head", 0)))}</text>
  <text x="40" y="494" font-family="Arial, sans-serif" font-size="18" fill="#172026">ListObjectsV2: {_svg_text(str(evidence["confirmation"]["status_codes"].get("list_objects", 0)))}</text>
  <text x="40" y="548" font-family="Arial, sans-serif" font-size="14" fill="#55616d">Generated: {_svg_text(evidence["generated_at"])}</text>
</svg>
"""


def build_elasticsearch_snapshot_svg(result: Dict) -> str:
    evidence = build_elasticsearch_evidence_bundle(result)
    basis = evidence["confirmation"]["basis"][:6]
    rows = [
        f'<text x="40" y="{214 + idx * 28}" font-size="16" fill="#172026">{_svg_text(item)}</text>'
        for idx, item in enumerate(basis)
    ]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="620" viewBox="0 0 1200 620">
  <rect width="1200" height="620" fill="#f7f9fb"/>
  <rect x="24" y="24" width="1152" height="572" fill="#ffffff" stroke="#d9e0e7"/>
  <text x="40" y="72" font-family="Arial, sans-serif" font-size="32" font-weight="700" fill="#172026">Confirmed Critical Elasticsearch Exposure</text>
  <rect x="40" y="96" width="132" height="32" fill="#9f1d20"/>
  <text x="56" y="118" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#ffffff">CONFIRMED</text>
  <text x="40" y="158" font-family="Arial, sans-serif" font-size="20" fill="#172026">URL: {_svg_text(str(evidence["url"]))}</text>
  <text x="40" y="188" font-family="Arial, sans-serif" font-size="18" fill="#172026">Cluster: {_svg_text(str(evidence["cluster_name"]))} | Version: {_svg_text(str(evidence["version"]))} | Indices: {_svg_text(str(evidence["indices_count"]))}</text>
  {''.join(rows)}
  <text x="40" y="458" font-family="Arial, sans-serif" font-size="18" fill="#172026">Severity: {_svg_text(str(evidence["severity_score"]))}/100</text>
  <text x="40" y="490" font-family="Arial, sans-serif" font-size="18" fill="#172026">Rules: {_svg_text(", ".join(evidence["detected_rules"][:8]))}</text>
  <text x="40" y="548" font-family="Arial, sans-serif" font-size="14" fill="#55616d">Generated: {_svg_text(evidence["generated_at"])}</text>
</svg>
"""


def build_laravel_debug_snapshot_svg(result: Dict) -> str:
    evidence = build_laravel_debug_evidence_bundle(result)
    basis = evidence["confirmation"]["basis"][:6]
    rows = [
        f'<text x="40" y="{214 + idx * 28}" font-size="16" fill="#172026">{_svg_text(item)}</text>'
        for idx, item in enumerate(basis)
    ]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="620" viewBox="0 0 1200 620">
  <rect width="1200" height="620" fill="#f7f9fb"/>
  <rect x="24" y="24" width="1152" height="572" fill="#ffffff" stroke="#d9e0e7"/>
  <text x="40" y="72" font-family="Arial, sans-serif" font-size="32" font-weight="700" fill="#172026">Confirmed Laravel Debug Exposure</text>
  <rect x="40" y="96" width="132" height="32" fill="#9f1d20"/>
  <text x="56" y="118" font-family="Arial, sans-serif" font-size="16" font-weight="700" fill="#ffffff">{_svg_text(str(evidence["severity"]).upper())}</text>
  <text x="40" y="158" font-family="Arial, sans-serif" font-size="20" fill="#172026">URL: {_svg_text(str(evidence["url"]))}</text>
  <text x="40" y="188" font-family="Arial, sans-serif" font-size="18" fill="#172026">Environment: {_svg_text(str(evidence["environment"]))} | Priority: {_svg_text(str(evidence["priority"]))}</text>
  {''.join(rows)}
  <text x="40" y="458" font-family="Arial, sans-serif" font-size="18" fill="#172026">Severity: {_svg_text(str(evidence["severity_score"]))}/100</text>
  <text x="40" y="490" font-family="Arial, sans-serif" font-size="18" fill="#172026">Rules: {_svg_text(", ".join(evidence["detected_rules"][:8]))}</text>
  <text x="40" y="548" font-family="Arial, sans-serif" font-size="14" fill="#55616d">Generated: {_svg_text(evidence["generated_at"])}</text>
</svg>
"""


def build_trufflehog_s3_snapshot_svg(result: Dict) -> str:
    evidence = build_trufflehog_s3_evidence_bundle(result)
    findings = evidence["findings"][:6]
    rows = [
        f'<text x="40" y="{210 + idx * 32}" font-size="16" fill="#172026">'
        f'{_svg_text(str(item.get("detector")))} | {_svg_text(str(item.get("object_key")))} | '
        f'{_svg_text(str(item.get("redacted")))} | {_svg_text(str(item.get("fingerprint")))}</text>'
        for idx, item in enumerate(findings)
    ]
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="620">
  <rect width="1200" height="620" fill="#f7f9fb"/>
  <rect x="24" y="24" width="1152" height="572" fill="#ffffff" stroke="#d9e0e7"/>
  <text x="40" y="72" font-size="32" font-weight="700" fill="#172026">Confirmed TruffleHog Secret Exposure</text>
  <rect x="40" y="96" width="132" height="32" fill="#9f1d20"/>
  <text x="56" y="118" font-size="16" font-weight="700" fill="#ffffff">VERIFIED</text>
  <text x="40" y="158" font-size="20" fill="#172026">Bucket: {_svg_text(str(evidence["bucket"]))}</text>
  <text x="40" y="188" font-size="18" fill="#172026">Verified secrets: {_svg_text(str(evidence["verified_count"]))}</text>
  {''.join(rows)}
  <text x="40" y="548" font-size="14" fill="#55616d">Generated: {_svg_text(evidence["generated_at"])}</text>
</svg>
"""


def _write_pil_screenshot(result: Dict, png_path: str) -> bool:
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return False

    paths = screenshot_paths(png_path)
    title = _screenshot_title(result)
    badge = severity_bucket(result).upper()
    rendered = [
        _write_pil_board(title, badge, _pil_screenshot_lines(result), paths["overview"]),
        _write_pil_board(f"{title} - Impact", badge, _impact_screenshot_lines(result), paths["impact"]),
        _write_pil_board(f"{title} - Anonymous Validation", badge, _validation_screenshot_lines(result), paths["validation"]),
    ]
    return all(rendered)


def _write_pil_board(title: str, badge: str, lines: List[str], png_path: str) -> bool:
    from PIL import Image, ImageDraw

    width, height = 1600, 1000
    image = Image.new("RGB", (width, height), "#f7f9fb")
    draw = ImageDraw.Draw(image)
    font_regular, font_bold, font_title, font_small = _load_fonts()

    draw.rectangle((24, 24, width - 24, height - 24), fill="#ffffff", outline="#d9e0e7")
    draw.rectangle((24, 24, width - 24, 148), fill="#172026")
    draw.text((52, 50), title[:95], fill="#ffffff", font=font_title)
    badge_color = "#9f1d20" if badge == "CRITICAL" else "#a15c00"
    draw.rectangle((52, 104, 190, 134), fill=badge_color)
    draw.text((66, 111), badge, fill="#ffffff", font=font_bold)
    draw.text((220, 111), f"Generated: {_now_iso()}", fill="#d8e1ea", font=font_small)

    y = 184
    for line in _wrap_lines(lines, 170):
        if line.endswith(":") and not line.startswith(("http", "curl", "-")):
            draw.rectangle((48, y - 4, width - 48, y + 28), fill="#eef2f5")
            draw.text((60, y + 2), line, fill="#172026", font=font_bold)
            y += 42
        else:
            draw.text((60, y), line, fill="#172026", font=font_regular)
            y += 28
        if y > height - 70:
            draw.text((60, y), "...truncated; see report.md and evidence.json for complete proof", fill="#55616d", font=font_regular)
            break

    image.save(png_path, "PNG")
    return os.path.exists(png_path)


def _load_fonts():
    from PIL import ImageFont

    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ]
    bold_candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf",
    ]
    regular_path = next((path for path in candidates if os.path.exists(path)), "")
    bold_path = next((path for path in bold_candidates if os.path.exists(path)), regular_path)
    if regular_path:
        return (
            ImageFont.truetype(regular_path, 24),
            ImageFont.truetype(bold_path, 24),
            ImageFont.truetype(bold_path, 34),
            ImageFont.truetype(regular_path, 18),
        )
    font = ImageFont.load_default()
    return font, font, font, font


def _screenshot_title(result: Dict) -> str:
    titles = {
        "elasticsearch": "Confirmed Critical Elasticsearch Exposure",
        "laravel_debug": "Confirmed Laravel Debug Exposure",
        "trufflehog_s3": "Confirmed TruffleHog Secret Exposure",
    }
    return titles.get(result.get("module"), "Confirmed Critical S3 Exposure")


def _pil_screenshot_lines(result: Dict) -> List[str]:
    if result.get("module") == "trufflehog_s3":
        lines = [
            f"Bucket: {result.get('bucket') or result.get('host') or 'unknown'}",
            f"Verified secrets: {result.get('trufflehog_verified_count', 0)}",
            f"Unverified matches: {result.get('trufflehog_unverified_count', 0)}",
            f"Severity: {result.get('severity_score', 0)}/100",
            "",
            "Verified findings:",
        ]
        for item in result.get("trufflehog_findings") or []:
            if item.get("verified"):
                lines.append(
                    f"- {item.get('detector')} | {item.get('object_key')} | "
                    f"{item.get('redacted')} | fingerprint={item.get('fingerprint')}"
                )
        return lines

    if result.get("module") == "elasticsearch":
        lines = [
            f"URL: {result.get('url', '')}",
            f"Cluster: {result.get('cluster_name') or 'unknown'}",
            f"Version: {result.get('version') or 'unknown'}",
            f"Indices: {result.get('indices_count', 0)}",
            f"Environment: {result.get('environment') or 'unknown'}",
            f"Severity: {result.get('severity_score', 0)}/100",
            "",
            "Confirmation Basis:",
        ]
        lines.extend(_elasticsearch_confirmation_basis(result))
        lines.extend(["", "Matched Rules:"])
        for rule, data in (result.get("sample_data") or {}).items():
            matches = ", ".join(str(item) for item in (data.get("matched") or [])[:8])
            lines.append(f"- {rule}: {matches or data.get('description', '')}")
        lines.extend(["", f"Generated: {_now_iso()}"])
        return lines

    if result.get("module") == "laravel_debug":
        lines = [
            f"URL: {result.get('url', '')}",
            f"Environment: {result.get('environment') or 'unknown'}",
            f"Severity: {severity_bucket(result)}",
            f"Severity Score: {result.get('severity_score', 0)}/100",
            f"Priority: {result.get('notification_priority') or 'unknown'}",
            f"False-positive Confidence: {result.get('false_positive_confidence', 0)}%",
            "",
            "Confirmation Basis:",
        ]
        lines.extend(_laravel_confirmation_basis(result))
        lines.extend(["", "Matched Rules:"])
        for rule, data in (result.get("sample_data") or {}).items():
            matches = ", ".join(str(item) for item in (data.get("matched") or [])[:8])
            lines.append(f"- {rule}: {matches or data.get('description', '')}")
        lines.extend(["", f"Generated: {_now_iso()}"])
        return lines

    lines = [
        f"Bucket: {result.get('bucket') or result.get('host') or 'unknown'}",
        f"URL: {result.get('url', '')}",
        f"Environment: {result.get('environment') or 'unknown'}",
        f"Severity: {result.get('severity_score', 0)}/100",
        f"Priority: {result.get('notification_priority') or 'unknown'}",
        f"Bucket HEAD: {(result.get('status_codes') or {}).get('bucket_head', 0)}",
        f"ListObjectsV2: {(result.get('status_codes') or {}).get('list_objects', 0)}",
        "",
        "Confirmation Basis:",
    ]
    lines.extend(_confirmation_basis(result))
    lines.extend(["", "Public Object Checks:"])

    checked_public = [
        item for item in result.get("checked_objects") or []
        if item.get("public_read") and item.get("status") == 200
    ]
    if checked_public:
        for item in checked_public[:12]:
            lines.append(
                f"- {item.get('key', '')}: HTTP {item.get('status')} "
                f"Content-Length {item.get('content_length') or 'unknown'}"
            )
    else:
        lines.append("- No public object HEAD 200 checks were recorded.")

    lines.extend(["", f"Generated: {_now_iso()}"])
    return lines


def _impact_screenshot_lines(result: Dict) -> List[str]:
    module = result.get("module")
    lines = [
        f"Target: {result.get('url') or result.get('host') or result.get('bucket') or 'unknown'}",
        f"Severity: {severity_bucket(result)} ({result.get('severity_score', 0)}/100)",
        "",
        "Why this matters:",
    ]
    if module == "s3_bucket_impact":
        lines.extend([
            f"- Anonymous users can list {result.get('listed_objects', 0)} object key(s).",
            f"- Anonymous object HEAD 200 confirmed for {result.get('public_read_checked', 0)} sampled object(s).",
        ])
        sensitive = _sensitive_examples(result.get("sample_data") or {})
        if sensitive:
            lines.append("- Sensitive-looking object names: " + "; ".join(sensitive[:8]))
        checked_public = [item for item in result.get("checked_objects") or [] if item.get("public_read")]
        if checked_public:
            lines.append("")
            lines.append("Representative exposed objects:")
            for item in checked_public[:8]:
                lines.append(f"- {item.get('key')} | HTTP {item.get('status')} | Content-Length {item.get('content_length') or 'unknown'}")
    elif module == "elasticsearch":
        lines.extend([
            "- Elasticsearch endpoint is reachable without recorded authentication.",
            f"- Cluster: {result.get('cluster_name') or 'unknown'} | Version: {result.get('version') or 'unknown'}",
            f"- Index metadata exposed: {result.get('indices_count', 0)} index/indices.",
            "- Detection rules: " + ", ".join((result.get("detected_rules") or [])[:10]),
        ])
        matches = _rule_matches(result.get("sample_data") or {})
        if matches:
            lines.append("")
            lines.append("Matched data indicators:")
            for item in matches[:10]:
                lines.append(f"- {item}")
    elif module == "laravel_debug":
        lines.extend([
            "- Laravel debug output is reachable without recorded authentication.",
            "- Debug output can expose stack traces, paths, config and secrets.",
            f"- Environment: {result.get('environment') or 'unknown'}",
            "- Detection rules: " + ", ".join((result.get("detected_rules") or [])[:10]),
        ])
        evidence = result.get("evidence") or []
        if evidence:
            lines.append("")
            lines.append("Observed evidence markers:")
            for item in evidence[:10]:
                lines.append(f"- {item}")
    elif module == "trufflehog_s3":
        lines.extend([
            f"- TruffleHog verified {result.get('trufflehog_verified_count', 0)} secret(s).",
            "- Verified credentials must be treated as compromised.",
            "- Raw secret values were excluded from generated artifacts.",
        ])
        for item in result.get("trufflehog_findings") or []:
            if item.get("verified"):
                lines.append(f"- {item.get('detector')} | {item.get('object_key')} | {item.get('redacted')}")
    return lines


def _validation_screenshot_lines(result: Dict) -> List[str]:
    validation = _anonymous_validation(result)
    lines = [
        "Anonymous validation:",
        f"- {validation.get('summary', '')}",
    ]
    if validation.get("data_proof"):
        lines.append(f"- {validation['data_proof']}")
    commands = validation.get("commands") or []
    if commands:
        lines.extend(["", "Copy-paste proof commands:"])
        for command in commands[:6]:
            lines.append(f"- {command}")
    lines.extend(["", "Interpretation:"])
    if result.get("module") == "trufflehog_s3":
        lines.extend([
            "- TruffleHog performed detector-specific verification where supported.",
            "- Raw secrets are omitted; use the redacted value and fingerprint for incident correlation.",
        ])
    else:
        lines.extend([
            "- These commands intentionally do not include cookies, Authorization headers, API keys or session tokens.",
            "- A 200 response with object names, metadata, matched indicators or non-zero Content-Length proves unauthenticated exposure.",
        ])
    return lines


def _confirmation_basis(result: Dict) -> List[str]:
    basis = []
    rules = set(result.get("detected_rules") or [])
    status_codes = result.get("status_codes") or {}
    checked_objects = result.get("checked_objects") or []

    if "public_bucket_listing" in rules and status_codes.get("list_objects") == 200:
        basis.append(
            f"Anonymous ListObjectsV2 returned HTTP 200 with {result.get('listed_objects', 0)} object key(s)."
        )
    public_read = [
        item for item in checked_objects
        if item.get("public_read") and item.get("status") == 200
    ]
    if public_read:
        basis.append(f"Anonymous object HEAD returned HTTP 200 for {len(public_read)} sampled object(s).")
    sensitive_rules = sorted((set(result.get("detected_rules") or []) & CONFIRMED_S3_RULES) - {
        "public_bucket_listing",
        "public_object_read",
    })
    if sensitive_rules and status_codes.get("list_objects") == 200:
        basis.append("Confirmed public listing included sensitive-looking object names: " + ", ".join(sensitive_rules))
    return basis or ["No confirmation basis recorded."]


def _elasticsearch_confirmation_basis(result: Dict) -> List[str]:
    basis = []
    if result.get("accessible"):
        basis.append("Endpoint responded as accessible Elasticsearch.")
    if result.get("cluster_name"):
        basis.append(f"Elasticsearch cluster name was observed: {result.get('cluster_name')}.")
    if result.get("version"):
        basis.append(f"Elasticsearch version metadata was observed: {result.get('version')}.")
    if result.get("indices_count", 0) > 0:
        basis.append(f"Index metadata was accessible; observed {result.get('indices_count', 0)} index/indices.")
    rules = sorted(set(result.get("detected_rules") or []) & CONFIRMED_ES_RULES)
    if rules:
        basis.append("Critical detection rules matched: " + ", ".join(rules))
    return basis or ["No confirmation basis recorded."]


def _laravel_confirmation_basis(result: Dict) -> List[str]:
    basis = []
    if result.get("accessible"):
        basis.append("Endpoint was reachable and returned text content for analysis.")

    evidence = [str(item) for item in result.get("evidence") or []]
    laravel_hits = [item for item in evidence if item.lower().startswith("laravel:")]
    debug_hits = [item for item in evidence if item.lower().startswith("debug:")]
    secret_hits = [item for item in evidence if item.lower().startswith("secret:")]
    if laravel_hits:
        basis.append("Laravel markers were observed: " + ", ".join(laravel_hits[:5]))
    if debug_hits:
        basis.append("Debug markers were observed: " + ", ".join(debug_hits[:5]))
    if secret_hits:
        basis.append("Secret/environment indicators were observed: " + ", ".join(secret_hits[:5]))

    status_codes = result.get("status_codes") or {}
    if status_codes:
        basis.append("HTTP evidence: " + ", ".join(f"{key}={value}" for key, value in status_codes.items()))

    rules = sorted(set(result.get("detected_rules") or []) & CONFIRMED_LARAVEL_RULES)
    if rules:
        basis.append("Laravel debug detection rules matched: " + ", ".join(rules))
    return basis or ["No confirmation basis recorded."]


def _trufflehog_confirmation_basis(result: Dict) -> List[str]:
    findings = [item for item in result.get("trufflehog_findings") or [] if item.get("verified")]
    basis = [f"TruffleHog returned Verified=true for {len(findings)} detector result(s)."]
    detectors = sorted({str(item.get("detector") or "unknown") for item in findings})
    if detectors:
        basis.append("Verified detectors: " + ", ".join(detectors))
    object_keys = sorted({str(item.get("object_key") or "unknown") for item in findings})
    if object_keys:
        basis.append("Affected S3 object keys: " + ", ".join(object_keys[:10]))
    return basis


def _wrap_lines(lines: Iterable[str], limit: int) -> List[str]:
    wrapped = []
    for line in lines:
        text = str(line)
        if len(text) <= limit:
            wrapped.append(text)
            continue
        while len(text) > limit:
            cut = text.rfind(" ", 0, limit)
            if cut <= 0:
                cut = limit
            wrapped.append(text[:cut])
            text = text[cut:].lstrip()
        if text:
            wrapped.append(text)
    return wrapped


def _rule_matches(sample_data: Dict) -> List[str]:
    matches = []
    for rule, data in sample_data.items():
        for item in data.get("matched") or []:
            matches.append(f"{rule}: {item}")
    return matches


def _anonymous_validation(result: Dict) -> Dict:
    module = result.get("module")
    if module == "s3_bucket_impact":
        return _s3_anonymous_validation(result)
    if module == "elasticsearch":
        return _elasticsearch_anonymous_validation(result)
    if module == "laravel_debug":
        return _laravel_anonymous_validation(result)
    if module == "trufflehog_s3":
        return _trufflehog_verification(result)
    return {"summary": "No anonymous validation available.", "commands": []}


def _anonymous_validation_lines(result: Dict) -> List[str]:
    validation = _anonymous_validation(result)
    lines = [f"- {validation['summary']}"]
    if validation.get("data_proof"):
        lines.append(f"- Data proof: {validation['data_proof']}")
    commands = validation.get("commands") or []
    if commands:
        lines.append("")
        lines.append("Run these commands from any unauthenticated network location that can reach the target:")
        for command in commands:
            lines.append(f"- `{command}`")
    return lines


def _screenshot_report_lines(result: Dict) -> List[str]:
    if severity_bucket(result) != SCREENSHOT_SEVERITY:
        return []
    return [
        "- Screenshots: `proof_screenshot.png`, `proof_screenshot_impact.png`, `proof_screenshot_validation.png`",
    ]


def _s3_anonymous_validation(result: Dict) -> Dict:
    url = result.get("url", "").rstrip("/")
    list_url = f"{url}/?list-type=2&max-keys=5"
    checked_public = [
        item for item in result.get("checked_objects") or []
        if item.get("public_read") and item.get("status") == 200
    ]
    commands = [f"curl -sS {_shell_quote(list_url)} | head -40"]
    data_proof = f"anonymous ListObjectsV2 returned HTTP {(result.get('status_codes') or {}).get('list_objects', 0)}"
    if checked_public:
        object_url = f"{url}/{checked_public[0].get('key', '')}"
        commands.append(f"curl -I {_shell_quote(object_url)}")
        size = checked_public[0].get("content_length") or "unknown"
        data_proof += f"; sampled object `{checked_public[0].get('key', '')}` returned HTTP 200 with Content-Length {size}"
    elif result.get("listed_objects", 0):
        data_proof += f" with {result.get('listed_objects', 0)} listed object key(s)"
    return {
        "summary": "No authentication headers, cookies, or credentials are required for the validation commands.",
        "data_proof": data_proof,
        "commands": commands,
    }


def _elasticsearch_anonymous_validation(result: Dict) -> Dict:
    url = result.get("url", "").rstrip("/")
    commands = [
        f"curl -sS {_shell_quote(url + '/')}",
        f"curl -sS {_shell_quote(url + '/_cat/indices?v')}",
    ]
    if result.get("indices_count", 0) > 0:
        commands.append(f"curl -sS {_shell_quote(url + '/_search?size=1')}")
    return {
        "summary": "The scanner confirmed Elasticsearch metadata without recording any authentication requirement.",
        "data_proof": (
            f"cluster=`{result.get('cluster_name') or 'unknown'}`, "
            f"version=`{result.get('version') or 'unknown'}`, "
            f"indices={result.get('indices_count', 0)}"
        ),
        "commands": commands,
    }


def _laravel_anonymous_validation(result: Dict) -> Dict:
    checked_paths = result.get("checked_paths") or [result.get("url", "")]
    commands = [f"curl -i {_shell_quote(path)} | head -80" for path in checked_paths[:2] if path]
    status_codes = ", ".join(f"{key}={value}" for key, value in (result.get("status_codes") or {}).items())
    evidence = ", ".join(str(item) for item in (result.get("evidence") or [])[:6])
    return {
        "summary": "The debug page evidence was observed without authentication headers, cookies, or credentials.",
        "data_proof": f"HTTP evidence: {status_codes or 'unknown'}; markers: {evidence or 'none'}",
        "commands": commands,
    }


def _trufflehog_verification(result: Dict) -> Dict:
    bucket = result.get("bucket") or result.get("host") or "unknown"
    return {
        "summary": "TruffleHog performed detector-specific verification for the recorded Verified=true results.",
        "data_proof": (
            f"verified={result.get('trufflehog_verified_count', 0)}; "
            f"unverified={result.get('trufflehog_unverified_count', 0)}; raw secrets omitted"
        ),
        "commands": [f"trufflehog s3 --bucket={_shell_quote(bucket)} --json --no-update"],
    }


def _sensitive_examples(sample_data: Dict) -> List[str]:
    examples = []
    for rule, data in sample_data.items():
        if rule in {"public_bucket_listing", "public_object_read", "listing_blocked", "business_context_in_name"}:
            continue
        for match in data.get("matched") or []:
            examples.append(f"{rule}: {match}")
    return examples


def _redact_sample_data(sample_data: Dict) -> Dict:
    redacted = {}
    for rule, data in sample_data.items():
        redacted[rule] = dict(data)
        redacted[rule]["matched"] = [_redact_key(str(item)) for item in data.get("matched") or []]
    return redacted


def _redact_checked_objects(checked_objects: Iterable[Dict]) -> List[Dict]:
    redacted = []
    for item in checked_objects:
        redacted.append({
            "key": _redact_key(str(item.get("key", ""))),
            "status": item.get("status", 0),
            "public_read": bool(item.get("public_read")),
            "content_length": item.get("content_length", ""),
        })
    return redacted


def _redact_key(key: str) -> str:
    return re.sub(r"(?i)(password|passwd|secret|token|api[_-]?key)=([^/&\s]+)", r"\1=<redacted>", key)


def _shell_quote(value: str) -> str:
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def _report_dir_name(result: Dict) -> str:
    if result.get("module") == "elasticsearch":
        return _safe_name(f"elasticsearch_{result.get('host', 'host')}_{result.get('port', '')}")
    if result.get("module") == "laravel_debug":
        return _safe_name(f"laravel_debug_{result.get('host', 'host')}_{result.get('port') or result.get('scheme', '')}")
    if result.get("module") == "trufflehog_s3":
        return _safe_name(f"trufflehog_s3_{result.get('bucket') or result.get('host') or 'bucket'}")
    return _safe_name(result.get("bucket") or result.get("host") or "s3")


def _find_screenshot_browser() -> str:
    for binary in ("firefox", "chromium", "chromium-browser", "google-chrome"):
        path = shutil.which(binary)
        if path:
            return path
    return ""


def _screenshot_command(browser: str, png_path: str, url: str) -> List[str]:
    name = os.path.basename(browser).lower()
    if "firefox" in name:
        return [browser, "--headless", "--screenshot", png_path, "--window-size=1280,1100", url]
    return [
        browser,
        "--headless",
        "--disable-gpu",
        "--no-sandbox",
        f"--screenshot={png_path}",
        "--window-size=1280,1100",
        url,
    ]


def _safe_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return safe[:120] or "finding"


def _write_text(path: str, content: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _write_json(path: str, data: Dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _svg_text(value: str) -> str:
    return html.escape(value, quote=True)
