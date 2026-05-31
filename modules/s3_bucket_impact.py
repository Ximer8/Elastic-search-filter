#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""AWS S3 bucket exposure and impact scanner module."""

import re
import time
import xml.etree.ElementTree as ET
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from modules.base import ModuleResult, ScannerModule, ScanTarget

requests.packages.urllib3.disable_warnings()


BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
AWS_ERROR_RE = re.compile(r"<Code>([^<]+)</Code>", re.IGNORECASE)

SENSITIVE_KEY_PATTERNS = {
    "secrets": re.compile(r"(^|[/._-])(\.env|secret|secrets|credential|credentials|token|apikey|api-key)([/._-]|$)", re.I),
    "private_keys": re.compile(r"\.(pem|key|p12|pfx|jks|keystore)$", re.I),
    "database_backups": re.compile(r"(^|[/._-])(backup|dump|db|database|mysql|postgres|mongo|redis)([/._-]|$)|\.(sql|dump|bak)$", re.I),
    "archives": re.compile(r"\.(zip|tar|tgz|gz|7z|rar)$", re.I),
    "logs": re.compile(r"(^|[/._-])(log|logs|access|error|debug)([/._-]|$)|\.log$", re.I),
    "pii_named": re.compile(r"(customer|user|users|client|clients|email|emails|phone|passport|ssn|invoice|billing|payment)", re.I),
    "source_code": re.compile(r"(^|/)(\.git|src|source|config|settings)(/|$)|\.(py|php|rb|go|java|env|yaml|yml|ini|conf|properties)$", re.I),
}
STATIC_ASSET_RE = re.compile(
    r"\.(?:js|mjs|css|map|png|jpe?g|gif|webp|svg|ico|bmp|tiff?|avif|woff2?|ttf|eot|otf|mp4|webm|mov|mp3|wav|pdf)$",
    re.I,
)
SENSITIVE_RULES = {"secrets", "private_keys", "database_backups", "logs", "pii_named", "source_code"}


class S3BucketImpactModule(ScannerModule):
    name = "s3_bucket_impact"
    description = "Assesses public AWS S3 bucket exposure and business impact"

    def scan(self, target: ScanTarget, timeout: int, sample_size: int) -> Iterable[ModuleResult]:
        bucket, endpoints = self._bucket_and_endpoints_from_target(target)
        if not bucket:
            return

        for endpoint in endpoints:
            result = self._scan_endpoint(bucket, endpoint, timeout, sample_size)
            if result:
                yield result
                return

    def _scan_endpoint(
        self,
        bucket: str,
        endpoint: Dict[str, str],
        timeout: int,
        sample_size: int,
    ) -> Optional[ModuleResult]:
        started = time.time()
        base_url = endpoint["base_url"]
        headers = {
            "User-Agent": "modular-research-scanner/1.0 s3-bucket-impact",
            "Accept": "application/xml,text/xml,text/plain,*/*",
        }

        head = self._request("HEAD", base_url, headers, timeout)
        if not head:
            return

        region = head["headers"].get("x-amz-bucket-region", "")
        bucket_exists = head["status_code"] in {200, 301, 302, 307, 400, 403} or self._looks_like_s3_response(head)
        if not bucket_exists:
            return None

        separator = "&" if "?" in endpoint["list_url"] else "?"
        listing_url = f"{endpoint['list_url']}{separator}list-type=2&max-keys={max(1, min(sample_size, 1000))}"
        listing = self._request("GET", listing_url, headers, timeout)
        if listing and not region:
            region = listing["headers"].get("x-amz-bucket-region", "")
        object_keys = self._parse_listed_keys(listing["text"]) if listing else []
        public_listing = bool(listing and listing["status_code"] == 200 and object_keys)

        checked_objects = []
        public_read_count = 0
        for key in object_keys[: min(len(object_keys), 25)]:
            object_url = f"{endpoint['object_base_url'].rstrip('/')}/{self._quote_key(key)}"
            obj_head = self._request("HEAD", object_url, headers, timeout)
            status_code = obj_head["status_code"] if obj_head else 0
            content_length = obj_head["headers"].get("Content-Length", "") if obj_head else ""
            public_read = status_code == 200
            if public_read:
                public_read_count += 1
            checked_objects.append({
                "key": key,
                "status": status_code,
                "public_read": public_read,
                "content_length": content_length,
            })

        detected_rules, sample_data, evidence = self._analyze(bucket, head, listing, object_keys, checked_objects)
        if not self._has_actionable_exposure(detected_rules):
            return None
        if not detected_rules:
            return None

        environment, env_confidence, env_signals = self._classify_environment(bucket, object_keys)
        severity_score = self._severity_score(
            detected_rules,
            environment,
            len(object_keys),
            public_read_count,
            object_keys,
        )
        priority = self._notification_priority(severity_score, detected_rules)
        report = self._security_report(
            bucket=bucket,
            region=region,
            severity_score=severity_score,
            priority=priority,
            detected_rules=detected_rules,
            object_keys=object_keys,
            checked_objects=checked_objects,
            evidence=evidence,
            environment=environment,
        )

        return ModuleResult(
            module=self.name,
            url=base_url,
            host=bucket,
            port=443,
            scheme="https",
            accessible=True,
            severity_score=severity_score,
            detected_rules=detected_rules,
            sample_data=sample_data,
            environment=environment,
            environment_confidence=env_confidence,
            environment_signals=env_signals,
            response_time=time.time() - started,
            details={
                "bucket": bucket,
                "region": region,
                "endpoint_source": endpoint.get("source", "unknown"),
                "notification_priority": priority,
                "public_listing": public_listing,
                "listed_objects": len(object_keys),
                "public_read_checked": public_read_count,
                "checked_objects": checked_objects[:25],
                "evidence": evidence[:16],
                "security_report": report,
                "status_codes": {
                    "bucket_head": head["status_code"],
                    "list_objects": listing["status_code"] if listing else 0,
                },
            },
        )

    def _bucket_and_endpoints_from_target(self, target: ScanTarget) -> Tuple[Optional[str], List[Dict[str, str]]]:
        for item in self._target_values(target):
            bucket, endpoints = self._bucket_and_endpoints_from_text(item)
            if bucket:
                return bucket, endpoints
        return None, []

    def _target_values(self, target: ScanTarget) -> List[str]:
        values = []
        for item in [target.raw, target.url, target.host]:
            if item and item not in values:
                values.append(item)
        return values

    def _bucket_and_endpoints_from_text(self, value: str) -> Tuple[Optional[str], List[Dict[str, str]]]:
        value = value.strip().strip("/").strip()
        if not value:
            return None, []

        if value.startswith("s3://"):
            bucket = value[5:].split("/", 1)[0]
            if not self._valid_bucket(bucket):
                return None, []
            return bucket, self._dedupe_endpoints([self._canonical_endpoint(bucket)])

        if self._looks_like_s3_http_value(value) and not value.startswith(("http://", "https://")):
            return self._bucket_and_endpoints_from_text(f"https://{value}")

        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            bucket, original_endpoint, region = self._endpoint_from_parsed_url(parsed)
            if not bucket:
                return None, []

            endpoints = [original_endpoint]
            if region and "amazonaws.com" in (parsed.hostname or ""):
                endpoints.append(self._regional_endpoint(bucket, region))
            if "amazonaws.com" in (parsed.hostname or ""):
                endpoints.append(self._canonical_endpoint(bucket))
            return bucket, self._dedupe_endpoints(endpoints)

        if "." in value:
            return None, []
        if self._valid_bucket(value):
            return value, self._dedupe_endpoints([self._canonical_endpoint(value)])
        return None, []

    def _looks_like_s3_http_value(self, value: str) -> bool:
        lowered = value.lower()
        return (
            "amazonaws.com" in lowered
            or "digitaloceanspaces.com" in lowered
            or "storage.googleapis.com" in lowered
        )

    def _endpoint_from_parsed_url(self, parsed) -> Tuple[Optional[str], Optional[Dict[str, str]], str]:
        host = parsed.hostname or ""
        path_parts = [part for part in parsed.path.split("/") if part]
        origin = f"{parsed.scheme}://{host}"
        region = ""

        match = re.match(r"^(.+)\.s3[.-]([a-z0-9-]+)\.amazonaws\.com$", host)
        if match:
            bucket = match.group(1)
            region = match.group(2)
            if self._valid_bucket(bucket):
                return bucket, self._virtual_hosted_endpoint(origin, "original"), region

        match = re.match(r"^(.+)\.s3\.amazonaws\.com$", host)
        if match:
            bucket = match.group(1)
            if self._valid_bucket(bucket):
                return bucket, self._virtual_hosted_endpoint(origin, "original"), region

        match = re.match(r"^(.+)\.s3-website[.-]([a-z0-9-]+)\.amazonaws\.com$", host)
        if match:
            bucket = match.group(1)
            region = match.group(2)
            if self._valid_bucket(bucket):
                return bucket, self._virtual_hosted_endpoint(origin, "original"), region

        if re.match(r"^s3[.-]([a-z0-9-]+)\.amazonaws\.com$", host) or host == "s3.amazonaws.com":
            region_match = re.match(r"^s3[.-]([a-z0-9-]+)\.amazonaws\.com$", host)
            region = region_match.group(1) if region_match else ""
            if path_parts and self._valid_bucket(path_parts[0]):
                bucket = path_parts[0]
                base_url = f"{origin}/{bucket}"
                return bucket, self._path_style_endpoint(base_url, "original"), region

        if self._looks_like_s3_http_value(host):
            bucket = host.split(".", 1)[0]
            if self._valid_bucket(bucket):
                return bucket, self._virtual_hosted_endpoint(origin, "original"), region

        return None, None, ""

    def _virtual_hosted_endpoint(self, base_url: str, source: str) -> Dict[str, str]:
        return {
            "base_url": base_url.rstrip("/"),
            "list_url": f"{base_url.rstrip('/')}/",
            "object_base_url": base_url.rstrip("/"),
            "source": source,
        }

    def _path_style_endpoint(self, base_url: str, source: str) -> Dict[str, str]:
        return {
            "base_url": base_url.rstrip("/"),
            "list_url": base_url.rstrip("/"),
            "object_base_url": base_url.rstrip("/"),
            "source": source,
        }

    def _canonical_endpoint(self, bucket: str) -> Dict[str, str]:
        return self._virtual_hosted_endpoint(f"https://{bucket}.s3.amazonaws.com", "canonical")

    def _regional_endpoint(self, bucket: str, region: str) -> Dict[str, str]:
        return self._virtual_hosted_endpoint(f"https://{bucket}.s3.{region}.amazonaws.com", "regional")

    def _dedupe_endpoints(self, endpoints: List[Optional[Dict[str, str]]]) -> List[Dict[str, str]]:
        deduped = []
        seen = set()
        for endpoint in endpoints:
            if not endpoint:
                continue
            key = (endpoint["base_url"], endpoint["list_url"], endpoint["object_base_url"])
            if key not in seen:
                seen.add(key)
                deduped.append(endpoint)
        return deduped

    def _request(self, method: str, url: str, headers: Dict, timeout: int) -> Optional[Dict]:
        response = None
        for attempt in range(3):
            try:
                response = requests.request(
                    method,
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=False,
                )
                break
            except RequestException:
                if attempt == 2:
                    return None
                time.sleep(0.25 * (attempt + 1))

        text = ""
        if method != "HEAD":
            content_type = response.headers.get("Content-Type", "")
            if any(kind in content_type.lower() for kind in ["xml", "text", "json"]) or len(response.content) < 512000:
                text = response.text

        return {
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": text,
        }

    def _looks_like_s3_response(self, response: Dict) -> bool:
        headers = {str(key).lower(): str(value).lower() for key, value in response.get("headers", {}).items()}
        server = headers.get("server", "")
        return (
            "amazons3" in server
            or any(key.startswith("x-amz-") for key in headers)
            or "<code>nosuchkey</code>" in (response.get("text") or "").lower()
        )

    def _bucket_from_target(self, target: ScanTarget) -> Optional[str]:
        bucket, _ = self._bucket_and_endpoints_from_target(target)
        return bucket

    def _bucket_from_text(self, value: str) -> Optional[str]:
        value = value.strip().strip("/").strip()
        if not value:
            return None

        if value.startswith("s3://"):
            value = value[5:].split("/", 1)[0]
            return value if self._valid_bucket(value) else None

        if "amazonaws.com" in value and not value.startswith(("http://", "https://")):
            return self._bucket_from_text(f"https://{value}")

        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            host = parsed.hostname or ""
            path_parts = [part for part in parsed.path.split("/") if part]

            match = re.match(r"^(.+)\.s3[.-][a-z0-9-]+\.amazonaws\.com$", host)
            if not match:
                match = re.match(r"^(.+)\.s3\.amazonaws\.com$", host)
            if not match:
                match = re.match(r"^(.+)\.s3-website[.-][a-z0-9-]+\.amazonaws\.com$", host)
            if match:
                bucket = match.group(1)
                return bucket if self._valid_bucket(bucket) else None

            if re.match(r"^s3[.-][a-z0-9-]+\.amazonaws\.com$", host) or host == "s3.amazonaws.com":
                if path_parts and self._valid_bucket(path_parts[0]):
                    return path_parts[0]
            return None

        if self._valid_bucket(value):
            return value
        return None

    def _valid_bucket(self, bucket: str) -> bool:
        if not BUCKET_RE.match(bucket):
            return False
        if ".." in bucket or ".-" in bucket or "-." in bucket:
            return False
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", bucket):
            return False
        return True

    def _parse_listed_keys(self, xml_text: str) -> List[str]:
        if not xml_text:
            return []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return []

        keys = []
        for elem in root.iter():
            if elem.tag.endswith("Key") and elem.text:
                keys.append(elem.text)
        return keys

    def _quote_key(self, key: str) -> str:
        from urllib.parse import quote

        return quote(key, safe="/")

    def _analyze(
        self,
        bucket: str,
        head: Dict,
        listing: Optional[Dict],
        object_keys: List[str],
        checked_objects: List[Dict],
    ) -> Tuple[List[str], Dict, List[str]]:
        detected = []
        sample_data = {}
        evidence = [f"bucket_head:http_{head['status_code']}"]

        if head["status_code"] == 200:
            detected.append("bucket_public_head")
            evidence.append("bucket_head_public")

        if listing:
            evidence.append(f"list_objects:http_{listing['status_code']}")
            if listing["status_code"] == 200 and object_keys:
                detected.append("public_bucket_listing")
                sample_data["public_bucket_listing"] = {
                    "category": "CRITICAL",
                    "description": "Bucket object listing is publicly accessible",
                    "matched": object_keys[:10],
                    "severity": 10,
                }

        public_objects = [item["key"] for item in checked_objects if item.get("public_read")]
        if public_objects:
            detected.append("public_object_read")
            sample_data["public_object_read"] = {
                "category": "HIGH",
                "description": "One or more listed objects are publicly readable",
                "matched": public_objects[:10],
                "severity": 8,
            }
            evidence.append(f"public_read_objects:{len(public_objects)}")

        sensitive_hits = self._sensitive_key_hits(object_keys)
        for rule, hits in sensitive_hits.items():
            detected.append(rule)
            sample_data[rule] = {
                "category": "HIGH",
                "description": f"Sensitive object names matched {rule}",
                "matched": hits[:10],
                "severity": 8,
            }

        error_code = self._aws_error_code(listing["text"]) if listing else ""
        if error_code in {"AccessDenied", "AllAccessDisabled"} and not object_keys:
            detected.append("listing_blocked")
            sample_data["listing_blocked"] = {
                "category": "INFO",
                "description": "Bucket exists, but anonymous listing is blocked",
                "matched": [error_code],
                "severity": 1,
            }
            evidence.append(f"aws_error:{error_code}")

        if bucket and re.search(r"(^|[.-])(prod|production|customer|client|billing|backup|data)([.-]|$)", bucket, re.I):
            detected.append("business_context_in_name")
            sample_data["business_context_in_name"] = {
                "category": "MEDIUM",
                "description": "Bucket name suggests production or business data context",
                "matched": [bucket],
                "severity": 5,
            }

        return list(dict.fromkeys(detected)), sample_data, evidence

    def _has_actionable_exposure(self, detected_rules: List[str]) -> bool:
        actionable = {
            "bucket_public_head",
            "public_bucket_listing",
            "public_object_read",
            "secrets",
            "private_keys",
            "database_backups",
            "archives",
            "logs",
            "pii_named",
            "source_code",
        }
        return bool(set(detected_rules) & actionable)

    def _aws_error_code(self, text: str) -> str:
        match = AWS_ERROR_RE.search(text or "")
        return match.group(1) if match else ""

    def _sensitive_key_hits(self, object_keys: List[str]) -> Dict[str, List[str]]:
        hits = {}
        for rule, pattern in SENSITIVE_KEY_PATTERNS.items():
            matched = [key for key in object_keys if pattern.search(key)]
            if matched:
                hits[rule] = matched
        return hits

    def _classify_environment(self, bucket: str, object_keys: List[str]) -> Tuple[str, int, List[str]]:
        combined = " ".join([bucket] + object_keys[:100]).lower()
        if re.search(r"(^|[./_-])(dev|test|qa|stage|staging|sandbox|demo)([./_-]|$)", combined):
            return "test", 75, ["bucket_or_key:test_marker"]
        if re.search(r"(^|[./_-])(prod|production|live|customer|client|billing)([./_-]|$)", combined):
            return "production", 80, ["bucket_or_key:production_marker"]
        return "unknown", 0, []

    def _severity_score(
        self,
        detected_rules: List[str],
        environment: str,
        listed_count: int,
        public_read_count: int,
        object_keys: Optional[List[str]] = None,
    ) -> int:
        weights = {
            "bucket_public_head": 5,
            "public_bucket_listing": 20,
            "public_object_read": 12,
            "secrets": 25,
            "private_keys": 30,
            "database_backups": 25,
            "archives": 10,
            "logs": 12,
            "pii_named": 20,
            "source_code": 18,
            "business_context_in_name": 8,
            "listing_blocked": 1,
        }
        score = sum(weights.get(rule, 0) for rule in detected_rules)
        if environment == "production":
            score += 15
        if listed_count >= 100:
            score += 10
        if public_read_count >= 10:
            score += 10
        if self._mostly_static_assets(object_keys or []) and not (set(detected_rules) & SENSITIVE_RULES):
            score = min(score, 35 if environment != "production" else 45)
        return min(score, 100)

    def _mostly_static_assets(self, object_keys: List[str]) -> bool:
        if not object_keys:
            return False
        sampled = object_keys[: min(len(object_keys), 50)]
        static_count = sum(1 for key in sampled if STATIC_ASSET_RE.search(key))
        return static_count / len(sampled) >= 0.8

    def _notification_priority(self, severity_score: int, detected_rules: List[str]) -> str:
        if severity_score >= 70 or "private_keys" in detected_rules or "secrets" in detected_rules:
            return "urgent"
        if severity_score >= 45:
            return "high"
        if severity_score >= 20:
            return "medium"
        return "low"

    def _security_report(
        self,
        bucket: str,
        region: str,
        severity_score: int,
        priority: str,
        detected_rules: List[str],
        object_keys: List[str],
        checked_objects: List[Dict],
        evidence: List[str],
        environment: str,
    ) -> str:
        sensitive_examples = []
        for rule, hits in self._sensitive_key_hits(object_keys).items():
            sensitive_examples.extend(f"{rule}: {key}" for key in hits[:3])

        public_examples = [item["key"] for item in checked_objects if item.get("public_read")][:5]
        lines = [
            f"S3 Bucket Security Report: {bucket}",
            f"Region: {region or 'unknown'}",
            f"Environment: {environment}",
            f"Priority: {priority}",
            f"Severity Score: {severity_score}/100",
            f"Detected Rules: {', '.join(detected_rules) if detected_rules else 'none'}",
            "",
            "Impact:",
        ]

        if "public_bucket_listing" in detected_rules:
            lines.append(f"- Anonymous users can list object names. Listed sample size: {len(object_keys)}.")
        if "public_object_read" in detected_rules:
            lines.append(f"- Anonymous users can read at least {len(public_examples)} sampled object(s).")
        if sensitive_examples:
            lines.append("- Object names suggest sensitive data may be present: " + "; ".join(sensitive_examples[:8]))
        if "listing_blocked" in detected_rules:
            lines.append("- Bucket exists, but anonymous listing was blocked in this check.")

        lines.extend([
            "",
            "Evidence:",
            "- " + "; ".join(evidence[:10]),
            "",
            "Recommended Remediation:",
            "- Disable public ACLs and public bucket policies unless the bucket is intentionally public.",
            "- Enable S3 Block Public Access at account and bucket level.",
            "- Review bucket policy, object ACLs, and IAM principals with s3:GetObject/s3:ListBucket.",
            "- Move secrets, backups, database dumps, logs, and PII out of public buckets.",
            "- Enable S3 server access logs or CloudTrail data events for investigation.",
            "- Rotate credentials if keys, tokens, private keys, or database dumps were exposed.",
        ])
        return "\n".join(lines)
