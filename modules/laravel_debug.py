#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Laravel debug exposure scanner module."""

import re
import time
from html import unescape
from typing import Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

from modules.base import ModuleResult, ScannerModule, ScanTarget

requests.packages.urllib3.disable_warnings()


LARAVEL_MARKERS = [
    "laravel", "illuminate\\", "illuminate/", "vendor/laravel/framework",
    "laravel framework", "csrf-token", "laravel_session"
]

DEBUG_MARKERS = [
    "whoops", "facade\\ignition", "ignition", "stack trace",
    "stacktrace", "symfony\\component", "exception", "app_debug",
    "php debugbar", "debugbar", "trace"
]

ENV_SECRET_PATTERNS = {
    "app_key": re.compile(r"\bAPP_KEY\s*=\s*([^\s<>'\"]+)", re.IGNORECASE),
    "db_password": re.compile(r"\bDB_PASSWORD\s*=\s*([^\s<>'\"]+)", re.IGNORECASE),
    "aws_access_key_id": re.compile(r"\bAWS_ACCESS_KEY_ID\s*=\s*([^\s<>'\"]+)", re.IGNORECASE),
    "aws_secret_access_key": re.compile(r"\bAWS_SECRET_ACCESS_KEY\s*=\s*([^\s<>'\"]+)", re.IGNORECASE),
    "mail_password": re.compile(r"\bMAIL_PASSWORD\s*=\s*([^\s<>'\"]+)", re.IGNORECASE),
    "redis_password": re.compile(r"\bREDIS_PASSWORD\s*=\s*([^\s<>'\"]+)", re.IGNORECASE),
    "api_key": re.compile(r"\b[A-Z0-9_]*(?:API[_-]?KEY|SECRET|TOKEN)\s*=\s*([^\s<>'\"]+)", re.IGNORECASE),
}

ENVIRONMENT_PATTERNS = {
    "production": [
        re.compile(r"\bAPP_ENV\s*=\s*production\b", re.IGNORECASE),
        re.compile(r"\bAPP_ENV['\"]?\s*[:=]\s*['\"]production['\"]", re.IGNORECASE),
        re.compile(r"\bproduction\b", re.IGNORECASE),
    ],
    "test": [
        re.compile(r"\bAPP_ENV\s*=\s*(local|dev|development|staging|stage|test|testing|qa)\b", re.IGNORECASE),
        re.compile(r"\bAPP_ENV['\"]?\s*[:=]\s*['\"](local|dev|development|staging|stage|test|testing|qa)['\"]", re.IGNORECASE),
    ],
}

CONTACT_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}")
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
META_RE = re.compile(
    r"<meta[^>]+(?:property|name)=['\"](?:og:site_name|application-name|author|copyright)['\"][^>]+content=['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)


class LaravelDebugModule(ScannerModule):
    name = "laravel_debug"
    description = "Detects exposed Laravel debug pages and prioritizes reports"

    def scan(self, target: ScanTarget, timeout: int, sample_size: int) -> Iterable[ModuleResult]:
        for base_url in self._candidate_base_urls(target):
            result = self._scan_base_url(base_url, target, timeout)
            if result:
                yield result
                return

    def _candidate_base_urls(self, target: ScanTarget) -> List[str]:
        if target.url:
            parsed = urlparse(target.url)
            if parsed.scheme and parsed.netloc:
                return [f"{parsed.scheme}://{parsed.netloc}"]

        if target.raw.startswith(("http://", "https://")):
            parsed = urlparse(target.raw)
            if parsed.scheme and parsed.netloc:
                return [f"{parsed.scheme}://{parsed.netloc}"]

        host = target.host
        port = target.port
        if port == 443:
            return [f"https://{host}:443", f"http://{host}:443"]
        if port == 80:
            return [f"http://{host}:80", f"https://{host}:80"]
        if port:
            return [f"http://{host}:{port}", f"https://{host}:{port}"]
        return [f"https://{host}", f"http://{host}"]

    def _scan_base_url(self, base_url: str, target: ScanTarget, timeout: int) -> Optional[ModuleResult]:
        headers = {
            "User-Agent": "modular-research-scanner/1.0 laravel-debug",
            "Accept": "text/html,application/xhtml+xml,application/json,text/plain,*/*",
        }
        probe_path = "/_scanner_laravel_debug_probe_404"
        checks = [("/", "root"), (probe_path, "not_found_probe")]
        pages = []
        started = time.time()

        for path, label in checks:
            page = self._get(base_url + path, headers, timeout)
            if page:
                page["label"] = label
                pages.append(page)

        if not pages:
            return None

        combined = "\n".join(page["text"][:250000] for page in pages)
        detected_rules, sample_data, evidence = self._analyze_debug_content(combined, pages)
        if not detected_rules:
            return None

        environment, env_confidence, env_signals = self._classify_environment(combined, base_url)
        owner = self._discover_owner(base_url, headers, timeout, pages)
        severity_score = self._severity_score(detected_rules, environment, owner)
        false_positive_confidence = self._false_positive_confidence(detected_rules, evidence)
        notification_priority = self._notification_priority(severity_score, detected_rules, environment)

        parsed = urlparse(base_url)
        return ModuleResult(
            module=self.name,
            url=base_url,
            host=parsed.hostname or target.host,
            port=parsed.port or target.port,
            scheme=parsed.scheme,
            accessible=True,
            severity_score=severity_score,
            detected_rules=detected_rules,
            sample_data=sample_data,
            environment=environment,
            environment_confidence=env_confidence,
            environment_signals=env_signals,
            response_time=time.time() - started,
            details={
                "notification_priority": notification_priority,
                "false_positive_confidence": false_positive_confidence,
                "evidence": evidence[:12],
                "owner": owner,
                "checked_paths": [page["url"] for page in pages],
                "status_codes": {page["label"]: page["status_code"] for page in pages},
            }
        )

    def _get(self, url: str, headers: Dict, timeout: int) -> Optional[Dict]:
        try:
            response = requests.get(
                url,
                timeout=timeout,
                headers=headers,
                verify=False,
                allow_redirects=True,
            )
        except RequestException:
            return None

        content_type = response.headers.get("Content-Type", "")
        text = response.text if self._is_text_response(content_type, response.content) else ""
        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "text": text,
        }

    def _is_text_response(self, content_type: str, content: bytes) -> bool:
        if any(kind in content_type.lower() for kind in ["text/", "json", "html", "xml", "javascript"]):
            return True
        return len(content) < 512000

    def _analyze_debug_content(self, content: str, pages: List[Dict]) -> Tuple[List[str], Dict, List[str]]:
        lower = content.lower()
        laravel_hits = sorted({marker for marker in LARAVEL_MARKERS if marker in lower})
        debug_hits = sorted({marker for marker in DEBUG_MARKERS if marker in lower})
        env_secret_hits = self._env_secret_hits(content)
        evidence = []

        for page in pages:
            if page["status_code"] >= 500:
                evidence.append(f"{page['label']}:http_{page['status_code']}")

        evidence.extend(f"laravel:{hit}" for hit in laravel_hits[:5])
        evidence.extend(f"debug:{hit}" for hit in debug_hits[:5])
        evidence.extend(f"secret:{hit}" for hit in env_secret_hits[:5])

        # False-positive control: require Laravel signal plus debug signal, or
        # Laravel signal plus explicit env/secrets leak. A generic 500 page is
        # not enough.
        if not laravel_hits or not (debug_hits or env_secret_hits):
            return [], {}, evidence

        detected = ["laravel_debug"]
        sample_data = {
            "laravel_debug": {
                "category": "🔴 CRITICAL",
                "description": "Laravel debug/exception page is exposed",
                "matched": (laravel_hits + debug_hits)[:8],
                "severity": 10,
            }
        }

        if any(page["status_code"] >= 500 for page in pages):
            detected.append("server_error_debug")
            sample_data["server_error_debug"] = {
                "category": "🟠 HIGH",
                "description": "Debug page is reachable on server error response",
                "matched": [str(page["status_code"]) for page in pages if page["status_code"] >= 500],
                "severity": 8,
            }

        if "stack trace" in lower or "stacktrace" in lower or "trace" in lower:
            detected.append("stack_trace")
            sample_data["stack_trace"] = {
                "category": "🟠 HIGH",
                "description": "Stack trace or trace frames are exposed",
                "matched": [hit for hit in debug_hits if "trace" in hit][:5],
                "severity": 8,
            }

        if env_secret_hits:
            detected.append("env_secrets")
            sample_data["env_secrets"] = {
                "category": "🔴 CRITICAL",
                "description": "Environment variables or secrets appear in debug output",
                "matched": env_secret_hits[:8],
                "severity": 10,
            }

        return detected, sample_data, evidence

    def _env_secret_hits(self, content: str) -> List[str]:
        hits = []
        for name, pattern in ENV_SECRET_PATTERNS.items():
            match = pattern.search(content)
            if match:
                value = match.group(1)
                if value and value.lower() not in {"null", "false", "true", "empty", "redacted"}:
                    hits.append(name)
        return hits

    def _classify_environment(self, content: str, base_url: str) -> Tuple[str, int, List[str]]:
        signals = []
        for pattern in ENVIRONMENT_PATTERNS["test"]:
            match = pattern.search(content)
            if match:
                signals.append(f"content:{match.group(0)[:60]}")
                return "test", 90, signals

        for pattern in ENVIRONMENT_PATTERNS["production"]:
            match = pattern.search(content)
            if match:
                signals.append(f"content:{match.group(0)[:60]}")
                return "production", 90, signals

        parsed = urlparse(base_url)
        host = parsed.hostname or ""
        if re.search(r"(^|[.-])(dev|test|qa|stage|staging|local|sandbox)([.-]|$)", host, re.IGNORECASE):
            return "test", 70, [f"host:{host}"]
        if re.search(r"(^|[.-])(prod|production|live)([.-]|$)", host, re.IGNORECASE):
            return "production", 75, [f"host:{host}"]

        return "unknown", 0, []

    def _discover_owner(self, base_url: str, headers: Dict, timeout: int, pages: List[Dict]) -> Dict:
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        sources = []
        contacts = []
        company = ""

        for path in ["/.well-known/security.txt", "/security.txt"]:
            page = self._get(origin + path, headers, timeout)
            if page and page["status_code"] == 200 and page["text"]:
                sources.append(path)
                contacts.extend(CONTACT_RE.findall(page["text"]))

        homepage_text = pages[0]["text"] if pages else ""
        if homepage_text:
            title_match = TITLE_RE.search(homepage_text)
            if title_match:
                company = self._clean_text(title_match.group(1))[:120]
                sources.append("homepage:title")

            meta_match = META_RE.search(homepage_text)
            if meta_match and not company:
                company = self._clean_text(meta_match.group(1))[:120]
                sources.append("homepage:meta")

            contacts.extend(CONTACT_RE.findall(homepage_text))

        domain = parsed.hostname or ""
        filtered_contacts = self._filter_contacts(contacts, domain)
        confidence = 0
        if filtered_contacts:
            confidence += 50
        if any("security.txt" in source for source in sources):
            confidence += 30
        if company:
            confidence += 20

        return {
            "company": company,
            "contacts": filtered_contacts[:8],
            "confidence": min(confidence, 100),
            "sources": sources[:8],
        }

    def _filter_contacts(self, contacts: List[str], domain: str) -> List[str]:
        seen = set()
        filtered = []
        provider_terms = {"amazonaws.com", "cloudfront.net", "azure.com", "googleapis.com"}
        root_domain = ".".join(domain.split(".")[-2:]) if "." in domain else domain

        for contact in contacts:
            normalized = contact.strip(".,;:()[]<>").lower()
            if normalized in seen:
                continue
            seen.add(normalized)
            if any(term in normalized for term in provider_terms):
                continue
            if root_domain and root_domain not in normalized and not normalized.startswith(("security@", "support@", "abuse@")):
                continue
            filtered.append(normalized)

        return filtered

    def _clean_text(self, text: str) -> str:
        return re.sub(r"\s+", " ", unescape(re.sub(r"<[^>]+>", " ", text))).strip()

    def _severity_score(self, detected_rules: List[str], environment: str, owner: Dict) -> int:
        score = 0
        weights = {
            "laravel_debug": 25,
            "server_error_debug": 10,
            "stack_trace": 10,
            "env_secrets": 35,
        }
        for rule in detected_rules:
            score += weights.get(rule, 0)
        if environment == "production":
            score += 15
        if owner.get("contacts"):
            score += 5
        return min(score, 100)

    def _false_positive_confidence(self, detected_rules: List[str], evidence: List[str]) -> int:
        confidence = 40
        confidence += min(len(evidence), 8) * 5
        if "env_secrets" in detected_rules:
            confidence += 20
        if "stack_trace" in detected_rules:
            confidence += 15
        return min(confidence, 100)

    def _notification_priority(self, severity_score: int, detected_rules: List[str], environment: str) -> str:
        if severity_score >= 70 or ("env_secrets" in detected_rules and environment == "production"):
            return "urgent"
        if severity_score >= 45:
            return "high"
        if severity_score >= 25:
            return "medium"
        return "low"
