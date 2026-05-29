#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Modular research scanner.

This is the new module-aware entrypoint. Existing Elasticsearch scripts remain
available for compatibility, while new checks should be added as modules.
"""

import argparse
import csv
import json
import os
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

import es_advanced_scanner
from modules.base import ScanTarget
from modules.registry import AVAILABLE_MODULES, get_modules


URL_RE = re.compile(r"https?://[^\s,\"'<>]+", re.IGNORECASE)
TOKEN_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{1,253}$")


def load_targets(path: str, delimiter: str = ",") -> List[ScanTarget]:
    """Loads targets and normalizes them for modules."""
    targets = []
    seen = set()
    for host, port in es_advanced_scanner.extract_targets_from_csv(path, delimiter=delimiter):
        raw = f"{host}:{port}" if port else host
        key = target_dedupe_key(ScanTarget(raw=raw, host=host, port=port))
        if key not in seen:
            seen.add(key)
            targets.append(ScanTarget(raw=raw, host=host, port=port))

    for raw in extract_generic_targets(path, delimiter=delimiter):
        target = normalize_generic_target(raw)
        key = target_dedupe_key(target)
        if key not in seen:
            seen.add(key)
            targets.append(target)
    return targets


def target_dedupe_key(target: ScanTarget):
    """Deduplicates URL and host:port forms of the same target."""
    host = (target.host or "").lower().strip()
    port = target.port

    if host:
        return ("network", host, port)
    return ("raw", target.raw.lower().strip())


def extract_generic_targets(path: str, delimiter: str = ",") -> List[str]:
    """Extracts URL/domain/bucket-like values for non-IP modules such as S3."""
    values = []
    seen = set()
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        sample = f.read(4096)
        f.seek(0)
        has_delimiter = delimiter in sample

        rows = csv.reader(f, delimiter=delimiter) if has_delimiter else ([line.strip()] for line in f)
        for row in rows:
            for cell in row:
                for value in split_candidate_values(str(cell), allow_plain=not has_delimiter):
                    if value and value not in seen:
                        seen.add(value)
                        values.append(value)
    return values


def split_candidate_values(text: str, allow_plain: bool = False) -> List[str]:
    values = []
    for url in URL_RE.findall(text):
        values.append(url.strip())
        text = text.replace(url, " ")

    for token in re.split(r"[\s,;]+", text):
        token = token.strip().strip("\"'<>")
        if not token or token.lower() in {"host", "ip", "port", "protocol", "title", "domain", "country", "city", "link", "org"}:
            continue
        if token.startswith("s3://") or "amazonaws.com" in token:
            values.append(token)
            continue
        if allow_plain and TOKEN_RE.match(token) and any(ch.isalpha() for ch in token):
            values.append(token)
    return values


def normalize_generic_target(raw: str) -> ScanTarget:
    if raw.startswith(("http://", "https://")):
        from urllib.parse import urlparse

        parsed = urlparse(raw)
        return ScanTarget(
            raw=raw,
            host=parsed.hostname or parsed.netloc or raw,
            port=parsed.port,
            scheme=parsed.scheme,
            url=raw,
        )

    if raw.startswith("s3://"):
        bucket = raw[5:].split("/", 1)[0]
        return ScanTarget(raw=raw, host=bucket, port=None, scheme="s3", url=raw)

    host = raw.split("/", 1)[0]
    return ScanTarget(raw=raw, host=host, port=None)


def result_line(result: dict) -> str:
    severity_emoji = (
        "🔴" if result["severity_score"] >= 50
        else "🟠" if result["severity_score"] >= 30
        else "🟡" if result["severity_score"] >= 10
        else "🟢"
    )

    parts = [
        result.get("module", "unknown"),
        result["url"],
        f"score={result['severity_score']}",
        severity_emoji,
        f"env={result.get('environment', 'unknown')}",
    ]

    if result.get("cluster_name"):
        parts.append(f"cluster={result['cluster_name']}")
    if result.get("version"):
        parts.append(f"ver={result['version']}")
    if result.get("indices_count") is not None:
        parts.append(f"indices={result.get('indices_count', 0)}")
    if result.get("notification_priority"):
        parts.append(f"priority={result['notification_priority']}")
    if result.get("false_positive_confidence") is not None:
        parts.append(f"fp_confidence={result['false_positive_confidence']}")
    owner = result.get("owner") or {}
    if owner.get("contacts"):
        parts.append(f"owner_contact={owner['contacts'][0]}")
    if result.get("detected_rules"):
        parts.append(f"detected={','.join(result['detected_rules'])}")

    return "\t".join(parts)


def compact_module_result(result: dict) -> str:
    """Formats one finding for quick per-module review."""
    lines = [
        f"URL: {result.get('url', '')}",
        f"Score: {result.get('severity_score', 0)}",
        f"Environment: {result.get('environment', 'unknown')} ({result.get('environment_confidence', 0)}%)",
    ]

    if result.get("notification_priority"):
        lines.append(f"Priority: {result['notification_priority']}")
    if result.get("false_positive_confidence") is not None:
        lines.append(f"False Positive Confidence: {result['false_positive_confidence']}%")
    if result.get("detected_rules"):
        lines.append(f"Detections: {', '.join(result['detected_rules'])}")

    owner = result.get("owner") or {}
    if owner:
        contacts = owner.get("contacts") or []
        lines.append(f"Owner Company: {owner.get('company') or 'unknown'}")
        lines.append(f"Owner Confidence: {owner.get('confidence', 0)}%")
        if contacts:
            lines.append(f"Owner Contacts: {', '.join(contacts[:5])}")
        if owner.get("sources"):
            lines.append(f"Owner Sources: {', '.join(owner['sources'][:5])}")

    if result.get("cluster_name"):
        lines.append(f"Cluster: {result['cluster_name']}")
    if result.get("version"):
        lines.append(f"Version: {result['version']}")
    if result.get("indices_count") is not None:
        lines.append(f"Indices: {result.get('indices_count', 0)}")
    if result.get("bucket"):
        lines.append(f"Bucket: {result['bucket']}")
    if result.get("region"):
        lines.append(f"Region: {result['region']}")
    if result.get("listed_objects") is not None:
        lines.append(f"Listed Objects: {result.get('listed_objects', 0)}")
    if result.get("public_read_checked") is not None:
        lines.append(f"Public Read Objects Checked: {result.get('public_read_checked', 0)}")

    evidence = result.get("evidence") or []
    if evidence:
        lines.append(f"Evidence: {', '.join(str(item) for item in evidence[:8])}")

    sample_data = result.get("sample_data") or {}
    if sample_data:
        matched = []
        for rule_name, info in sample_data.items():
            rule_matches = info.get("matched") or []
            if rule_matches:
                matched.append(f"{rule_name}={','.join(str(item) for item in rule_matches[:4])}")
        if matched:
            lines.append(f"Matched: {'; '.join(matched[:6])}")

    checked_paths = result.get("checked_paths") or []
    if checked_paths:
        lines.append(f"Checked Paths: {', '.join(checked_paths[:4])}")

    status_codes = result.get("status_codes") or {}
    if status_codes:
        lines.append(
            "Status Codes: " + ", ".join(f"{key}={value}" for key, value in status_codes.items())
        )

    if result.get("error"):
        lines.append(f"Error: {result['error']}")

    if result.get("security_report"):
        lines.append("")
        lines.append(result["security_report"])

    return "\n".join(lines)


def write_module_summaries(results: List[dict], modules, output_dir: str):
    """Writes one compact summary file per selected module."""
    os.makedirs(output_dir, exist_ok=True)

    by_module = defaultdict(list)
    for result in results:
        by_module[result.get("module", "unknown")].append(result)

    for module in modules:
        module_results = sorted(
            by_module.get(module.name, []),
            key=lambda item: (-item.get("severity_score", 0), item.get("url", ""))
        )
        path = os.path.join(output_dir, f"{module.name}_summary.txt")
        critical = [r for r in module_results if r.get("severity_score", 0) >= 30]

        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Module: {module.name}\n")
            f.write(f"# Description: {module.description}\n")
            f.write(f"# Findings: {len(module_results)}\n")
            f.write(f"# Critical findings: {len(critical)}\n")
            f.write("#" + "=" * 79 + "\n\n")

            if not module_results:
                f.write("No findings.\n")
                continue

            for idx, result in enumerate(module_results, 1):
                f.write(f"## Finding {idx}\n")
                f.write(compact_module_result(result))
                f.write("\n\n")


def print_statistics(results: List[dict], targets_count: int):
    by_module = defaultdict(int)
    critical_by_module = defaultdict(int)
    detections = defaultdict(int)
    environments = defaultdict(int)
    ransomware_notes = 0

    for result in results:
        module = result.get("module", "unknown")
        by_module[module] += 1
        if result["severity_score"] >= 30:
            critical_by_module[module] += 1

        environments[result.get("environment", "unknown") or "unknown"] += 1
        for rule in result.get("detected_rules", []):
            detections[rule] += 1
            if rule == "ransomware_note":
                ransomware_notes += 1

    print("\n" + "=" * 80)
    print("MODULAR SCAN STATISTICS")
    print("=" * 80)
    print(f"Targets: {targets_count}")
    print(f"Findings: {len(results)}")
    print(f"Critical findings (score >= 30): {len([r for r in results if r['severity_score'] >= 30])}")
    print(f"Possible ransomware notes: {ransomware_notes}")

    print("\nBy module:")
    for module, count in sorted(by_module.items(), key=lambda x: x[0]):
        print(f"  {module}: {count} findings ({critical_by_module[module]} critical)")

    print("\nEnvironment split:")
    for env in ["production", "test", "unknown"]:
        print(f"  {env}: {environments.get(env, 0)}")

    if detections:
        print("\nTop detections:")
        for rule, count in sorted(detections.items(), key=lambda x: -x[1])[:12]:
            print(f"  {rule}: {count}")

    print("=" * 80)


def main():
    ap = argparse.ArgumentParser(
        description="Modular research scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"Available modules: {', '.join(sorted(AVAILABLE_MODULES))}"
    )
    ap.add_argument("-i", "--input", required=True, help="CSV file with targets")
    ap.add_argument(
        "--modules",
        default="elasticsearch",
        help="Comma-separated modules to run, or 'all' (default: elasticsearch)"
    )
    ap.add_argument("--delimiter", default=",", help="CSV delimiter (default: ,)")
    ap.add_argument("-w", "--workers", type=int, default=30, help="Worker threads (default: 30)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout seconds (default: 10)")
    ap.add_argument("--sample-size", type=int, default=500, help="Sample size for modules (default: 500)")
    ap.add_argument("--out-results", default="scan_results.txt", help="Text results output")
    ap.add_argument("--out-critical", default="critical_findings.txt", help="Critical findings output")
    ap.add_argument("--out-json", default="scan_results.json", help="JSON output")
    ap.add_argument(
        "--out-module-dir",
        default="module_summaries",
        help="Directory for compact per-module summary files"
    )

    args = ap.parse_args()

    module_names = sorted(AVAILABLE_MODULES) if args.modules == "all" else [
        name.strip() for name in args.modules.split(",") if name.strip()
    ]

    try:
        modules = get_modules(module_names)
    except ValueError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        sys.exit(2)

    print("[*] Loading targets...")
    targets = load_targets(args.input, delimiter=args.delimiter)
    if not targets:
        print("[!] No targets found", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Targets: {len(targets)}")
    print(f"[*] Modules: {', '.join(module.name for module in modules)}")
    print(f"[*] Workers: {args.workers}")

    all_results = []
    tasks = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        future_context = {}
        for target in targets:
            for module in modules:
                future = executor.submit(
                    lambda m, t: [r.to_dict() for r in m.scan(t, args.timeout, args.sample_size)],
                    module,
                    target
                )
                tasks.append(future)
                future_context[future] = (module.name, target.raw)

        completed = 0
        for future in as_completed(tasks):
            completed += 1
            module_name, target_raw = future_context[future]
            try:
                results = future.result()
            except Exception as exc:
                print(f"[!] {completed}/{len(tasks)} {module_name}:{target_raw} error: {exc}")
                continue

            if results:
                all_results.extend(results)
                print(f"[+] {completed}/{len(tasks)} {module_name}:{target_raw} findings={len(results)}")
            else:
                print(f"[-] {completed}/{len(tasks)} {module_name}:{target_raw} no findings")

    all_results.sort(key=lambda r: (-r["severity_score"], r.get("module", ""), r.get("url", "")))
    critical_results = [r for r in all_results if r["severity_score"] >= 30]

    with open(args.out_results, "w", encoding="utf-8") as f:
        f.write("# Modular Research Scanner Results\n")
        f.write(f"# Targets: {len(targets)}\n")
        f.write(f"# Modules: {', '.join(module.name for module in modules)}\n")
        f.write(f"# Findings: {len(all_results)}\n")
        f.write(f"# Critical findings: {len(critical_results)}\n")
        f.write("#" + "=" * 79 + "\n\n")
        for result in all_results:
            f.write(result_line(result) + "\n")

    with open(args.out_critical, "w", encoding="utf-8") as f:
        f.write("# Critical Findings\n")
        f.write(f"# Total critical: {len(critical_results)}\n")
        f.write("#" + "=" * 79 + "\n\n")
        for result in critical_results:
            f.write(result_line(result) + "\n")

    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    write_module_summaries(all_results, modules, args.out_module_dir)

    print_statistics(all_results, len(targets))
    print("\nOutput files:")
    print(f"  Results: {args.out_results}")
    print(f"  Critical: {args.out_critical}")
    print(f"  JSON: {args.out_json}")
    print(f"  Module summaries: {args.out_module_dir}")


if __name__ == "__main__":
    main()
