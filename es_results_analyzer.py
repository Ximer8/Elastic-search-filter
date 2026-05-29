#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Scanner Results Analyzer
Утилита для анализа и фильтрации результатов сканирования
"""

import argparse
import json
import sys
from collections import defaultdict
from typing import Dict, List


def load_results(json_path: str) -> List[Dict]:
    """Загружает результаты из JSON"""
    with open(json_path, "r", encoding="utf-8") as f:
        return json.load(f)


def filter_by_severity(results: List[Dict], min_score: int) -> List[Dict]:
    """Фильтрует по минимальному severity score"""
    return [r for r in results if r["severity_score"] >= min_score]


def filter_by_detection(results: List[Dict], detection_type: str) -> List[Dict]:
    """Фильтрует по типу детекции"""
    return [r for r in results if detection_type in r["detected_rules"]]


def filter_by_module(results: List[Dict], module_name: str) -> List[Dict]:
    """Фильтрует по модулю сканирования"""
    return [r for r in results if r.get("module", "elasticsearch") == module_name]


def group_by_cluster(results: List[Dict]) -> Dict[str, List[Dict]]:
    """Группирует по кластерам"""
    clusters = defaultdict(list)
    for r in results:
        cluster = r.get("cluster_name", "unknown")
        clusters[cluster].append(r)
    return dict(clusters)


def get_statistics(results: List[Dict]) -> Dict:
    """Собирает статистику"""
    stats = {
        "total": len(results),
        "by_severity": {
            "critical": len([r for r in results if r["severity_score"] >= 50]),
            "high": len([r for r in results if 30 <= r["severity_score"] < 50]),
            "medium": len([r for r in results if 10 <= r["severity_score"] < 30]),
            "low": len([r for r in results if r["severity_score"] < 10])
        },
        "detections": defaultdict(int),
        "ransomware_notes": 0,
        "modules": defaultdict(int),
        "module_critical": defaultdict(int),
        "environments": defaultdict(int),
        "environment_critical": defaultdict(int),
        "clusters": set(),
        "versions": defaultdict(int),
        "total_indices": 0,
        "avg_response_time": 0
    }
    
    for r in results:
        module_name = r.get("module", "elasticsearch")
        stats["modules"][module_name] += 1
        if r["severity_score"] >= 30:
            stats["module_critical"][module_name] += 1

        # Детекции
        for det in r["detected_rules"]:
            stats["detections"][det] += 1
            if det == "ransomware_note":
                stats["ransomware_notes"] += 1

        # Окружения
        environment = r.get("environment", "unknown") or "unknown"
        stats["environments"][environment] += 1
        if r["severity_score"] >= 30:
            stats["environment_critical"][environment] += 1
        
        # Кластеры
        if r.get("cluster_name"):
            stats["clusters"].add(r["cluster_name"])
        
        # Версии
        if r.get("version"):
            stats["versions"][r["version"]] += 1
        
        # Индексы
        stats["total_indices"] += r.get("indices_count", 0)
    
    # Средний response time
    if results:
        stats["avg_response_time"] = sum(r.get("response_time", 0) for r in results) / len(results)
    
    stats["clusters"] = len(stats["clusters"])
    stats["detections"] = dict(stats["detections"])
    stats["modules"] = dict(stats["modules"])
    stats["module_critical"] = dict(stats["module_critical"])
    stats["environments"] = dict(stats["environments"])
    stats["environment_critical"] = dict(stats["environment_critical"])
    stats["versions"] = dict(stats["versions"])
    
    return stats


def export_urls(results: List[Dict], output: str):
    """Экспортирует только URL"""
    with open(output, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"{r['url']}\n")


def export_detailed_csv(results: List[Dict], output: str):
    """Экспортирует детальный CSV"""
    import csv
    
    with open(output, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            "Module", "URL", "Host", "Port", "Scheme", "Cluster", "Version", 
            "Environment", "Env Confidence", "Indices", "Severity",
            "Priority", "FP Confidence", "Owner Contacts", "Ransomware Note",
            "Detections", "Response Time"
        ])
        
        for r in results:
            writer.writerow([
                r.get("module", "elasticsearch"),
                r["url"],
                r["host"],
                r["port"],
                r["scheme"],
                r.get("cluster_name", ""),
                r.get("version", ""),
                r.get("environment", "unknown"),
                r.get("environment_confidence", 0),
                r.get("indices_count", 0),
                r["severity_score"],
                r.get("notification_priority", ""),
                r.get("false_positive_confidence", ""),
                ",".join((r.get("owner") or {}).get("contacts", [])),
                "yes" if "ransomware_note" in r.get("detected_rules", []) else "no",
                ",".join(r["detected_rules"]),
                f"{r.get('response_time', 0):.2f}"
            ])


def print_statistics(stats: Dict):
    """Выводит статистику в консоль"""
    print("\n" + "=" * 80)
    print("📊 STATISTICS REPORT")
    print("=" * 80)
    
    print(f"\nTotal hosts: {stats['total']}")
    
    print("\n🎯 By Severity:")
    print(f"  🔴 Critical (≥50): {stats['by_severity']['critical']}")
    print(f"  🟠 High (30-49): {stats['by_severity']['high']}")
    print(f"  🟡 Medium (10-29): {stats['by_severity']['medium']}")
    print(f"  🟢 Low (<10): {stats['by_severity']['low']}")
    
    print(f"\n🔍 Top Detections:")
    for det, count in sorted(stats["detections"].items(), key=lambda x: -x[1])[:10]:
        print(f"  {det}: {count}")

    print(f"\n🧨 Ransomware note findings: {stats['ransomware_notes']}")

    print(f"\n🧩 Modules:")
    for module_name, count in sorted(stats["modules"].items(), key=lambda x: x[0]):
        critical = stats["module_critical"].get(module_name, 0)
        print(f"  {module_name}: {count} hosts ({critical} critical)")

    print(f"\n🏷️  Environment Split:")
    for env in ["production", "test", "unknown"]:
        total = stats["environments"].get(env, 0)
        critical = stats["environment_critical"].get(env, 0)
        print(f"  {env}: {total} hosts ({critical} critical)")
    
    print(f"\n🖥️  Unique clusters: {stats['clusters']}")
    
    if stats["versions"]:
        print(f"\n📦 Elasticsearch Versions:")
        for ver, count in sorted(stats["versions"].items(), key=lambda x: -x[1])[:10]:
            print(f"  {ver}: {count}")
    
    print(f"\n📊 Total indices: {stats['total_indices']}")
    print(f"⏱️  Avg response time: {stats['avg_response_time']:.2f}s")
    
    print("=" * 80 + "\n")


def generate_markdown_report(results: List[Dict], stats: Dict, output: str):
    """Генерирует Markdown отчет"""
    lines = []
    
    lines.append("# Modular Security Scan Report\n")
    lines.append(f"**Total Hosts Scanned:** {stats['total']}\n")
    lines.append(f"**Total Indices:** {stats['total_indices']}\n")
    lines.append(f"**Unique Clusters:** {stats['clusters']}\n\n")
    lines.append(f"**Ransomware Note Findings:** {stats['ransomware_notes']}\n\n")

    lines.append("## 🧩 Modules\n")
    lines.append("| Module | Hosts | Critical |")
    lines.append("|--------|-------|----------|")
    for module_name, count in sorted(stats["modules"].items(), key=lambda x: x[0]):
        lines.append(f"| {module_name} | {count} | {stats['module_critical'].get(module_name, 0)} |")
    lines.append("")
    
    lines.append("## 📊 Severity Distribution\n")
    lines.append("| Severity | Count | Percentage |")
    lines.append("|----------|-------|------------|")
    total = stats['total']
    for sev, count in stats['by_severity'].items():
        pct = (count / total * 100) if total > 0 else 0
        lines.append(f"| {sev.capitalize()} | {count} | {pct:.1f}% |")
    lines.append("")

    lines.append("## 🏷️ Environment Split\n")
    lines.append("| Environment | Hosts | Critical |")
    lines.append("|-------------|-------|----------|")
    for env in ["production", "test", "unknown"]:
        lines.append(
            f"| {env} | {stats['environments'].get(env, 0)} | "
            f"{stats['environment_critical'].get(env, 0)} |"
        )
    lines.append("")

    lines.append("## 🧨 Possible Ransomware Notes\n")
    ransomware = [r for r in results if "ransomware_note" in r.get("detected_rules", [])]
    if ransomware:
        lines.append("| Module | URL | Environment | Score | Cluster | Matched |")
        lines.append("|--------|-----|-------------|-------|---------|---------|")
        for r in sorted(ransomware, key=lambda x: -x["severity_score"])[:30]:
            matched = ", ".join(
                r.get("sample_data", {}).get("ransomware_note", {}).get("matched", [])[:5]
            )
            lines.append(
                f"| {r.get('module', 'elasticsearch')} | {r['url']} | {r.get('environment', 'unknown')} | "
                f"{r['severity_score']} | {r.get('cluster_name', '')} | {matched} |"
            )
    else:
        lines.append("*No ransomware notes detected*")
    lines.append("")

    lines.append("## Laravel Debug Findings\n")
    laravel_debug = [r for r in results if r.get("module") == "laravel_debug"]
    if laravel_debug:
        lines.append("| URL | Environment | Score | Priority | FP Confidence | Owner Contact | Detections |")
        lines.append("|-----|-------------|-------|----------|---------------|---------------|------------|")
        for r in sorted(laravel_debug, key=lambda x: -x["severity_score"])[:30]:
            owner_contacts = (r.get("owner") or {}).get("contacts", [])
            lines.append(
                f"| {r['url']} | {r.get('environment', 'unknown')} | {r['severity_score']} | "
                f"{r.get('notification_priority', '')} | {r.get('false_positive_confidence', '')} | "
                f"{owner_contacts[0] if owner_contacts else ''} | {', '.join(r.get('detected_rules', [])[:6])} |"
            )
    else:
        lines.append("*No Laravel debug findings*")
    lines.append("")
    
    lines.append("## 🔍 Top Detections\n")
    lines.append("| Detection | Count |")
    lines.append("|-----------|-------|")
    for det, count in sorted(stats["detections"].items(), key=lambda x: -x[1])[:15]:
        lines.append(f"| {det} | {count} |")
    lines.append("")
    
    lines.append("## 🔴 Critical Findings (Score ≥ 50)\n")
    critical = [r for r in results if r["severity_score"] >= 50]
    if critical:
        lines.append("| Module | URL | Score | Indices | Detections |")
        lines.append("|--------|-----|-------|---------|------------|")
        for r in sorted(critical, key=lambda x: -x["severity_score"])[:20]:
            dets = ", ".join(r["detected_rules"][:5])
            lines.append(
                f"| {r.get('module', 'elasticsearch')} | {r['url']} | "
                f"{r['severity_score']} | {r.get('indices_count', 0)} | {dets} |"
            )
    else:
        lines.append("*No critical findings*")
    lines.append("")
    
    lines.append("## 📦 Elasticsearch Versions\n")
    if stats["versions"]:
        lines.append("| Version | Count |")
        lines.append("|---------|-------|")
        for ver, count in sorted(stats["versions"].items(), key=lambda x: -x[1])[:10]:
            lines.append(f"| {ver} | {count} |")
    else:
        lines.append("*No Elasticsearch versions in this result set*")
    lines.append("")
    
    with open(output, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def main():
    ap = argparse.ArgumentParser(
        description="Анализ и фильтрация результатов модульного сканирования",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:

  # Показать статистику
  python3 es_results_analyzer.py -i es_results.json --stats

  # Фильтр по severity
  python3 es_results_analyzer.py -i es_results.json --min-score 50 -o critical_only.json

  # Фильтр по детекции
  python3 es_results_analyzer.py -i es_results.json --detection credentials -o creds_only.json

  # Экспорт только URL
  python3 es_results_analyzer.py -i es_results.json --export-urls targets.txt

  # Экспорт CSV
  python3 es_results_analyzer.py -i es_results.json --export-csv results.csv

  # Markdown отчет
  python3 es_results_analyzer.py -i es_results.json --markdown-report report.md
        """
    )
    
    ap.add_argument("-i", "--input", required=True, help="JSON файл с результатами")
    ap.add_argument("-o", "--output", help="Выходной JSON файл (после фильтрации)")
    
    # Фильтры
    ap.add_argument("--min-score", type=int, help="Минимальный severity score")
    ap.add_argument("--detection", help="Фильтр по типу детекции")
    ap.add_argument("--module", help="Фильтр по модулю сканирования")
    
    # Экспорт
    ap.add_argument("--export-urls", help="Экспорт только URL в файл")
    ap.add_argument("--export-csv", help="Экспорт в CSV")
    ap.add_argument("--markdown-report", help="Генерация Markdown отчета")
    
    # Статистика
    ap.add_argument("--stats", action="store_true", help="Показать статистику")
    
    args = ap.parse_args()
    
    # Загружаем результаты
    print(f"[*] Loading results from {args.input}")
    results = load_results(args.input)
    print(f"[*] Loaded {len(results)} results")
    
    # Применяем фильтры
    filtered = results
    
    if args.min_score is not None:
        filtered = filter_by_severity(filtered, args.min_score)
        print(f"[*] After severity filter (>={args.min_score}): {len(filtered)} results")
    
    if args.detection:
        filtered = filter_by_detection(filtered, args.detection)
        print(f"[*] After detection filter ('{args.detection}'): {len(filtered)} results")

    if args.module:
        filtered = filter_by_module(filtered, args.module)
        print(f"[*] After module filter ('{args.module}'): {len(filtered)} results")
    
    # Статистика
    if args.stats or not any([args.output, args.export_urls, args.export_csv, args.markdown_report]):
        stats = get_statistics(filtered)
        print_statistics(stats)
    
    # Сохраняем отфильтрованные результаты
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(filtered, f, indent=2, ensure_ascii=False)
        print(f"[+] Saved filtered results to {args.output}")
    
    # Экспорт URL
    if args.export_urls:
        export_urls(filtered, args.export_urls)
        print(f"[+] Exported URLs to {args.export_urls}")
    
    # Экспорт CSV
    if args.export_csv:
        export_detailed_csv(filtered, args.export_csv)
        print(f"[+] Exported CSV to {args.export_csv}")
    
    # Markdown отчет
    if args.markdown_report:
        stats = get_statistics(filtered)
        generate_markdown_report(filtered, stats, args.markdown_report)
        print(f"[+] Generated Markdown report: {args.markdown_report}")


if __name__ == "__main__":
    main()
