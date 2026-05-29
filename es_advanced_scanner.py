#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Elasticsearch Security Scanner
Поддержка множества портов, детекция критичных данных, scoring system
"""

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()

# ============================================================================
# КОНСТАНТЫ И РЕГУЛЯРКИ
# ============================================================================

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
URL_RE = re.compile(r"https?://[^\s,\"'<>]+", re.IGNORECASE)
IP_PORT_RE = re.compile(
    r"\b((?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)):(\d{1,5})\b"
)

UA = "es-security-scanner/2.0"
COMMON_PORTS = [9200, 9300, 9201, 9202, 5601, 8080, 443, 80]


# ============================================================================
# КРИТЕРИИ ДЕТЕКЦИИ (основаны на ваших фильтрах)
# ============================================================================

@dataclass
class DetectionRule:
    """Правило детекции критичных данных"""
    name: str
    category: str
    keywords: List[str]
    severity: int  # 1-10, где 10 = критично
    description: str


RANSOMWARE_NOTE_KEYWORDS = [
    "ransom", "ransomware", "your files are encrypted", "all your files",
    "all your data", "decrypt", "decryption", "decryptor", "restore your files",
    "recover your files", "recover your data", "pay ransom", "tor browser",
    ".onion", "read_me", "read-me", "how_to_decrypt", "how-to-decrypt",
    "help_decrypt", "decrypt_instructions", "encrypted by"
]

TEST_ENV_KEYWORDS = [
    "test", "testing", "dev", "development", "stage", "staging", "qa", "uat",
    "sandbox", "demo", "local", "nonprod", "non-prod", "preprod", "pre-prod",
    "trial", "sample", "mock", "fixture"
]

PROD_ENV_KEYWORDS = [
    "prod", "production", "live", "customer", "customers", "client", "tenant",
    "account", "billing", "payment", "order", "orders", "invoice", "user",
    "users", "support", "ticket", "subscription", "crm"
]

EXPLICIT_PROD_ENV_KEYWORDS = {"prod", "production", "live"}


DETECTION_RULES = [
    DetectionRule(
        name="credentials",
        category="🔴 CRITICAL",
        keywords=["api_key", "apikey", "api-key", "secret", "token", "authorization", "bearer", "access_token"],
        severity=10,
        description="API keys, secrets, tokens"
    ),
    DetectionRule(
        name="ransomware_note",
        category="🔴 CRITICAL",
        keywords=RANSOMWARE_NOTE_KEYWORDS,
        severity=10,
        description="Possible ransomware note or recovery/payment instructions"
    ),
    DetectionRule(
        name="passwords",
        category="🔴 CRITICAL",
        keywords=["password", "passwd", "pwd", "hash", "bcrypt", "argon2", "sha256", "md5"],
        severity=10,
        description="Passwords and hashes"
    ),
    DetectionRule(
        name="pii",
        category="🔴 CRITICAL",
        keywords=["email", "@gmail.com", "@outlook.com", "user_id", "phone", "address", 
                 "first_name", "last_name", "full_name", "dob", "birth", "ssn", "passport"],
        severity=9,
        description="Personal Identifiable Information"
    ),
    DetectionRule(
        name="medical",
        category="🔴 CRITICAL",
        keywords=["medical", "health", "diagnosis", "patient", "clinic", "doctor", "hospital"],
        severity=10,
        description="Medical/Health data (HIPAA)"
    ),
    DetectionRule(
        name="financial",
        category="🔴 CRITICAL",
        keywords=["payment", "billing", "invoice", "transaction", "card_number", "cvv", 
                 "stripe", "paypal", "iban", "swift", "amount", "currency"],
        severity=9,
        description="Financial/Payment data"
    ),
    DetectionRule(
        name="support_chats",
        category="🟠 HIGH",
        keywords=["chat", "conversation", "message", "ticket", "agent", "requester", 
                 "conversation_id", "thread_id", "sender", "receiver"],
        severity=8,
        description="Support conversations"
    ),
    DetectionRule(
        name="internal_notes",
        category="🟠 HIGH",
        keywords=["internal", "internal_note", "agent_note", "private_note", "staff", 
                 "visible_to_customer", "internal_only", "confidential"],
        severity=8,
        description="Internal/private notes"
    ),
    DetectionRule(
        name="production",
        category="🟠 HIGH",
        keywords=["prod", "production", "live", "customer", "customers", "account_id", 
                 "customer_id", "subscription", "tenant", "organization_id"],
        severity=7,
        description="Production environment"
    ),
    DetectionRule(
        name="cloud_metadata",
        category="🟠 HIGH",
        keywords=["aws", "s3", "gcp", "azure", "bucket", "instance_id", "project_id", 
                 "region", "vpc", "iam"],
        severity=7,
        description="Cloud infrastructure metadata"
    ),
    DetectionRule(
        name="corporate",
        category="🟡 MEDIUM",
        keywords=["@company.com", "Inc", "LLC", "Ltd", "@corp.com", "enterprise", 
                 "premium", "contract", "sla", "account_manager"],
        severity=6,
        description="Corporate/Enterprise data"
    ),
    DetectionRule(
        name="backups",
        category="🟡 MEDIUM",
        keywords=["backup", "dump", "snapshot", "export", "restore", "archive"],
        severity=7,
        description="Backup/dump files"
    ),
    DetectionRule(
        name="cicd",
        category="🟡 MEDIUM",
        keywords=["jenkins", "gitlab", "github", "pipeline", "ci", "cd", "deploy", 
                 "kubernetes", "k8s", "docker"],
        severity=6,
        description="CI/CD and DevOps"
    ),
    DetectionRule(
        name="auth_logs",
        category="🟡 MEDIUM",
        keywords=["auth", "authentication", "login", "signin", "logout", "failed_login", 
                 "2fa", "otp", "mfa"],
        severity=7,
        description="Authentication logs"
    ),
]


# ============================================================================
# СТРУКТУРЫ ДАННЫХ
# ============================================================================

@dataclass
class ScanResult:
    """Результат сканирования одного хоста"""
    host: str
    port: int
    scheme: str
    accessible: bool
    indices_count: int = 0
    cluster_name: str = ""
    version: str = ""
    detected_rules: List[str] = field(default_factory=list)
    severity_score: int = 0
    sample_data: Dict = field(default_factory=dict)
    environment: str = "unknown"
    environment_confidence: int = 0
    environment_signals: List[str] = field(default_factory=list)
    error: str = ""
    response_time: float = 0.0


# ============================================================================
# ИЗВЛЕЧЕНИЕ ЦЕЛЕЙ ИЗ CSV
# ============================================================================

def extract_targets_from_csv(path: str, delimiter: str = ",") -> List[Tuple[str, Optional[int]]]:
    """
    Извлекает IP/хосты и порты из CSV.
    Ищет в колонке 'link' или во всех колонках.
    Возвращает [(host, port), ...]
    """
    targets = []
    seen = set()
    
    with open(path, "r", encoding="utf-8", errors="ignore", newline="") as f:
        reader = csv.DictReader(f, delimiter=delimiter)
        
        # Если нет заголовков, читаем как обычный CSV
        if reader.fieldnames is None:
            f.seek(0)
            reader = csv.reader(f, delimiter=delimiter)
            rows = list(reader)
        else:
            rows = list(reader)
        
        for row in rows:
            if isinstance(row, dict):
                # DictReader
                text = " ".join(str(v) for v in row.values())
            else:
                # обычный reader
                text = " ".join(row)

            text_without_urls = URL_RE.sub(" ", text)
            
            # Ищем URL
            for url in URL_RE.findall(text):
                try:
                    parsed = urlparse(url)
                    host = parsed.hostname or parsed.netloc
                    port = parsed.port
                    
                    if host:
                        key = (host, port)
                        if key not in seen:
                            seen.add(key)
                            targets.append(key)
                except:
                    pass

            # Ищем IP:port без схемы
            for ip, port_text in IP_PORT_RE.findall(text_without_urls):
                try:
                    port = int(port_text)
                except ValueError:
                    continue

                if not 1 <= port <= 65535:
                    continue

                key = (ip, port)
                if key not in seen:
                    seen.add(key)
                    targets.append(key)
            
            # Ищем IP адреса
            text_without_ip_ports = IP_PORT_RE.sub(" ", text_without_urls)
            for ip in IP_RE.findall(text_without_ip_ports):
                key = (ip, None)
                if key not in seen:
                    seen.add(key)
                    targets.append(key)
    
    return targets


# ============================================================================
# АНАЛИЗ СОДЕРЖИМОГО
# ============================================================================

def analyze_content(text: str, json_data: Optional[Dict] = None) -> Tuple[List[str], int, Dict]:
    """
    Анализирует контент на наличие критичных данных.
    Возвращает (detected_rules, severity_score, sample_data)
    """
    detected = []
    severity_score = 0
    sample_data = {}
    
    # Анализируем текст и JSON
    search_text = text.lower()
    if json_data:
        search_text += " " + json.dumps(json_data).lower()
    
    for rule in DETECTION_RULES:
        matched_keywords = []
        for keyword in rule.keywords:
            if keyword.lower() in search_text:
                matched_keywords.append(keyword)
        
        if matched_keywords:
            detected.append(rule.name)
            severity_score += rule.severity
            sample_data[rule.name] = {
                "category": rule.category,
                "description": rule.description,
                "matched": matched_keywords[:5],  # первые 5 совпадений
                "severity": rule.severity
            }
    
    return detected, severity_score, sample_data


def env_keyword_matches(text: str, keyword: str) -> bool:
    """Ищет env-keyword как отдельный токен, чтобы prod/dev не матчились в product/device."""
    if len(keyword) <= 4 or "-" in keyword:
        pattern = r"(?<![a-z0-9])" + re.escape(keyword) + r"(?![a-z0-9])"
        return re.search(pattern, text) is not None
    return keyword in text


def classify_environment(text: str, cluster_name: str = "", index_names: Optional[List[str]] = None) -> Tuple[str, int, List[str]]:
    """
    Классифицирует Elasticsearch как production/test/unknown по именам кластера,
    индексов и собранному контенту. Сигналы из имени кластера и индексов имеют
    больший вес, потому что они обычно отражают назначение инстанса лучше sample.
    """
    signals = []
    prod_score = 0
    test_score = 0
    explicit_prod_signal = False
    explicit_test_signal = False

    sources = []
    if cluster_name:
        sources.append(("cluster", cluster_name, 3))
    for index_name in index_names or []:
        sources.append(("index", index_name, 2))
    if text:
        sources.append(("content", text[:200000], 1))

    for source_name, value, weight in sources:
        value_lower = value.lower()
        for keyword in TEST_ENV_KEYWORDS:
            if env_keyword_matches(value_lower, keyword):
                test_score += weight
                if source_name in {"cluster", "index"}:
                    explicit_test_signal = True
                if len(signals) < 12:
                    signals.append(f"{source_name}:{keyword}")
        for keyword in PROD_ENV_KEYWORDS:
            if env_keyword_matches(value_lower, keyword):
                prod_score += weight
                if source_name in {"cluster", "index"} and keyword in EXPLICIT_PROD_ENV_KEYWORDS:
                    explicit_prod_signal = True
                if len(signals) < 12:
                    signals.append(f"{source_name}:{keyword}")

    if prod_score == 0 and test_score == 0:
        return "unknown", 0, signals

    total = prod_score + test_score
    if explicit_test_signal and not explicit_prod_signal:
        return "test", int(test_score / total * 100), signals
    if explicit_prod_signal and not explicit_test_signal:
        return "production", int(prod_score / total * 100), signals

    if test_score > prod_score or (test_score == prod_score and explicit_test_signal and not explicit_prod_signal):
        return "test", int(test_score / total * 100), signals
    if prod_score > test_score or (prod_score == test_score and explicit_prod_signal and not explicit_test_signal):
        return "production", int(prod_score / total * 100), signals

    return "unknown", 50, signals


def parse_cat_indices(text: str) -> Optional[int]:
    """Парсит _cat/indices?v и возвращает количество индексов"""
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if not lines:
        return None
    
    header = lines[0].lower()
    if "health" in header and "status" in header and "index" in header:
        return max(0, len(lines) - 1)
    
    return None


def parse_cat_indices_json(data: List[Dict]) -> Tuple[int, List[str]]:
    """Парсит _cat/indices?format=json и возвращает количество и имена индексов"""
    index_names = []
    for item in data:
        index_name = item.get("index")
        if index_name:
            index_names.append(index_name)
    return len(index_names), index_names


def extract_cluster_info(data: Dict) -> Tuple[str, str]:
    """Извлекает имя кластера и версию из JSON ответа"""
    cluster_name = data.get("cluster_name", "")
    version = ""
    if "version" in data:
        version = data["version"].get("number", "")
    return cluster_name, version


# ============================================================================
# СКАНИРОВАНИЕ
# ============================================================================

def scan_elasticsearch(host: str, port: Optional[int], timeout: int, max_sample_size: int = 500) -> List[ScanResult]:
    """
    Сканирует Elasticsearch на указанном хосте и порту (или нескольких портах).
    Возвращает список результатов.
    """
    results = []
    
    # Определяем порты для проверки
    ports_to_check = []
    if port:
        ports_to_check = [port]
    else:
        ports_to_check = COMMON_PORTS
    
    for check_port in ports_to_check:
        result = scan_single_port(host, check_port, timeout, max_sample_size)
        if result:
            results.append(result)
    
    return results


def scan_single_port(host: str, port: int, timeout: int, max_sample_size: int) -> Optional[ScanResult]:
    """Сканирует один порт"""
    import time
    
    headers = {"User-Agent": UA, "Accept": "application/json, text/plain, */*"}
    
    schemes = ["http", "https"]
    
    for scheme in schemes:
        try:
            start_time = time.time()
            
            # 1. Проверяем корень /
            root_url = f"{scheme}://{host}:{port}/"
            r = requests.get(root_url, timeout=timeout, headers=headers, verify=False, allow_redirects=True)
            
            if r.status_code != 200:
                continue
            
            response_time = time.time() - start_time
            
            # Парсим JSON если возможно
            json_data = None
            try:
                json_data = r.json()
            except:
                pass
            
            # Проверяем что это Elasticsearch
            if not json_data or "tagline" not in json_data:
                continue
            
            # Это Elasticsearch!
            cluster_name, version = extract_cluster_info(json_data)
            
            result = ScanResult(
                host=host,
                port=port,
                scheme=scheme,
                accessible=True,
                cluster_name=cluster_name,
                version=version,
                response_time=response_time
            )
            
            # 2. Проверяем _cat/indices
            indices_count, index_names = get_indices_metadata(scheme, host, port, timeout, headers)
            result.indices_count = indices_count or 0
            
            # 3. Собираем sample данных из нескольких источников
            all_content = r.text
            all_json = json_data or {}
            
            # Пробуем _search
            search_data = get_search_sample(scheme, host, port, timeout, headers, max_sample_size)
            if search_data:
                all_content += " " + json.dumps(search_data)
                all_json.update(search_data)
            
            # Пробуем _cluster/health
            cluster_data = get_cluster_health(scheme, host, port, timeout, headers)
            if cluster_data:
                all_content += " " + json.dumps(cluster_data)
            
            # Пробуем _cluster/state
            state_data = get_cluster_state(scheme, host, port, timeout, headers)
            if state_data:
                all_content += " " + json.dumps(state_data)
            
            # Анализируем весь собранный контент
            detected, severity, sample_data = analyze_content(all_content, all_json)
            environment, env_confidence, env_signals = classify_environment(
                all_content,
                cluster_name=cluster_name,
                index_names=index_names
            )
            
            result.detected_rules = detected
            result.severity_score = severity
            result.sample_data = sample_data
            result.environment = environment
            result.environment_confidence = env_confidence
            result.environment_signals = env_signals
            
            return result
            
        except RequestException as e:
            continue
        except Exception as e:
            continue
    
    return None


def get_indices_metadata(scheme: str, host: str, port: int, timeout: int, headers: Dict) -> Tuple[Optional[int], List[str]]:
    """Получает количество и имена индексов"""
    try:
        url = f"{scheme}://{host}:{port}/_cat/indices"
        r = requests.get(url, timeout=timeout, headers=headers, params={"format": "json"}, verify=False)
        if r.status_code == 200:
            return parse_cat_indices_json(r.json())
    except:
        pass

    return check_cat_indices(scheme, host, port, timeout, headers), []


def check_cat_indices(scheme: str, host: str, port: int, timeout: int, headers: Dict) -> Optional[int]:
    """Проверяет _cat/indices"""
    try:
        url = f"{scheme}://{host}:{port}/_cat/indices?v"
        r = requests.get(url, timeout=timeout, headers=headers, verify=False)
        if r.status_code == 200:
            return parse_cat_indices(r.text)
    except:
        pass
    return None


def get_search_sample(scheme: str, host: str, port: int, timeout: int, headers: Dict, max_size: int) -> Optional[Dict]:
    """Получает sample данных через _search"""
    try:
        url = f"{scheme}://{host}:{port}/_search"
        params = {"size": min(max_size, 100)}
        r = requests.get(url, timeout=timeout, headers=headers, params=params, verify=False)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def get_cluster_health(scheme: str, host: str, port: int, timeout: int, headers: Dict) -> Optional[Dict]:
    """Получает _cluster/health"""
    try:
        url = f"{scheme}://{host}:{port}/_cluster/health"
        r = requests.get(url, timeout=timeout, headers=headers, verify=False)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None


def get_cluster_state(scheme: str, host: str, port: int, timeout: int, headers: Dict) -> Optional[Dict]:
    """Получает _cluster/state (может быть большой!)"""
    try:
        url = f"{scheme}://{host}:{port}/_cluster/state"
        r = requests.get(url, timeout=timeout, headers=headers, verify=False)
        if r.status_code == 200 and len(r.content) < 1024 * 1024:  # макс 1MB
            return r.json()
    except:
        pass
    return None


# ============================================================================
# ФОРМАТИРОВАНИЕ ВЫВОДА
# ============================================================================

def format_result_line(result: ScanResult) -> str:
    """Форматирует одну строку результата"""
    severity_emoji = "🔴" if result.severity_score >= 50 else "🟠" if result.severity_score >= 30 else "🟡" if result.severity_score >= 10 else "🟢"
    
    parts = [
        f"{result.scheme}://{result.host}:{result.port}",
        f"indices={result.indices_count}",
        f"score={result.severity_score}",
        f"{severity_emoji}"
    ]
    
    if result.cluster_name:
        parts.append(f"cluster={result.cluster_name}")
    
    if result.version:
        parts.append(f"ver={result.version}")

    parts.append(f"env={result.environment}")
    
    if result.detected_rules:
        parts.append(f"detected={','.join(result.detected_rules)}")
    
    return "\t".join(parts)


def create_detailed_report(result: ScanResult) -> str:
    """Создает детальный отчет по одному хосту"""
    lines = []
    lines.append("=" * 80)
    lines.append(f"HOST: {result.scheme}://{result.host}:{result.port}")
    lines.append(f"Cluster: {result.cluster_name or 'N/A'}")
    lines.append(f"Version: {result.version or 'N/A'}")
    lines.append(f"Environment: {result.environment} ({result.environment_confidence}% confidence)")
    if result.environment_signals:
        lines.append(f"Environment Signals: {', '.join(result.environment_signals[:10])}")
    lines.append(f"Indices: {result.indices_count}")
    lines.append(f"Severity Score: {result.severity_score}")
    lines.append(f"Response Time: {result.response_time:.2f}s")
    lines.append("")
    
    if result.detected_rules:
        lines.append("DETECTED ISSUES:")
        for rule_name in result.detected_rules:
            if rule_name in result.sample_data:
                info = result.sample_data[rule_name]
                lines.append(f"  {info['category']} {rule_name.upper()}")
                lines.append(f"    Description: {info['description']}")
                lines.append(f"    Severity: {info['severity']}/10")
                lines.append(f"    Matched keywords: {', '.join(info['matched'])}")
                lines.append("")
    else:
        lines.append("No critical data detected")
    
    lines.append("=" * 80)
    lines.append("")
    
    return "\n".join(lines)


# ============================================================================
# MAIN
# ============================================================================

def main():
    ap = argparse.ArgumentParser(
        description="Advanced Elasticsearch Security Scanner - проверяет доступность и детектирует критичные данные",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    ap.add_argument("-i", "--input", required=True, help="CSV файл с хостами/URL")
    ap.add_argument("--delimiter", default=",", help="CSV разделитель (по умолчанию: ,)")
    ap.add_argument("-w", "--workers", type=int, default=30, help="Количество потоков (по умолчанию: 30)")
    ap.add_argument("-t", "--timeout", type=int, default=10, help="Таймаут запроса в секундах (по умолчанию: 10)")
    ap.add_argument("--sample-size", type=int, default=500, help="Размер sample для анализа (по умолчанию: 500)")
    
    ap.add_argument("--out-results", default="es_results.txt", help="Файл с результатами")
    ap.add_argument("--out-critical", default="es_critical.txt", help="Файл с критичными находками")
    ap.add_argument("--out-detailed", default="es_detailed_report.txt", help="Детальный отчет")
    ap.add_argument("--out-json", default="es_results.json", help="JSON с полными данными")
    
    args = ap.parse_args()
    
    # Извлекаем цели
    print("[*] Извлекаем цели из CSV...")
    targets = extract_targets_from_csv(args.input, delimiter=args.delimiter)
    
    if not targets:
        print("[!] Не найдено целей в CSV", file=sys.stderr)
        sys.exit(1)
    
    print(f"[*] Найдено {len(targets)} уникальных целей")
    print(f"[*] Запуск сканирования с {args.workers} потоками...")
    
    all_results = []
    
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = {
            ex.submit(scan_elasticsearch, host, port, args.timeout, args.sample_size): (host, port)
            for host, port in targets
        }
        
        completed = 0
        for fut in as_completed(futures):
            completed += 1
            host, port = futures[fut]
            
            try:
                results = fut.result()
                if results:
                    all_results.extend(results)
                    print(f"[+] {completed}/{len(targets)} - {host}:{port or 'multi'} - Found {len(results)} accessible port(s)")
                else:
                    print(f"[-] {completed}/{len(targets)} - {host}:{port or 'multi'} - Not accessible")
            except Exception as e:
                print(f"[!] {completed}/{len(targets)} - {host}:{port or 'multi'} - Error: {e}")
    
    # Сортируем по severity score (от большего к меньшему)
    all_results.sort(key=lambda x: (-x.severity_score, -x.indices_count, x.host))
    
    print(f"\n[*] Сканирование завершено. Найдено доступных хостов: {len(all_results)}")
    
    # Записываем результаты
    critical_results = [r for r in all_results if r.severity_score >= 30]
    ransomware_results = [r for r in all_results if "ransomware_note" in r.detected_rules]
    production_results = [r for r in all_results if r.environment == "production"]
    test_results = [r for r in all_results if r.environment == "test"]
    unknown_env_results = [r for r in all_results if r.environment == "unknown"]
    
    # 1. Основной файл результатов
    with open(args.out_results, "w", encoding="utf-8") as f:
        f.write("# Elasticsearch Security Scan Results\n")
        f.write(f"# Total hosts scanned: {len(targets)}\n")
        f.write(f"# Accessible hosts: {len(all_results)}\n")
        f.write(f"# Critical findings: {len(critical_results)}\n")
        f.write(f"# Ransomware note findings: {len(ransomware_results)}\n")
        f.write(f"# Production/Test/Unknown: {len(production_results)}/{len(test_results)}/{len(unknown_env_results)}\n")
        f.write("#\n")
        f.write("# Format: URL | Indices | Score | Severity | Details\n")
        f.write("#" + "=" * 79 + "\n\n")
        
        for result in all_results:
            f.write(format_result_line(result) + "\n")
    
    # 2. Критичные находки
    with open(args.out_critical, "w", encoding="utf-8") as f:
        f.write("# 🔴 CRITICAL ELASTICSEARCH FINDINGS 🔴\n")
        f.write(f"# Total critical: {len(critical_results)}\n")
        f.write("#" + "=" * 79 + "\n\n")
        
        for result in critical_results:
            f.write(format_result_line(result) + "\n")
    
    # 3. Детальный отчет
    with open(args.out_detailed, "w", encoding="utf-8") as f:
        f.write("ELASTICSEARCH SECURITY DETAILED REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        for result in all_results:
            if result.detected_rules:  # только те, где что-то найдено
                f.write(create_detailed_report(result))
    
    # 4. JSON для дальнейшей обработки
    json_data = []
    for result in all_results:
        json_data.append({
            "url": f"{result.scheme}://{result.host}:{result.port}",
            "host": result.host,
            "port": result.port,
            "scheme": result.scheme,
            "cluster_name": result.cluster_name,
            "version": result.version,
            "indices_count": result.indices_count,
            "severity_score": result.severity_score,
            "detected_rules": result.detected_rules,
            "sample_data": result.sample_data,
            "environment": result.environment,
            "environment_confidence": result.environment_confidence,
            "environment_signals": result.environment_signals,
            "response_time": result.response_time
        })
    
    with open(args.out_json, "w", encoding="utf-8") as f:
        json.dump(json_data, f, indent=2, ensure_ascii=False)
    
    # Статистика
    print("\n" + "=" * 80)
    print("СТАТИСТИКА СКАНИРОВАНИЯ:")
    print("=" * 80)
    print(f"Всего просканировано целей: {len(targets)}")
    print(f"Доступных Elasticsearch хостов: {len(all_results)}")
    print(f"🔴 Критичных находок (score >= 30): {len(critical_results)}")
    print(f"🧨 Возможных ransomware записок: {len(ransomware_results)}")
    print(f"🟠 Средних находок (score 10-29): {len([r for r in all_results if 10 <= r.severity_score < 30])}")
    print(f"🟢 Низких находок (score < 10): {len([r for r in all_results if r.severity_score < 10])}")

    print("\nРАЗДЕЛЕНИЕ ПО ОКРУЖЕНИЯМ:")
    print(f"  production: {len(production_results)}")
    print(f"  test-like: {len(test_results)}")
    print(f"  unknown: {len(unknown_env_results)}")
    print(f"  production critical: {len([r for r in production_results if r.severity_score >= 30])}")
    print(f"  test-like critical: {len([r for r in test_results if r.severity_score >= 30])}")
    
    # Топ детекций
    detection_stats = defaultdict(int)
    for result in all_results:
        for rule in result.detected_rules:
            detection_stats[rule] += 1
    
    if detection_stats:
        print("\nТОП ДЕТЕКЦИЙ:")
        for rule, count in sorted(detection_stats.items(), key=lambda x: -x[1])[:10]:
            rule_info = next((r for r in DETECTION_RULES if r.name == rule), None)
            if rule_info:
                print(f"  {rule_info.category} {rule}: {count} хостов")
    
    print("\nФАЙЛЫ РЕЗУЛЬТАТОВ:")
    print(f"  📄 Основные результаты: {args.out_results}")
    print(f"  🔴 Критичные находки: {args.out_critical}")
    print(f"  📋 Детальный отчет: {args.out_detailed}")
    print(f"  📊 JSON данные: {args.out_json}")
    print("=" * 80)


if __name__ == "__main__":
    main()
