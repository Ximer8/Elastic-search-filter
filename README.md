# Modular Research Scanner

Инструмент для авторизованного security research: массовая проверка целей,
отсев ложнопозитивных результатов, риск-скоринг и подготовка данных для
ответственного уведомления владельца системы.

Проект начинался как Elasticsearch scanner, но теперь имеет модульный
интерфейс. Старые Elasticsearch entrypoint-ы сохранены для совместимости.

## Возможности

- Модульный запуск проверок через `scanner.py`
- Модули: `elasticsearch`, `laravel_debug`
- Legacy Elasticsearch scanner с мультипортовой проверкой
- Детекция чувствительных данных: credentials, passwords, PII, medical,
  financial, backups, CI/CD, auth logs
- Детекция возможных ransomware записок в Elasticsearch
- Классификация окружения: `production`, `test`, `unknown`
- JSON, TXT, CSV и Markdown отчеты
- Analyzer для фильтрации по severity, detection и module
- Deep Inspector для детального анализа конкретного Elasticsearch host

## Структура

```text
.
├── scanner.py                 # Новый модульный entrypoint
├── modules/
│   ├── base.py                # ScanTarget, ModuleResult, ScannerModule
│   ├── registry.py            # Регистрация доступных модулей
│   ├── elasticsearch.py       # Elasticsearch adapter module
│   └── laravel_debug.py       # Laravel debug exposure module
├── es_advanced_scanner.py     # Legacy Elasticsearch scanner
├── es_results_analyzer.py     # Analyzer для JSON результатов
├── es_deep_inspector.py       # Deep inspection одного Elasticsearch host
├── scan.sh                    # Legacy удобный launcher
└── automated_pipeline.sh      # Legacy automated ES workflow
```

## Установка

Нужен Python 3 и `requests`.

```bash
pip install requests --break-system-packages
```

Если окружение не разрешает `--break-system-packages`, используйте virtualenv.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

## Быстрый старт

### Модульный запуск

```bash
python3 scanner.py -i targets.csv --modules elasticsearch,laravel_debug
```

Параметры:

```bash
python3 scanner.py \
  -i targets.csv \
  --modules elasticsearch,laravel_debug \
  -w 50 \
  -t 12 \
  --sample-size 500 \
  --out-results scan_results.txt \
  --out-critical critical_findings.txt \
  --out-json scan_results.json \
  --out-module-dir module_summaries
```

Доступные модули:

```bash
python3 scanner.py --help
```

Сейчас зарегистрированы модули:

```text
elasticsearch
laravel_debug
```

Laravel debug отдельно:

```bash
python3 scanner.py -i urls.csv --modules laravel_debug
```

### Legacy Elasticsearch запуск

Старый scanner оставлен без изменения основного CLI:

```bash
python3 es_advanced_scanner.py -i targets.csv
```

Расширенный запуск:

```bash
python3 es_advanced_scanner.py \
  -i targets.csv \
  --delimiter "," \
  -w 50 \
  -t 15 \
  --sample-size 1000 \
  --out-results es_results.txt \
  --out-critical es_critical.txt \
  --out-detailed es_detailed_report.txt \
  --out-json es_results.json
```

## Формат входного CSV

Scanner ищет URL, `IP:port` и IP во всех колонках CSV.

Простой список IP:

```csv
192.168.1.100
10.0.0.50
172.16.0.20
```

IP с портами:

```csv
192.168.1.100:9200
10.0.0.50:9300
172.16.0.20:443
```

Полные URL:

```csv
http://192.168.1.100:9200
https://elastic.example.com:9200
http://10.0.0.50:9300
```

CSV из Shodan/Censys:

```csv
ip,port,link
192.168.1.100,9200,http://192.168.1.100:9200
10.0.0.50,9300,http://10.0.0.50:9300
```

## Результаты

Модульный JSON содержит общий формат для всех будущих модулей:

```json
{
  "module": "elasticsearch",
  "url": "http://127.0.0.1:9200",
  "host": "127.0.0.1",
  "port": 9200,
  "scheme": "http",
  "accessible": true,
  "severity_score": 36,
  "detected_rules": ["credentials", "ransomware_note", "pii", "production"],
  "environment": "production",
  "environment_confidence": 100,
  "environment_signals": ["cluster:prod", "index:orders"],
  "cluster_name": "prod-customer-es",
  "version": "8.12.0",
  "indices_count": 2
}
```

TXT output:

```text
elasticsearch	http://127.0.0.1:9200	score=36	🟠	env=production	cluster=prod-customer-es	ver=8.12.0	indices=2	detected=credentials,ransomware_note,pii,production
```

Per-module summaries:

```text
module_summaries/
├── elasticsearch_summary.txt
└── laravel_debug_summary.txt
```

Эти файлы короткие, но содержат все важное для быстрого ручного просмотра:

- URL
- score
- environment
- priority
- false-positive confidence
- detections
- owner contacts
- evidence
- matched keywords
- checked paths/status codes

## Severity

Severity считается суммой сработавших правил.

- `>= 50`: critical
- `30-49`: high
- `10-29`: medium
- `< 10`: low

В legacy scanner критичными для отдельного файла считаются результаты
`score >= 30`. Это сохранено для совместимости.

## Elasticsearch module

Модуль проверяет:

- HTTP и HTTPS
- стандартные Elasticsearch порты: `9200`, `9300`, `9201`, `9202`, `5601`,
  `8080`, `443`, `80`
- root endpoint на Elasticsearch tagline
- `_cat/indices`
- `_search` sample
- `_cluster/health`
- `_cluster/state`, если ответ меньше 1 MB

Детекции:

- `credentials`
- `ransomware_note`
- `passwords`
- `pii`
- `medical`
- `financial`
- `support_chats`
- `internal_notes`
- `production`
- `cloud_metadata`
- `corporate`
- `backups`
- `cicd`
- `auth_logs`

### Ransomware notes

Ищутся признаки записок и инструкций вроде:

- `your files are encrypted`
- `how_to_decrypt`
- `help_decrypt`
- `tor browser`
- `.onion`
- `ransomware`
- `encrypted by`

Словарь специально не включает слишком общие слова вроде `readme`, `wallet`,
`bitcoin`, чтобы не раздувать false positives.

### Environment split

Каждый результат получает:

- `environment`: `production`, `test`, `unknown`
- `environment_confidence`: 0-100
- `environment_signals`: найденные сигналы

Сигналы берутся из:

- имени кластера
- имен индексов
- sample-контента

Явные `qa`, `test`, `dev`, `staging` в cluster/index имеют приоритет над
непрямыми business-сигналами из документов.

## Laravel debug module

Модуль `laravel_debug` ищет exposed Laravel debug/exception pages и снижает
риск ложнопозитивных результатов. Он не эксплуатирует приложение: делает
обычные GET запросы на `/` и безопасный случайный 404-path, чтобы проверить,
не отдается ли debug stack trace.

Запуск:

```bash
python3 scanner.py -i urls.csv --modules laravel_debug --out-json laravel_debug.json
```

Надежная находка требует Laravel marker плюс debug marker или явную утечку
env/secrets. Обычная 500/404 страница без таких признаков не считается
finding.

Детекции:

- `laravel_debug`: exposed Laravel debug/exception page
- `server_error_debug`: debug page reachable on 5xx response
- `stack_trace`: stack trace frames are exposed
- `env_secrets`: в debug output видны env/secrets признаки

Дополнительные поля:

- `notification_priority`: `urgent`, `high`, `medium`, `low`
- `false_positive_confidence`: уверенность, что это не ложнопозитив
- `evidence`: короткие безопасные сигналы
- `owner`: company, contacts, confidence, sources
- `checked_paths`: какие URL проверялись
- `status_codes`: HTTP статусы проверенных paths

Owner discovery пассивный:

- `/.well-known/security.txt`
- `/security.txt`
- homepage title/meta
- emails на homepage/security.txt

Контакты cloud provider фильтруются, приоритет у контактов самого домена.

## Analyzer

Показать статистику:

```bash
python3 es_results_analyzer.py -i scan_results.json --stats
```

Фильтр по severity:

```bash
python3 es_results_analyzer.py -i scan_results.json --min-score 30 -o high_plus.json
```

Фильтр по detection:

```bash
python3 es_results_analyzer.py -i scan_results.json --detection ransomware_note -o ransomware_notes.json
```

Фильтр по module:

```bash
python3 es_results_analyzer.py -i scan_results.json --module elasticsearch -o elasticsearch_only.json
```

Экспорт URL:

```bash
python3 es_results_analyzer.py -i scan_results.json --export-urls urls.txt
```

CSV:

```bash
python3 es_results_analyzer.py -i scan_results.json --export-csv results.csv
```

Markdown report:

```bash
python3 es_results_analyzer.py -i scan_results.json --markdown-report report.md
```

Analyzer совместим со старыми JSON без поля `module`: такие результаты
считаются `elasticsearch`.

## Deep Inspector

Для детального анализа одного Elasticsearch host:

```bash
python3 es_deep_inspector.py http 192.168.1.100 9200
```

Он создает:

```text
deep_analysis_192.168.1.100_9200.txt
deep_analysis_192.168.1.100_9200.json
```

Deep Inspector проверяет:

- список индексов
- mapping
- settings
- sample документов
- sensitive поля
- emails, phones, credit cards
- passwords/tokens
- ransomware note признаки в имени индекса и документах

## Модульный интерфейс

Новый модуль должен:

1. Наследовать `ScannerModule`
2. Принимать `ScanTarget`
3. Возвращать один или несколько `ModuleResult`
4. Быть зарегистрированным в `modules/registry.py`

Единые правила:

- Имя модуля: lowercase snake_case, regex `^[a-z][a-z0-9_]*$`
- `module.name` обязан совпадать с ключом в `AVAILABLE_MODULES`
- `module.description` обязателен
- Модуль не пишет файлы самостоятельно
- Модуль не печатает в stdout во время scan
- Модуль возвращает только `ModuleResult`
- Все дополнительные поля кладутся в `ModuleResult.details`
- Секреты в `sample_data`, `evidence`, `details` должны быть редактированы
- Обычные ошибки сети не должны падать наружу, модуль просто не возвращает finding
- Finding должен проходить false-positive контроль внутри модуля
- Network activity должен быть bounded: timeout из CLI, ограниченный sample/fetch
- Модуль должен быть пассивным, если явно не согласован active режим

Registry проверяет базовые правила при запуске `scanner.py`.

Минимальный пример:

```python
from typing import Iterable

from modules.base import ModuleResult, ScannerModule, ScanTarget


class ExampleModule(ScannerModule):
    name = "example"
    description = "Example module"

    def scan(self, target: ScanTarget, timeout: int, sample_size: int) -> Iterable[ModuleResult]:
        yield ModuleResult(
            module=self.name,
            url=target.url or target.raw,
            host=target.host,
            accessible=True,
            severity_score=0,
            detected_rules=[],
        )
```

Регистрация:

```python
from modules.example import ExampleModule

AVAILABLE_MODULES = {
    ElasticsearchModule.name: ElasticsearchModule(),
    ExampleModule.name: ExampleModule(),
}
```

После этого:

```bash
python3 scanner.py -i targets.csv --modules elasticsearch,example
```

### Рекомендованный `ModuleResult`

```python
ModuleResult(
    module="example",
    url="https://example.com",
    host="example.com",
    accessible=True,
    severity_score=42,
    detected_rules=["example_exposure"],
    sample_data={
        "example_exposure": {
            "category": "HIGH",
            "description": "What was found",
            "matched": ["safe evidence only"],
            "severity": 8,
        }
    },
    environment="production",
    environment_confidence=80,
    environment_signals=["host:prod"],
    details={
        "notification_priority": "high",
        "false_positive_confidence": 90,
        "evidence": ["short safe signal"],
        "owner": {
            "company": "Example",
            "contacts": ["security@example.com"],
            "confidence": 80,
            "sources": ["/.well-known/security.txt"],
        },
    }
)
```

`scanner.py` автоматически:

- пишет общий TXT
- пишет critical TXT
- пишет общий JSON
- пишет краткий файл по каждому модулю в `--out-module-dir`
- показывает общую статистику по модулям

## План для S3 module

Следующий модуль лучше добавлять как `modules/s3.py`, не внутрь
`es_advanced_scanner.py`.

Минимальный безопасный scope:

- распознавать bucket targets из URL/host
- проверять public listing через `?list-type=2`
- парсить XML listing
- искать подозрительные object keys:
  - `.env`
  - `credentials`
  - `aws_access_key_id`
  - `aws_secret_access_key`
  - `api_key`
  - `secret`
  - `token`
  - `password`
  - `private_key`
  - `kubeconfig`
  - `backup`
  - `dump`
  - `.sql`
  - `.bak`
  - `.zip`
  - `users`
  - `customers`
  - `orders`
  - `payments`
  - `kyc`
  - `passport`
  - `pii`
- не скачивать большие архивы и дампы
- для маленьких text/json/yaml/env файлов делать bounded fetch
- редактировать секреты в отчетах

S3 module должен возвращать `ModuleResult(module="s3", ...)`, чтобы analyzer
автоматически показывал отдельную статистику по S3.

## План для owner discovery module

Owner discovery лучше делать отдельным enrichment module:

- `/.well-known/security.txt`
- `/security.txt`
- RDAP/WHOIS
- DNS MX/TXT/SOA
- TLS certificate subject/SAN
- homepage contact/support/security/privacy/legal links
- emails вроде `security@domain`, `support@domain`, `abuse@domain`
- confidence score и список sources

Цель: найти контакт самой компании или ее security policy/support, а не
поддержку cloud provider как основной контакт.

## Проверка перед ручным запуском

Быстрая локальная проверка синтаксиса:

```bash
python3 -m py_compile \
  scanner.py \
  modules/base.py \
  modules/registry.py \
  modules/elasticsearch.py \
  es_advanced_scanner.py \
  es_results_analyzer.py \
  es_deep_inspector.py
```

Проверить CLI:

```bash
python3 scanner.py --help
python3 es_results_analyzer.py --help
python3 es_advanced_scanner.py --help
```

Проверить registry:

```bash
python3 -c "from modules.registry import validate_registry; validate_registry(); print('registry-ok')"
```

### Полный debug Laravel module

Позитивный тест должен показать один finding с:

- `module=laravel_debug`
- `severity_score >= 70`
- `notification_priority=urgent`
- `false_positive_confidence` близко к 100
- `owner.contacts`
- `env_secrets`

Негативный тест должен вернуть `no findings` для обычной Laravel-like страницы
без debug markers.

После запуска проверить все output-слои:

```bash
python3 scanner.py \
  -i laravel_targets.csv \
  --modules laravel_debug \
  --out-results laravel_results.txt \
  --out-critical laravel_critical.txt \
  --out-json laravel_results.json \
  --out-module-dir module_summaries

python3 es_results_analyzer.py \
  -i laravel_results.json \
  --stats \
  --module laravel_debug \
  --export-csv laravel_results.csv \
  --markdown-report laravel_report.md
```

Ручно посмотреть:

```bash
cat laravel_results.txt
cat laravel_critical.txt
cat module_summaries/laravel_debug_summary.txt
python3 -m json.tool laravel_results.json
```

## Рекомендуемый workflow

1. Запустить модульный scanner:

```bash
python3 scanner.py -i targets.csv --modules elasticsearch,laravel_debug --out-json scan_results.json
```

2. Посмотреть статистику:

```bash
python3 es_results_analyzer.py -i scan_results.json --stats
```

3. Вынести подозрительные ransomware findings:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --detection ransomware_note \
  -o ransomware_notes.json
```

4. Отдельно посмотреть production findings:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --min-score 30 \
  --export-csv high_findings.csv
```

5. Для конкретных Elasticsearch hosts запустить deep inspector вручную.

6. Для Laravel debug findings смотреть priority и owner contacts:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --module laravel_debug \
  --export-csv laravel_debug.csv
```

## Примечания по безопасности

- Используйте инструмент только для авторизованного research.
- Не сохраняйте полные секреты в публичные отчеты.
- Не скачивайте большие дампы без необходимости.
- Для уведомления владельцев оставляйте только минимальное доказательство
  воздействия: URL, тип находки, несколько безопасно отредактированных сигналов.
