# Modular Security Scanner

Інструмент для авторизованої перевірки власних або дозволених цілей. Він
допомагає швидко відсіяти false positive, знайти відкриті сервіси, оцінити
impact і підготувати короткий security report для команди безпеки.

Проєкт починався як Elasticsearch scanner, але зараз основний інтерфейс
модульний: можна запускати один конкретний модуль або всі модулі через
`--modules all`.

## Що вміє

- Запуск окремих перевірок через `scanner.py --modules <module>`
- Запуск усіх перевірок через `scanner.py --modules all`
- Модулі:
  - `elasticsearch` - відкриті Elasticsearch/Kibana-подібні сервіси
  - `laravel_debug` - відкриті Laravel debug/exception сторінки
  - `s3_bucket_impact` - impact-перевірка AWS S3 bucket exposure
  - `trufflehog_s3` - TruffleHog secret detection для явно переданих AWS S3 buckets
- JSON, TXT, CSV і Markdown звіти
- Per-module summaries у папці `module_summaries`
- Фільтрація результатів по severity, detection і module
- Legacy Elasticsearch-скрипти залишені для сумісності

## Безпечне використання

Використовуй сканер тільки для ресурсів, якими ти володієш, або для яких маєш
письмовий дозвіл на перевірку. S3-модуль не завантажує вміст файлів: він
перевіряє metadata, public listing, `HEAD` для знайдених об'єктів і ризикові
імена ключів.

## Структура

```text
.
├── scanner.py                    # Основний модульний entrypoint
├── modules/
│   ├── base.py                   # ScanTarget, ModuleResult, ScannerModule
│   ├── registry.py               # Реєстр доступних модулів
│   ├── elasticsearch.py          # Elasticsearch module adapter
│   ├── laravel_debug.py          # Laravel debug exposure module
│   ├── s3_bucket_impact.py       # AWS S3 bucket impact module
│   └── trufflehog_s3.py          # TruffleHog adapter for supplied S3 buckets
├── es_advanced_scanner.py        # Legacy Elasticsearch scanner
├── es_results_analyzer.py        # Analyzer для JSON результатів
├── es_deep_inspector.py          # Детальний аналіз одного Elasticsearch host
├── scan.sh                       # Legacy launcher
└── automated_pipeline.sh         # Legacy Elasticsearch workflow
```

## Встановлення

Рекомендовано через virtualenv:

```bash
cd /home/kike/Documents/Elastic-search-filter
python3 -m venv .venv
source .venv/bin/activate
pip install requests
```

Якщо працюєш без virtualenv:

```bash
pip install requests --break-system-packages
```

Для модуля `trufflehog_s3` окремо встанови офіційний TruffleHog CLI і переконайся,
що команда `trufflehog --version` доступна у `PATH`. Модуль використовує
налаштовані AWS credentials поточного середовища і запускає TruffleHog лише для
bucket-цілей, явно переданих у input-файлі.

Для повного локального дебагу через virtualenv:

```bash
python3 -m venv venv
venv/bin/python -m pip install -r requirements-dev.txt
venv/bin/python -m pytest -q
```

## Основна логіка запуску

Є два нормальні сценарії.

Подивитися, які модулі доступні:

```bash
python3 scanner.py --list-modules
```

Запустити один модуль:

```bash
python3 scanner.py -i targets.txt --modules elasticsearch
python3 scanner.py -i targets.txt --modules laravel_debug
python3 scanner.py -i buckets.txt --modules s3_bucket_impact
python3 scanner.py -i buckets.txt --modules trufflehog_s3
```

Запустити всі модулі одразу:

```bash
python3 scanner.py -i targets.txt --modules all
```

Тобто не потрібно вручну писати декілька модулів через кому, якщо твоя задумка
саме “перевірити всім”. Для цього є `all`. Список через кому потрібен тільки
коли ти хочеш власну комбінацію, наприклад:

```bash
python3 scanner.py -i targets.txt --modules elasticsearch,laravel_debug
```

## Якщо в тебе файл з URL по одному в рядок

Наприклад:

```text
http://1.2.3.4:9200
https://example.com
https://my-bucket.s3.amazonaws.com
```

Запуск усіх модулів:

```bash
python3 scanner.py \
  -i /path/to/links.txt \
  --modules all \
  -w 30 \
  -t 10 \
  --sample-size 500 \
  --out-results scan_results.txt \
  --out-critical critical_findings.txt \
  --out-json scan_results.json \
  --out-module-dir module_summaries \
  --out-report-dir critical_reports
```

Для production confirmed critical S3 findings сканер створює готові пакети
репортів у `critical_reports/`. Кожен пакет містить `report.md`,
`evidence.json`, `proof_snapshot.html`, `proof_snapshot.svg` і
`proof_screenshot.png`.

Для Elasticsearch confirmed critical findings сканер створює такий самий пакет:
report, structured evidence, HTML/SVG proof snapshot і PNG screenshot. ES report
створюється тільки якщо endpoint підтверджено як Elasticsearch, finding має
`accessible=True`, `severity_score >= 30`, critical detection rules і cluster/version
або index metadata.

Для Laravel debug findings репортер створює такий самий evidence-backed пакет,
коли є Laravel markers плюс debug або secret evidence. Generic HTTP 500 без
Laravel/debug доказів не репортиться.

Для `trufflehog_s3` критичний evidence-backed пакет створюється тільки коли
TruffleHog повернув щонайменше один результат із `Verified=true`. Raw secret
ніколи не записується в артефакти: зберігаються detector, bucket/key, redacted
preview і короткий SHA-256 fingerprint. Неперевірені збіги залишаються у
`scan_results.json` і module summary для ручного тріажу.

Пакети розкладаються по severity:

```text
critical_reports/
├── critical/                    # score >= 50, з proof_screenshot*.png
├── high/                        # score 30-49, без PNG screenshot
└── medium/                      # score 10-29, без PNG screenshot
```

Репортер не створює critical report для bucket-only або blocked-only випадків.
S3 finding має бути production + critical і підтверджений anonymous HTTP-доказом:
публічний listing з object keys, public object `HEAD 200`, або sensitive object
names з підтвердженого публічного listing. PNG screenshot генерується з локального
proof snapshot через headless Firefox/Chromium, якщо browser доступний у системі.
Якщо browser не стартує, PNG створюється через Pillow fallback.

Під час генерації evidence reports CLI показує прогрес, щоб було видно, що
скрипт не завис:

```text
[*] Generating evidence reports: 3 finding(s)
[*] Report 1/3 [critical] s3_bucket_impact: https://example-bucket.s3.amazonaws.com
    screenshots: critical_reports/critical/example-bucket/proof_screenshot.png (+ impact/validation)
    written: critical_reports/critical/example-bucket
```

Для critical findings створюється не один формальний screenshot, а набір:

```text
proof_screenshot.png              # overview: target, severity, confirmation
proof_screenshot_impact.png       # impact: що саме доступне і чому це важливо
proof_screenshot_validation.png   # curl proof: як перевірити без auth
```

У кожному report є секція `Anonymous Validation` з curl-командами. Вона пояснює,
що перевірка проходить без cookie/header/token, і показує proof, що відповідь
містить валідні непорожні дані, наприклад `ListObjectsV2 HTTP 200`, object
`HEAD 200` і `Content-Length`.

Щоб зменшити false positives у S3, публічні JS/CSS/images/fonts/video assets
без sensitive назв більше не роздувають finding до critical самі по собі.
Critical лишається для сильніших доказів: secrets, private keys, backups, logs,
PII-like names, backend/source/config файли або інший високий impact.

S3 bucket name-only сигнали на кшталт `prod`, `customer`, `backup` у назві bucket
більше не записуються як findings без anonymous access proof. Якщо немає public
listing, public object read, sensitive object names або іншого HTTP-доказу, це
не репортиться.

Після запуску дивись:

```text
scan_results.txt                  # короткий список усіх findings
critical_findings.txt             # findings з score >= 30
scan_results.json                 # повні дані для фільтрації
module_summaries/                 # окремий короткий звіт по кожному модулю
critical_reports/                 # evidence-backed пакети critical/high/medium
```

Повторний запуск з тим самим input-файлом, тим самим набором модулів,
delimiter і sample size не перескановує targets заново. Сканер читає
`scan_results.json` разом із `scan_results.json.manifest.json` і регенерує тільки
summaries/reports:

```text
[*] Cached results match this input and module set.
[*] Skipping network scan and regenerating summaries/reports from JSON.
```

Щоб примусово пересканувати targets заново:

```bash
python3 scanner.py -i targets.txt --modules s3_bucket_impact --force-scan
```

## Як відсіяти false positive і вже hacked/ransomware результати

Після сканування Elasticsearch:

```bash
python3 es_results_analyzer.py -i scan_results.json --stats
```

Витягнути тільки конкретний модуль:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --module elasticsearch \
  -o elasticsearch_only.json
```

Витягнути тільки результати з ransomware note:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --detection ransomware_note \
  -o ransomware_notes.json
```

Витягнути результати без низького noise, наприклад score від 30:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --min-score 30 \
  -o high_signal.json
```

Зробити Markdown-звіт для ручного перегляду:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --markdown-report security_report.md
```

Практичний порядок такий:

1. Запускаєш `scanner.py`.
2. Дивишся `module_summaries/`.
3. Відкладаєш `ransomware_note`, якщо тобі треба прибрати вже захоплені/зіпсовані цілі.
4. Працюєш з `critical_findings.txt` і JSON-фільтрами.

## S3 Bucket Impact Module

Модуль `s3_bucket_impact` приймає:

```text
my-company-prod-backups
s3://my-company-prod-backups
https://my-company-prod-backups.s3.amazonaws.com
https://s3.amazonaws.com/my-company-prod-backups
https://my-company-prod-backups.s3.us-east-1.amazonaws.com
```

Файл з бакетами:

```bash
nano buckets.txt
```

Приклад:

```text
my-company-prod-backups
my-company-public-assets
https://my-company-logs.s3.amazonaws.com
```

Запуск тільки S3-модуля:

```bash
python3 scanner.py \
  -i buckets.txt \
  --modules s3_bucket_impact \
  -w 10 \
  -t 10 \
  --sample-size 200 \
  --out-results s3_results.txt \
  --out-critical s3_critical.txt \
  --out-json s3_results.json \
  --out-module-dir s3_summaries
```

Де дивитися impact report:

```text
s3_summaries/s3_bucket_impact_summary.txt
```

Модуль перевіряє:

- чи bucket існує;
- який `x-amz-bucket-region` повертає AWS;
- чи доступний anonymous `ListBucket`;
- скільки object keys видно у sample;
- чи є public-read для знайдених об'єктів через `HEAD`;
- чи є ризикові імена файлів: `.env`, secrets, backups, dumps, private keys,
  logs, PII-like names, source/config paths;
- production/test/unknown context по назві bucket і object keys;
- severity score і notification priority;
- security report з impact, evidence і remediation.

## Severity

Загальна шкала:

```text
>= 50  critical
30-49  high
10-29  medium
< 10   low
```

Для `critical_findings.txt` у модульному сканері використовується `score >= 30`,
щоб не пропустити важливі findings на ранньому етапі triage.

## Приклади команд

Elasticsearch окремо:

```bash
python3 scanner.py -i links.txt --modules elasticsearch
```

Laravel debug окремо:

```bash
python3 scanner.py -i links.txt --modules laravel_debug
```

S3 impact окремо:

```bash
python3 scanner.py -i buckets.txt --modules s3_bucket_impact
```

Усі модулі:

```bash
python3 scanner.py -i links.txt --modules all
```

Експорт CSV для таблиці:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --export-csv results.csv
```

Експорт URL після фільтрації:

```bash
python3 es_results_analyzer.py \
  -i scan_results.json \
  --min-score 30 \
  --export-urls high_signal_urls.txt
```

## Legacy Elasticsearch tools

Старий запуск Elasticsearch залишився:

```bash
python3 es_advanced_scanner.py -i targets.csv
```

Deep inspection одного host:

```bash
python3 es_deep_inspector.py http 127.0.0.1 9200
```

Нові перевірки бажано додавати як модулі в `modules/` і реєструвати в
`modules/registry.py`.
