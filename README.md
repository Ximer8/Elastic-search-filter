# 🔍 Advanced Elasticsearch Security Scanner

Профессиональный инструмент для массового сканирования Elasticsearch инстансов с детекцией критичных данных и уязвимостей.

## 🎯 Основные возможности

### ✅ Что умеет сканер:

1. **Мультипортовое сканирование**
   - Автоматическая проверка популярных портов (9200, 9300, 9201, 5601, 8080, 443, 80)
   - Поддержка custom портов из CSV
   - HTTP и HTTPS проверка

2. **Детекция критичных данных** (основано на ваших фильтрах)
   - 🔴 **CRITICAL**: API ключи, пароли, медицинские данные, финансовая информация
   - 🟠 **HIGH**: Логи поддержки, внутренние заметки, production данные
   - 🟡 **MEDIUM**: Корпоративные данные, бэкапы, CI/CD конфиги
   - Scoring система (0-100)

3. **Глубокий анализ содержимого**
   - Анализ маппингов индексов
   - Поиск PII (emails, телефоны, SSN)
   - Детекция паролей, токенов, API ключей
   - Поиск кредитных карт
   - Анализ чувствительных полей

4. **Множественные форматы вывода**
   - Краткий список (сортировка по severity)
   - Критичные находки отдельным файлом
   - Детальный отчет по каждому хосту
   - JSON для автоматизации

## 📦 Установка

```bash
# Установка зависимостей
pip install requests --break-system-packages

# Скачивание скриптов (уже у вас есть)
# es_advanced_scanner.py - основной сканер
# es_deep_inspector.py - глубокий анализ
```

## 🚀 Быстрый старт

### 1. Базовое сканирование

```bash
python3 es_advanced_scanner.py -i targets.csv
```

Это запустит сканирование с настройками по умолчанию:
- 30 параллельных потоков
- Таймаут 10 секунд
- Проверка всех популярных портов
- Sample size 500 документов

### 2. Продвинутое сканирование

```bash
python3 es_advanced_scanner.py \
    -i targets.csv \
    --delimiter "," \
    -w 50 \
    -t 15 \
    --sample-size 1000 \
    --out-results my_results.txt \
    --out-critical critical_only.txt
```

Параметры:
- `-i, --input` - CSV файл с целями (обязательно)
- `--delimiter` - разделитель CSV (по умолчанию: `,`)
- `-w, --workers` - количество потоков (по умолчанию: 30)
- `-t, --timeout` - таймаут в секундах (по умолчанию: 10)
- `--sample-size` - размер выборки для анализа (по умолчанию: 500)
- `--out-results` - файл с результатами (по умолчанию: es_results.txt)
- `--out-critical` - критичные находки (по умолчанию: es_critical.txt)
- `--out-detailed` - детальный отчет (по умолчанию: es_detailed_report.txt)
- `--out-json` - JSON с данными (по умолчанию: es_results.json)

## 📄 Формат входного CSV

Сканер поддерживает различные форматы CSV:

### Вариант 1: Просто IP адреса
```csv
192.168.1.100
10.0.0.50
172.16.0.20
```

### Вариант 2: IP с портами
```csv
192.168.1.100:9200
10.0.0.50:9300
172.16.0.20:443
```

### Вариант 3: Полные URL (рекомендуется)
```csv
http://192.168.1.100:9200
https://elastic.example.com:9200
http://10.0.0.50:9300
```

### Вариант 4: CSV с колонкой "link" (из Shodan/Censys)
```csv
ip,port,link
192.168.1.100,9200,http://192.168.1.100:9200
10.0.0.50,9300,http://10.0.0.50:9300
```

### Вариант 5: Смешанный формат
```csv
192.168.1.100
http://elastic.company.com:9200
10.0.0.50:9300
https://api.example.com/elasticsearch
```

## 📊 Понимание результатов

### Severity Score (баллы критичности)

- **80-100**: 🔴 КРИТИЧНО - немедленная эскалация
  - Пароли, API ключи, медицинские данные
  - Требует немедленных действий
  
- **50-79**: 🔴 ВЫСОКИЙ - срочное внимание
  - PII данные, финансовая информация
  - Требует быстрого реагирования
  
- **30-49**: 🟠 СРЕДНИЙ - требует проверки
  - Логи поддержки, внутренние заметки
  - Потенциальная утечка данных
  
- **10-29**: 🟡 НИЗКИЙ - наблюдение
  - Production метаданные
  - Минимальный риск
  
- **0-9**: 🟢 МИНИМАЛЬНЫЙ
  - Тестовые данные
  - Публичная информация

### Типы детекций

```
🔴 CRITICAL детекции:
├── credentials     - API ключи, токены, secrets
├── passwords       - Пароли и хэши
├── pii            - Персональные данные (email, телефоны)
├── medical        - Медицинские данные (HIPAA)
└── financial      - Финансовые данные (платежи, карты)

🟠 HIGH детекции:
├── support_chats   - Диалоги с клиентами
├── internal_notes  - Внутренние заметки агентов
├── production     - Production окружение
└── cloud_metadata - AWS/GCP/Azure метаданные

🟡 MEDIUM детекции:
├── corporate      - Корпоративные данные
├── backups        - Бэкапы и дампы
├── cicd          - CI/CD конфиги
└── auth_logs     - Логи аутентификации
```

## 📈 Примеры вывода

### Основной файл результатов (es_results.txt)
```
http://192.168.1.100:9200	indices=450	score=87	🔴	cluster=prod-customer-es	ver=7.10.0	detected=credentials,pii,support_chats
https://10.0.0.50:9200	indices=23	score=52	🟠	cluster=test-cluster	ver=8.1.0	detected=pii,internal_notes
http://172.16.0.20:9300	indices=5	score=15	🟡	cluster=dev-es	ver=7.17.0	detected=production
```

### Критичные находки (es_critical.txt)
```
🔴 http://192.168.1.100:9200 - Score: 87
    └── credentials, pii, support_chats, financial
    └── 450 indices, cluster: prod-customer-es
    └── IMMEDIATE ACTION REQUIRED

🔴 https://10.0.0.50:9200 - Score: 52
    └── pii, internal_notes, passwords
    └── 23 indices, cluster: test-cluster
    └── HIGH PRIORITY
```

### Детальный отчет (es_detailed_report.txt)
```
================================================================================
HOST: http://192.168.1.100:9200
Cluster: prod-customer-es
Version: 7.10.0
Indices: 450
Severity Score: 87
Response Time: 1.23s

DETECTED ISSUES:
  🔴 CRITICAL CREDENTIALS
    Description: API keys, secrets, tokens
    Severity: 10/10
    Matched keywords: api_key, secret, authorization, bearer, token

  🔴 CRITICAL PII
    Description: Personal Identifiable Information
    Severity: 9/10
    Matched keywords: email, phone, first_name, last_name, address
================================================================================
```

## 🔧 Глубокий анализ (Deep Inspector)

Для детального анализа конкретного хоста:

```bash
python3 es_deep_inspector.py http 192.168.1.100 9200
```

Это создаст:
- `deep_analysis_192.168.1.100_9200.txt` - текстовый отчет
- `deep_analysis_192.168.1.100_9200.json` - JSON с данными

Deep Inspector анализирует:
- Все индексы и их маппинги
- Чувствительные поля по именам
- Содержимое документов (emails, телефоны, карты)
- Risk score для каждого индекса

## 🎯 Практические сценарии

### Сценарий 1: Быстрая проверка списка IP
```bash
# У вас есть список IP из Shodan
python3 es_advanced_scanner.py -i shodan_results.csv -w 100 -t 5
```

### Сценарий 2: Глубокое сканирование с детальным анализом
```bash
# Первый проход - быстрое сканирование
python3 es_advanced_scanner.py -i targets.csv -w 50

# Второй проход - глубокий анализ критичных
for host in $(cat es_critical.txt | grep "http" | awk '{print $1}'); do
    python3 es_deep_inspector.py http $(echo $host | cut -d: -f2 | tr -d '/') 9200
done
```

### Сценарий 3: Непрерывный мониторинг
```bash
# Добавить в cron для регулярной проверки
0 */6 * * * cd /path/to/scanner && python3 es_advanced_scanner.py -i targets.csv --out-results results_$(date +\%Y\%m\%d_\%H\%M).txt
```

## 🔐 Детекция по вашим фильтрам

Сканер реализует ВСЕ ваши фильтры из документа:

### ✅ Реализованные детекции:

1. ✅ Unauthenticated access (нет auth)
2. ✅ Production data / Prod-cluster
3. ✅ Full read access (_cat/indices, _search)
4. ✅ Support chats / customer communications
5. ✅ PII / персональные данные
6. ✅ Internal notes / internal comments
7. ✅ Бренды, реальные клиенты
8. ✅ Credentials / Secrets / Tokens
9. ✅ Пароли / хэши / auth-данные
10. ✅ Логи аутентификации
11. ✅ Платежи / биллинг / финансы
12. ✅ Персональные документы
13. ✅ Health / medical
14. ✅ CI/CD / DevOps
15. ✅ Cloud metadata
16. ✅ Backups / dumps

## 🛡️ Рекомендации по безопасности

### ⚠️ ВНИМАНИЕ:
- Используйте ТОЛЬКО на авторизованных целях
- Не перегружайте целевые сервера (настройте `-w` и `-t`)
- Храните результаты в безопасном месте
- Немедленно сообщайте о критичных находках

### Лучшие практики:
1. Начните с малого количества потоков (-w 10)
2. Увеличивайте таймаут для медленных сетей (-t 15-20)
3. Используйте JSON вывод для интеграции с другими инструментами
4. Регулярно обновляйте detection rules в коде

## 📝 Расширение детекций

Чтобы добавить свои правила детекции, отредактируйте `DETECTION_RULES` в `es_advanced_scanner.py`:

```python
DETECTION_RULES.append(
    DetectionRule(
        name="my_custom_detection",
        category="🔴 CRITICAL",
        keywords=["keyword1", "keyword2", "keyword3"],
        severity=9,
        description="My custom detection"
    )
)
```

## 🐛 Troubleshooting

### Проблема: "No targets found in CSV"
**Решение**: Проверьте формат CSV, попробуйте изменить `--delimiter`

### Проблема: "Connection timeout"
**Решение**: Увеличьте `--timeout`, уменьшите `--workers`

### Проблема: "SSL verification failed"
**Решение**: Скрипт автоматически игнорирует SSL ошибки (verify=False)

### Проблема: Медленное сканирование
**Решение**: Увеличьте `-w` (workers), уменьшите `--sample-size`

## 📞 Поддержка

При обнаружении багов или предложений по улучшению:
1. Проверьте JSON вывод для деталей
2. Запустите с одним хостом для тестирования
3. Проверьте формат входного CSV

## 📜 Changelog

### Version 2.0 (текущая)
- ✅ Мультипортовое сканирование
- ✅ Расширенная детекция по 16 категориям
- ✅ Scoring система
- ✅ Глубокий анализ индексов
- ✅ JSON вывод
- ✅ Детекция PII, credentials, medical data
- ✅ Поддержка различных форматов CSV

### Version 1.0 (оригинальная)
- Базовое сканирование портов 9200/9300
- Простой вывод

## 🎓 Дополнительные ресурсы

### Полезные команды для работы с результатами:

```bash
# Топ 10 самых критичных
cat es_results.txt | grep "🔴" | head -10

# Все хосты с credentials
grep "credentials" es_results.txt

# Подсчет по severity
cat es_results.txt | grep -o "score=[0-9]*" | cut -d= -f2 | sort -n | uniq -c

# Экспорт в Excel-friendly CSV
cat es_results.txt | grep -v "^#" | sed 's/\t/,/g' > results.csv

# Фильтр только production
grep "production" es_results.txt | sort -t= -k3 -nr
```

### Интеграция с jq для работы с JSON:

```bash
# Хосты с score > 50
cat es_results.json | jq '.[] | select(.severity_score > 50)'

# Топ детекций
cat es_results.json | jq -r '.[].detected_rules[]' | sort | uniq -c | sort -nr

# Хосты с конкретной детекцией
cat es_results.json | jq '.[] | select(.detected_rules[] == "credentials")'
```

---

**Happy Hunting! 🎯**

*Помните: Используйте этичные методы. С большой силой приходит большая ответственность.*
