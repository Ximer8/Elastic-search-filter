#!/bin/bash

# Elasticsearch Security Scanner - Automated Pipeline
# Полный автоматизированный workflow: Scan → Analyze → Report

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="scan_${TIMESTAMP}"

print_banner() {
    echo -e "${MAGENTA}"
    cat << "EOF"
╔════════════════════════════════════════════════════════════════════════════╗
║                                                                            ║
║   🤖 ELASTICSEARCH SECURITY SCANNER - AUTOMATED PIPELINE                   ║
║                                                                            ║
║   Автоматический workflow:                                                ║
║   1. Массовое сканирование                                                ║
║   2. Анализ и фильтрация                                                  ║
║   3. Глубокий анализ критичных хостов                                     ║
║   4. Генерация отчетов                                                    ║
║                                                                            ║
╚════════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR:${NC} $1"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING:${NC} $1"
}

# Проверка зависимостей
check_deps() {
    log "Checking dependencies..."
    
    if ! command -v python3 &> /dev/null; then
        error "Python3 not found"
        exit 1
    fi
    
    if ! python3 -c "import requests" 2>/dev/null; then
        warn "Installing requests module..."
        pip install requests --break-system-packages || pip install requests
    fi
    
    log "✓ All dependencies OK"
}

# Фаза 1: Массовое сканирование
phase_scan() {
    local csv="$1"
    local mode="$2"
    
    log "═══════════════════════════════════════════════════════════════"
    log "PHASE 1: MASS SCANNING"
    log "═══════════════════════════════════════════════════════════════"
    
    case "$mode" in
        fast)
            log "Mode: Fast (30 workers, 8s timeout)"
            WORKERS=30
            TIMEOUT=8
            SAMPLE=200
            ;;
        normal)
            log "Mode: Normal (50 workers, 12s timeout)"
            WORKERS=50
            TIMEOUT=12
            SAMPLE=500
            ;;
        thorough)
            log "Mode: Thorough (30 workers, 20s timeout, 1000 samples)"
            WORKERS=30
            TIMEOUT=20
            SAMPLE=1000
            ;;
        *)
            warn "Unknown mode, using normal"
            WORKERS=50
            TIMEOUT=12
            SAMPLE=500
            ;;
    esac
    
    log "Starting scan with $WORKERS workers..."
    
    python3 es_advanced_scanner.py \
        -i "$csv" \
        -w $WORKERS \
        -t $TIMEOUT \
        --sample-size $SAMPLE \
        --out-results "${OUTPUT_DIR}/scan_results.txt" \
        --out-critical "${OUTPUT_DIR}/critical_findings.txt" \
        --out-detailed "${OUTPUT_DIR}/detailed_report.txt" \
        --out-json "${OUTPUT_DIR}/results.json"
    
    if [ $? -eq 0 ]; then
        log "✓ Scanning completed"
        log "  Results: ${OUTPUT_DIR}/scan_results.txt"
        log "  Critical: ${OUTPUT_DIR}/critical_findings.txt"
        log "  JSON: ${OUTPUT_DIR}/results.json"
    else
        error "Scanning failed"
        exit 1
    fi
}

# Фаза 2: Анализ и фильтрация
phase_analyze() {
    log ""
    log "═══════════════════════════════════════════════════════════════"
    log "PHASE 2: ANALYSIS & FILTERING"
    log "═══════════════════════════════════════════════════════════════"
    
    local json="${OUTPUT_DIR}/results.json"
    
    # Общая статистика
    log "Generating statistics..."
    python3 es_results_analyzer.py -i "$json" --stats > "${OUTPUT_DIR}/statistics.txt"
    
    # Фильтры по severity
    log "Creating severity filters..."
    python3 es_results_analyzer.py -i "$json" --min-score 80 -o "${OUTPUT_DIR}/severity_80plus.json" 2>/dev/null
    python3 es_results_analyzer.py -i "$json" --min-score 50 -o "${OUTPUT_DIR}/severity_50plus.json" 2>/dev/null
    python3 es_results_analyzer.py -i "$json" --min-score 30 -o "${OUTPUT_DIR}/severity_30plus.json" 2>/dev/null
    
    # Фильтры по детекциям
    log "Creating detection filters..."
    for detection in credentials passwords pii medical financial support_chats; do
        python3 es_results_analyzer.py -i "$json" --detection "$detection" \
            -o "${OUTPUT_DIR}/detection_${detection}.json" 2>/dev/null && \
            log "  ✓ Found hosts with $detection"
    done
    
    # Экспорт URL
    log "Exporting URLs..."
    python3 es_results_analyzer.py -i "$json" --export-urls "${OUTPUT_DIR}/all_urls.txt"
    python3 es_results_analyzer.py -i "$json" --min-score 50 --export-urls "${OUTPUT_DIR}/critical_urls.txt" 2>/dev/null
    
    # CSV экспорт
    log "Exporting CSV..."
    python3 es_results_analyzer.py -i "$json" --export-csv "${OUTPUT_DIR}/results.csv"
    
    # Markdown отчет
    log "Generating Markdown report..."
    python3 es_results_analyzer.py -i "$json" --markdown-report "${OUTPUT_DIR}/report.md"
    
    log "✓ Analysis completed"
}

# Фаза 3: Глубокий анализ (опционально)
phase_deep_analysis() {
    local max_hosts="$1"
    
    log ""
    log "═══════════════════════════════════════════════════════════════"
    log "PHASE 3: DEEP ANALYSIS"
    log "═══════════════════════════════════════════════════════════════"
    
    local critical_urls="${OUTPUT_DIR}/critical_urls.txt"
    
    if [ ! -f "$critical_urls" ]; then
        warn "No critical URLs found, skipping deep analysis"
        return
    fi
    
    local count=$(wc -l < "$critical_urls")
    if [ $count -eq 0 ]; then
        warn "No critical hosts to analyze"
        return
    fi
    
    log "Found $count critical hosts"
    
    if [ $count -gt $max_hosts ]; then
        warn "Limiting deep analysis to first $max_hosts hosts"
        count=$max_hosts
    fi
    
    mkdir -p "${OUTPUT_DIR}/deep_analysis"
    
    local analyzed=0
    while IFS= read -r url && [ $analyzed -lt $max_hosts ]; do
        analyzed=$((analyzed + 1))
        
        log "[$analyzed/$count] Analyzing $url"
        
        # Парсим URL
        scheme=$(echo "$url" | grep -oP '^https?')
        host=$(echo "$url" | sed -E 's|^https?://||' | cut -d: -f1)
        port=$(echo "$url" | grep -oP ':\d+' | tr -d ':')
        
        if [ -z "$port" ]; then
            port="9200"
        fi
        
        # Запускаем deep inspector
        python3 es_deep_inspector.py "$scheme" "$host" "$port" \
            > "${OUTPUT_DIR}/deep_analysis/${host}_${port}.txt" 2>/dev/null
        
        if [ -f "deep_analysis_${host}_${port}.txt" ]; then
            mv "deep_analysis_${host}_${port}.txt" "${OUTPUT_DIR}/deep_analysis/"
        fi
        if [ -f "deep_analysis_${host}_${port}.json" ]; then
            mv "deep_analysis_${host}_${port}.json" "${OUTPUT_DIR}/deep_analysis/"
        fi
        
    done < "$critical_urls"
    
    log "✓ Deep analysis completed for $analyzed hosts"
}

# Фаза 4: Финальный отчет
phase_final_report() {
    log ""
    log "═══════════════════════════════════════════════════════════════"
    log "PHASE 4: FINAL REPORT"
    log "═══════════════════════════════════════════════════════════════"
    
    local report="${OUTPUT_DIR}/FINAL_REPORT.txt"
    
    cat > "$report" << EOF
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              ELASTICSEARCH SECURITY SCAN - FINAL REPORT                      ║
║              Scan Date: $(date '+%Y-%m-%d %H:%M:%S')                                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

SCAN SUMMARY:
═══════════════════════════════════════════════════════════════════════════════

EOF
    
    # Добавляем статистику
    cat "${OUTPUT_DIR}/statistics.txt" >> "$report" 2>/dev/null
    
    cat >> "$report" << EOF

CRITICAL FINDINGS:
═══════════════════════════════════════════════════════════════════════════════

EOF
    
    # Добавляем топ критичных находок
    if [ -f "${OUTPUT_DIR}/critical_findings.txt" ]; then
        head -20 "${OUTPUT_DIR}/critical_findings.txt" >> "$report"
    fi
    
    cat >> "$report" << EOF


OUTPUT FILES:
═══════════════════════════════════════════════════════════════════════════════

Main Results:
  📄 ${OUTPUT_DIR}/scan_results.txt       - All scan results
  🔴 ${OUTPUT_DIR}/critical_findings.txt  - Critical findings only
  📋 ${OUTPUT_DIR}/detailed_report.txt    - Detailed analysis
  📊 ${OUTPUT_DIR}/results.json           - JSON data
  📈 ${OUTPUT_DIR}/results.csv            - CSV export
  📝 ${OUTPUT_DIR}/report.md              - Markdown report
  📊 ${OUTPUT_DIR}/statistics.txt         - Statistics

Filtered Results:
  ${OUTPUT_DIR}/severity_*.json           - Filtered by severity
  ${OUTPUT_DIR}/detection_*.json          - Filtered by detection type
  ${OUTPUT_DIR}/all_urls.txt              - All accessible URLs
  ${OUTPUT_DIR}/critical_urls.txt         - Critical URLs only

Deep Analysis:
  ${OUTPUT_DIR}/deep_analysis/            - Detailed host analysis


NEXT STEPS:
═══════════════════════════════════════════════════════════════════════════════

1. Review critical findings in: ${OUTPUT_DIR}/critical_findings.txt
2. Check detection filters in: ${OUTPUT_DIR}/detection_*.json
3. Investigate deep analysis reports in: ${OUTPUT_DIR}/deep_analysis/
4. Share Markdown report: ${OUTPUT_DIR}/report.md

═══════════════════════════════════════════════════════════════════════════════
                              End of Report
═══════════════════════════════════════════════════════════════════════════════
EOF
    
    log "✓ Final report generated: $report"
    
    # Показываем отчет
    cat "$report"
}

# Main
print_banner

if [ $# -lt 1 ]; then
    echo -e "${RED}Usage:${NC} $0 <targets.csv> [mode] [deep_analysis_count]"
    echo ""
    echo "Modes:"
    echo "  fast      - Quick scan (30 workers, 8s timeout)"
    echo "  normal    - Balanced scan (default)"
    echo "  thorough  - Deep scan (20s timeout, 1000 samples)"
    echo ""
    echo "Examples:"
    echo "  $0 targets.csv"
    echo "  $0 targets.csv fast"
    echo "  $0 targets.csv normal 10"
    echo "  $0 targets.csv thorough 5"
    exit 1
fi

CSV="$1"
MODE="${2:-normal}"
DEEP_COUNT="${3:-5}"

if [ ! -f "$CSV" ]; then
    error "File not found: $CSV"
    exit 1
fi

# Создаем директорию для результатов
mkdir -p "$OUTPUT_DIR"
log "Output directory: $OUTPUT_DIR"

# Проверяем зависимости
check_deps

# Запускаем pipeline
START_TIME=$(date +%s)

phase_scan "$CSV" "$MODE"
phase_analyze
phase_deep_analysis "$DEEP_COUNT"
phase_final_report

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

log ""
log "═══════════════════════════════════════════════════════════════"
log "PIPELINE COMPLETED"
log "═══════════════════════════════════════════════════════════════"
log "Total time: ${DURATION}s"
log "Output directory: $OUTPUT_DIR"
log ""
log "Review the final report:"
log "  cat ${OUTPUT_DIR}/FINAL_REPORT.txt"
log ""
log "Happy Hunting! 🎯"
