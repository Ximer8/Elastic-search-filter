#!/bin/bash

# Elasticsearch Security Scanner - Easy Launcher
# Обертка для удобного запуска сканера

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    cat << "EOF"
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   🔍 Elasticsearch Security Scanner v2.0                     ║
║   Advanced Detection & Analysis Tool                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

print_help() {
    echo -e "${GREEN}Usage:${NC}"
    echo "  ./scan.sh <mode> [options]"
    echo ""
    echo -e "${GREEN}Modes:${NC}"
    echo "  quick <csv>          - Быстрое сканирование (30 потоков, 10s timeout)"
    echo "  normal <csv>         - Обычное сканирование (рекомендуется)"
    echo "  aggressive <csv>     - Агрессивное (100 потоков, 5s timeout)"
    echo "  deep <url>           - Глубокий анализ одного хоста"
    echo "  analyze <json>       - Анализ результатов"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  ./scan.sh quick targets.csv"
    echo "  ./scan.sh normal shodan_results.csv"
    echo "  ./scan.sh deep http://192.168.1.100:9200"
    echo "  ./scan.sh analyze es_results.json"
    echo ""
}

check_requirements() {
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}[!] Python3 not found${NC}"
        exit 1
    fi
    
    if ! python3 -c "import requests" 2>/dev/null; then
        echo -e "${YELLOW}[!] Installing requests...${NC}"
        pip install requests --break-system-packages || pip install requests
    fi
}

scan_quick() {
    local csv="$1"
    echo -e "${GREEN}[*] Quick Scan Mode${NC}"
    python3 es_advanced_scanner.py \
        -i "$csv" \
        -w 30 \
        -t 10 \
        --out-results "quick_results_$(date +%Y%m%d_%H%M%S).txt" \
        --out-critical "quick_critical_$(date +%Y%m%d_%H%M%S).txt"
}

scan_normal() {
    local csv="$1"
    echo -e "${GREEN}[*] Normal Scan Mode${NC}"
    python3 es_advanced_scanner.py \
        -i "$csv" \
        -w 50 \
        -t 12 \
        --sample-size 1000 \
        --out-results "results_$(date +%Y%m%d_%H%M%S).txt" \
        --out-critical "critical_$(date +%Y%m%d_%H%M%S).txt" \
        --out-detailed "detailed_$(date +%Y%m%d_%H%M%S).txt" \
        --out-json "results_$(date +%Y%m%d_%H%M%S).json"
}

scan_aggressive() {
    local csv="$1"
    echo -e "${YELLOW}[*] Aggressive Scan Mode (может быть шумным!)${NC}"
    python3 es_advanced_scanner.py \
        -i "$csv" \
        -w 100 \
        -t 5 \
        --sample-size 200 \
        --out-results "aggressive_results_$(date +%Y%m%d_%H%M%S).txt"
}

scan_deep() {
    local url="$1"
    
    # Парсим URL
    scheme=$(echo "$url" | grep -oP '^https?')
    host=$(echo "$url" | sed -E 's|^https?://||' | cut -d: -f1)
    port=$(echo "$url" | grep -oP ':\d+' | tr -d ':')
    
    if [ -z "$port" ]; then
        port="9200"
    fi
    
    echo -e "${GREEN}[*] Deep Analysis: $scheme://$host:$port${NC}"
    python3 es_deep_inspector.py "$scheme" "$host" "$port"
}

analyze_results() {
    local json="$1"
    
    echo -e "${GREEN}[*] Analyzing results from $json${NC}"
    
    # Статистика
    python3 es_results_analyzer.py -i "$json" --stats
    
    # Создаем полезные выборки
    echo -e "\n${BLUE}[*] Creating filtered outputs...${NC}"
    
    # Критичные (score >= 50)
    python3 es_results_analyzer.py -i "$json" --min-score 50 -o critical_only.json
    python3 es_results_analyzer.py -i "$json" --min-score 50 --export-urls critical_urls.txt
    
    # С credentials
    if python3 es_results_analyzer.py -i "$json" --detection credentials -o has_credentials.json 2>/dev/null; then
        echo -e "${RED}[!] Found hosts with CREDENTIALS${NC}"
    fi
    
    # С PII
    if python3 es_results_analyzer.py -i "$json" --detection pii -o has_pii.json 2>/dev/null; then
        echo -e "${RED}[!] Found hosts with PII data${NC}"
    fi
    
    # Markdown отчет
    python3 es_results_analyzer.py -i "$json" --markdown-report report_$(date +%Y%m%d).md
    
    echo -e "\n${GREEN}[+] Analysis complete!${NC}"
    echo "Files created:"
    echo "  - critical_only.json"
    echo "  - critical_urls.txt"
    echo "  - has_credentials.json (if found)"
    echo "  - has_pii.json (if found)"
    echo "  - report_$(date +%Y%m%d).md"
}

# Main
print_banner
check_requirements

if [ $# -eq 0 ]; then
    print_help
    exit 1
fi

MODE="$1"
TARGET="$2"

case "$MODE" in
    quick)
        if [ -z "$TARGET" ]; then
            echo -e "${RED}[!] CSV file required${NC}"
            exit 1
        fi
        scan_quick "$TARGET"
        ;;
    normal)
        if [ -z "$TARGET" ]; then
            echo -e "${RED}[!] CSV file required${NC}"
            exit 1
        fi
        scan_normal "$TARGET"
        ;;
    aggressive)
        if [ -z "$TARGET" ]; then
            echo -e "${RED}[!] CSV file required${NC}"
            exit 1
        fi
        scan_aggressive "$TARGET"
        ;;
    deep)
        if [ -z "$TARGET" ]; then
            echo -e "${RED}[!] URL required${NC}"
            exit 1
        fi
        scan_deep "$TARGET"
        ;;
    analyze)
        if [ -z "$TARGET" ]; then
            echo -e "${RED}[!] JSON file required${NC}"
            exit 1
        fi
        analyze_results "$TARGET"
        ;;
    *)
        echo -e "${RED}[!] Unknown mode: $MODE${NC}"
        print_help
        exit 1
        ;;
esac

echo -e "\n${GREEN}[✓] Done!${NC}"
