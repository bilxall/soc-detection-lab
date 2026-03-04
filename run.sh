#!/bin/bash
# ============================================================
# run.sh — SOC Detection Lab: One-shot runner
# Author: Bilal Ansari
#
# Usage:
#   chmod +x run.sh && ./run.sh
#
# No pip install needed — uses Python standard library only.
# ============================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}=================================================${NC}"
echo -e "${CYAN}   SOC Detection & Log Analysis Lab${NC}"
echo -e "${CYAN}   github.com/bilxallll/soc-detection-lab${NC}"
echo -e "${CYAN}=================================================${NC}"
echo ""

echo -e "${YELLOW}[1/4] Checking Python 3...${NC}"
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!] Python 3 not found.${NC}"
    echo "    Install from: https://www.python.org/downloads/"
    echo "    Or on Mac:    brew install python"
    exit 1
fi
echo -e "${GREEN}[+] $(python3 --version) found${NC}"

echo ""
echo -e "${YELLOW}[2/4] Creating directories...${NC}"
mkdir -p logs/sample output docs
echo -e "${GREEN}[+] Ready${NC}"

echo ""
echo -e "${YELLOW}[3/4] Generating 9,600+ Windows event log dataset...${NC}"
python3 scripts/generate_sample_logs.py

echo ""
echo -e "${YELLOW}[4/4] Running detection engine...${NC}"
echo ""
python3 scripts/log_analyzer.py logs/sample/windows_events.json --csv

echo ""
echo -e "${CYAN}=================================================${NC}"
echo -e "${GREEN}  Done! Output files generated:${NC}"
echo -e "${GREEN}    output/alerts.json  — structured alert data${NC}"
echo -e "${GREEN}    output/alerts.csv   — import into Splunk/Excel${NC}"
echo -e "${CYAN}=================================================${NC}"
echo ""
echo -e "${YELLOW}  SCREENSHOT THIS TERMINAL, then push to GitHub:${NC}"
echo ""
echo "     git init"
echo "     git add ."
echo "     git commit -m 'initial commit: SOC detection lab'"
echo "     gh repo create soc-detection-lab --public --push"
echo ""
