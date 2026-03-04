#!/bin/bash
# ============================================================
# setup.sh – SOC Detection Lab Environment Setup (macOS)
# Author: Bilal Ansari
# ============================================================

set -e

echo "================================================="
echo "  SOC Detection & Log Analysis Lab – Setup"
echo "================================================="

# ── 1. Check Python ───────────────────────────────────────
echo "[*] Checking Python 3..."
if ! command -v python3 &>/dev/null; then
  echo "[!] Python 3 not found. Install via: brew install python"
  exit 1
fi
echo "[+] Python 3 found: $(python3 --version)"

# ── 2. Create virtual environment ────────────────────────
echo "[*] Creating virtual environment..."
python3 -m venv venv
source venv/bin/activate
echo "[+] Virtualenv activated."

# ── 3. Install Python dependencies ───────────────────────
echo "[*] Installing dependencies..."
pip install --quiet --upgrade pip
pip install --quiet pandas tabulate colorama
echo "[+] Dependencies installed."

# ── 4. Create output directory ───────────────────────────
mkdir -p output logs/sample
echo "[+] Output directories created."

# ── 5. Generate sample logs ──────────────────────────────
echo "[*] Generating sample Windows event logs..."
cd scripts && python3 generate_sample_logs.py && cd ..
echo "[+] Sample logs ready."

echo ""
echo "================================================="
echo "  Setup complete! Run the lab:"
echo ""
echo "  source venv/bin/activate"
echo "  python3 scripts/log_analyzer.py logs/sample/windows_events.json --csv"
echo "================================================="
