# SOC Detection Lab – Full Setup Guide

## Overview

This guide walks through setting up a complete SOC detection environment on macOS using free tools. By the end you will have a working lab that ingests Windows-style logs, runs detections, and produces SIEM-ready alerts.

---

## Part 1: Python Lab (No VM Required)

This gets you running immediately with simulated logs.

### Step 1 – Clone the repository

```bash
git clone https://github.com/bilxallll/soc-detection-lab.git
cd soc-detection-lab
```

### Step 2 – Run setup

```bash
chmod +x setup.sh
./setup.sh
```

This will:
- Create a Python virtual environment
- Install required packages
- Generate sample Windows event logs with attack scenarios

### Step 3 – Run the analyzer

```bash
source venv/bin/activate
python3 scripts/log_analyzer.py logs/sample/windows_events.json --csv
```

Alerts are saved to `output/alerts.json` and `output/alerts.csv`.

---

## Part 2: Splunk Free Trial Setup

### Step 1 – Download Splunk Enterprise (Free Trial)

1. Go to https://www.splunk.com/en_us/download/splunk-enterprise.html
2. Register for a free account
3. Download the macOS `.dmg` installer
4. Install and start Splunk (default: http://localhost:8000)

### Step 2 – Ingest the sample logs

1. In Splunk Web, go to **Settings → Add Data → Upload**
2. Upload `logs/sample/windows_events.json`
3. Set Source Type to `json`
4. Set Index to `windows` (create it if it doesn't exist)

### Step 3 – Run the SPL queries

Copy queries from `detections/splunk_queries.spl` into the Splunk Search bar one at a time.

### Step 4 – Build a dashboard (optional)

1. After running a search, click **Save As → Dashboard Panel**
2. Name it "SOC Detection Lab"
3. Add all 5 detection queries as separate panels
4. Screenshot the dashboard for your GitHub README

---

## Part 3: Windows VM for Real Log Generation (Advanced)

### Requirements

- VirtualBox (free): https://www.virtualbox.org/
- Windows 10 ISO (free): https://www.microsoft.com/en-us/software-download/windows10

### Step 1 – Create a Windows 10 VM

1. Open VirtualBox → New
2. Name: `SOC-Lab-Win10`
3. RAM: 4GB minimum
4. Storage: 50GB dynamic

### Step 2 – Install Sysmon

Download from: https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

```powershell
# Run in PowerShell as Administrator
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

Use the SwiftOnSecurity config: https://github.com/SwiftOnSecurity/sysmon-config

### Step 3 – Generate attack logs

Run these PowerShell commands on the VM to simulate attacks that generate real Windows events:

```powershell
# Simulate failed logins (generates Event ID 4625)
for ($i=0; $i -lt 10; $i++) {
    $cred = New-Object System.Management.Automation.PSCredential("testuser",
        (ConvertTo-SecureString "wrongpassword$i" -AsPlainText -Force))
    try { Start-Process cmd -Credential $cred -ErrorAction SilentlyContinue } catch {}
    Start-Sleep -Milliseconds 500
}

# Check Security event log
Get-WinEvent -LogName Security -MaxEvents 50 | Where-Object Id -eq 4625 |
    Select-Object TimeCreated, Id, Message | Format-List
```

### Step 4 – Export logs for analysis

```powershell
# Export to JSON for use with the Python analyzer
Get-WinEvent -LogName Security -MaxEvents 1000 |
    Select-Object TimeCreated, Id, Message |
    ConvertTo-Json | Out-File C:\logs\security_events.json
```

Transfer the file to your Mac and run:
```bash
python3 scripts/log_analyzer.py /path/to/security_events.json --csv
```

---

## Event ID Reference

| Event ID | Description | Detection Use |
|---|---|---|
| 4624 | Successful logon | Lateral movement, off-hours logins |
| 4625 | Failed logon | Brute-force detection |
| 4648 | Logon with explicit credentials | Pass-the-hash, credential reuse |
| 4672 | Special privileges assigned | Privilege escalation |
| 4688 | Process creation | Malware/LOLBin detection |
| 4698 | Scheduled task created | Persistence mechanisms |
| 4776 | NTLM credential validation | Pass-the-hash |
| 7045 | New service installed | Malware persistence |

---

## Troubleshooting

**Python script not finding log file:**
```bash
# Make sure you're in the project root directory
cd soc-detection-lab
python3 scripts/log_analyzer.py logs/sample/windows_events.json
```

**Splunk not starting:**
```bash
# Start Splunk manually
/Applications/Splunk/bin/splunk start
```

**No alerts generated:**
- Verify the log file has events with EventID fields
- Check that timestamps are in ISO 8601 format: `2025-09-15T08:00:00`
