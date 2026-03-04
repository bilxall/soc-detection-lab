#!/usr/bin/env python3
"""
SOC Detection & Log Analysis Lab
Author: Bilal Ansari
Description: Analyzes Windows Event Logs and Sysmon telemetry to detect:
  - Brute-force login attempts
  - Lateral movement patterns
  - Anomalous authentication behavior
"""

import json
import re
import csv
import argparse
from datetime import datetime, timedelta
from collections import defaultdict
from pathlib import Path

# ─── THRESHOLDS ──────────────────────────────────────────────────────────────
BRUTE_FORCE_THRESHOLD = 5      # failed logins within window = alert
BRUTE_FORCE_WINDOW_SEC = 60    # seconds
LATERAL_MOVEMENT_THRESHOLD = 3 # unique hosts accessed within window
LATERAL_WINDOW_SEC = 300       # 5 minutes

# ─── MITRE ATT&CK MAPPING ────────────────────────────────────────────────────
MITRE_MAP = {
    "brute_force":        {"id": "T1110",   "name": "Brute Force"},
    "lateral_movement":   {"id": "T1021",   "name": "Remote Services"},
    "pass_the_hash":      {"id": "T1550.002", "name": "Pass the Hash"},
    "credential_dumping": {"id": "T1003",   "name": "OS Credential Dumping"},
}

# Windows Event IDs of interest
SUSPICIOUS_EVENT_IDS = {
    4625: "Failed Login",
    4624: "Successful Login",
    4648: "Explicit Credential Login",
    4768: "Kerberos TGT Request",
    4769: "Kerberos Service Ticket",
    4776: "NTLM Authentication",
    4672: "Special Privileges Assigned",
    4688: "Process Creation",
    4698: "Scheduled Task Created",
    7045: "New Service Installed",
}


class LogAnalyzer:
    def __init__(self, log_file: str, output_dir: str = "output"):
        self.log_file = Path(log_file)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.events = []
        self.alerts = []
        self.stats = defaultdict(int)

    # ── PARSING ──────────────────────────────────────────────────────────────

    def parse_logs(self):
        """Auto-detects JSON or CSV log format and parses accordingly."""
        suffix = self.log_file.suffix.lower()
        print(f"[*] Parsing log file: {self.log_file}")
        if suffix == ".json":
            self._parse_json()
        elif suffix == ".csv":
            self._parse_csv()
        else:
            print(f"[!] Unsupported format: {suffix}. Use .json or .csv")
            return
        print(f"[+] Loaded {len(self.events)} events.")

    def _parse_json(self):
        with open(self.log_file) as f:
            data = json.load(f)
        raw = data if isinstance(data, list) else data.get("events", [])
        for entry in raw:
            self.events.append(self._normalize(entry))

    def _parse_csv(self):
        with open(self.log_file, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                self.events.append(self._normalize(dict(row)))

    def _normalize(self, entry: dict) -> dict:
        """Normalize varied field names into a consistent schema."""
        ts_raw = entry.get("TimeCreated") or entry.get("timestamp") or entry.get("time") or ""
        try:
            ts = datetime.fromisoformat(ts_raw)
        except Exception:
            ts = datetime.min

        return {
            "timestamp":    ts,
            "event_id":     int(entry.get("EventID") or entry.get("event_id") or 0),
            "source_ip":    entry.get("IpAddress") or entry.get("source_ip") or "N/A",
            "username":     entry.get("TargetUserName") or entry.get("username") or "N/A",
            "hostname":     entry.get("WorkstationName") or entry.get("hostname") or "N/A",
            "logon_type":   entry.get("LogonType") or entry.get("logon_type") or "N/A",
            "process_name": entry.get("ProcessName") or entry.get("process_name") or "N/A",
            "raw":          entry,
        }

    # ── DETECTION ─────────────────────────────────────────────────────────────

    def detect_all(self):
        """Run all detection modules."""
        print("\n[*] Running detections...")
        self.detect_brute_force()
        self.detect_lateral_movement()
        self.detect_pass_the_hash()
        self.detect_suspicious_processes()
        print(f"[+] Detection complete. {len(self.alerts)} alert(s) generated.\n")

    def detect_brute_force(self):
        """T1110 – Cluster failed logins per user within a sliding time window."""
        failures = defaultdict(list)
        for ev in self.events:
            if ev["event_id"] == 4625:
                failures[ev["username"]].append(ev["timestamp"])

        for user, times in failures.items():
            times.sort()
            for i, t in enumerate(times):
                window = [x for x in times if t <= x <= t + timedelta(seconds=BRUTE_FORCE_WINDOW_SEC)]
                if len(window) >= BRUTE_FORCE_THRESHOLD:
                    self._add_alert(
                        technique="brute_force",
                        severity="HIGH",
                        description=f"Brute-force detected: {len(window)} failed logins for '{user}' within {BRUTE_FORCE_WINDOW_SEC}s",
                        timestamp=t,
                        user=user,
                    )
                    break  # one alert per user per burst

    def detect_lateral_movement(self):
        """T1021 – Detect a single user authenticating to many unique hosts quickly."""
        logins = defaultdict(list)
        for ev in self.events:
            if ev["event_id"] in (4624, 4648) and ev["hostname"] != "N/A":
                logins[ev["username"]].append((ev["timestamp"], ev["hostname"]))

        for user, entries in logins.items():
            entries.sort()
            for i, (t, _) in enumerate(entries):
                window = [(ts, h) for ts, h in entries
                          if t <= ts <= t + timedelta(seconds=LATERAL_WINDOW_SEC)]
                unique_hosts = {h for _, h in window}
                if len(unique_hosts) >= LATERAL_MOVEMENT_THRESHOLD:
                    self._add_alert(
                        technique="lateral_movement",
                        severity="HIGH",
                        description=f"Lateral movement: '{user}' accessed {len(unique_hosts)} hosts in {LATERAL_WINDOW_SEC}s: {unique_hosts}",
                        timestamp=t,
                        user=user,
                    )
                    break

    def detect_pass_the_hash(self):
        """T1550.002 – NTLM auth (4776) from non-standard workstation with logon type 3."""
        for ev in self.events:
            if ev["event_id"] == 4776 or (ev["event_id"] == 4624 and str(ev["logon_type"]) == "3"):
                src = ev["source_ip"]
                if src not in ("127.0.0.1", "::1", "N/A", "-"):
                    self._add_alert(
                        technique="pass_the_hash",
                        severity="MEDIUM",
                        description=f"Possible Pass-the-Hash: NTLM network logon by '{ev['username']}' from {src}",
                        timestamp=ev["timestamp"],
                        user=ev["username"],
                    )

    def detect_suspicious_processes(self):
        """Flag known LOLBins and credential-dumping tools (Event ID 4688)."""
        lolbins = {
            "mimikatz", "procdump", "wce", "gsecdump",
            "mshta.exe", "regsvr32.exe", "rundll32.exe",
            "certutil.exe", "bitsadmin.exe", "wscript.exe",
        }
        for ev in self.events:
            if ev["event_id"] == 4688:
                proc = ev["process_name"].lower()
                if any(lb in proc for lb in lolbins):
                    self._add_alert(
                        technique="credential_dumping",
                        severity="CRITICAL",
                        description=f"Suspicious process detected: '{ev['process_name']}' executed by '{ev['username']}'",
                        timestamp=ev["timestamp"],
                        user=ev["username"],
                    )

    # ── HELPERS ───────────────────────────────────────────────────────────────

    def _add_alert(self, technique, severity, description, timestamp, user="N/A"):
        mitre = MITRE_MAP.get(technique, {})
        alert = {
            "timestamp":       timestamp.isoformat() if timestamp != datetime.min else "N/A",
            "severity":        severity,
            "technique":       technique,
            "mitre_id":        mitre.get("id", "N/A"),
            "mitre_name":      mitre.get("name", "N/A"),
            "description":     description,
            "user":            user,
        }
        self.alerts.append(alert)
        self.stats[severity] += 1

    # ── REPORTING ─────────────────────────────────────────────────────────────

    def generate_report(self):
        """Print summary to console and write alerts to JSON."""
        print("=" * 65)
        print("  SOC DETECTION REPORT")
        print("=" * 65)
        print(f"  Log file   : {self.log_file}")
        print(f"  Events     : {len(self.events)}")
        print(f"  Alerts     : {len(self.alerts)}")
        print(f"  CRITICAL   : {self.stats.get('CRITICAL', 0)}")
        print(f"  HIGH       : {self.stats.get('HIGH', 0)}")
        print(f"  MEDIUM     : {self.stats.get('MEDIUM', 0)}")
        print("=" * 65)

        for i, a in enumerate(self.alerts, 1):
            print(f"\n[ALERT {i}] [{a['severity']}] {a['mitre_id']} – {a['mitre_name']}")
            print(f"  Time   : {a['timestamp']}")
            print(f"  User   : {a['user']}")
            print(f"  Detail : {a['description']}")

        out_path = self.output_dir / "alerts.json"
        with open(out_path, "w") as f:
            json.dump(self.alerts, f, indent=2)
        print(f"\n[+] Alerts saved to {out_path}")

    def export_csv(self):
        """Export alerts as CSV for import into Splunk/Excel."""
        out_path = self.output_dir / "alerts.csv"
        if not self.alerts:
            return
        with open(out_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.alerts[0].keys())
            writer.writeheader()
            writer.writerows(self.alerts)
        print(f"[+] CSV exported to {out_path}")


# ── ENTRY POINT ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SOC Log Analyzer – Bilal Ansari")
    parser.add_argument("logfile", help="Path to event log file (.json or .csv)")
    parser.add_argument("--output", default="output", help="Output directory (default: output)")
    parser.add_argument("--csv", action="store_true", help="Also export alerts as CSV")
    args = parser.parse_args()

    analyzer = LogAnalyzer(args.logfile, args.output)
    analyzer.parse_logs()
    analyzer.detect_all()
    analyzer.generate_report()
    if args.csv:
        analyzer.export_csv()


if __name__ == "__main__":
    main()
