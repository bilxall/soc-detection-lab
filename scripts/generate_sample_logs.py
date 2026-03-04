#!/usr/bin/env python3
"""
generate_sample_logs.py
Generates 10,000+ realistic Windows Security Event Log samples for lab testing.
Simulates a full 8-hour SOC shift with baseline noise + 4 attack scenarios.
"""

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(1337)

BASE_TIME          = datetime(2025, 9, 15, 8, 0, 0)
SHIFT_DURATION_SEC = 8 * 3600

LEGIT_USERS  = ["jsmith","adavis","breynolds","mthompson","clee",
                "rpatil","sweiss","dkumar","lfoster","hpark"]
HOSTS        = ["WS-FINANCE01","WS-HR02","WS-DEV04","WS-LEGAL05",
                "WS-EXEC06","SERVER-APP03","DC-PROD01","DC-BACKUP02"]
INTERNAL_IPS = ["192.168.1." + str(i) for i in range(10, 60)]
ATTACKER_IP  = "192.168.1.99"

events = []

def ts(offset_sec):
    return (BASE_TIME + timedelta(seconds=offset_sec)).isoformat()

def rand_ts(start, end):
    return ts(random.uniform(start, end))

def event(time, eid, user, ip, host, logon="N/A", proc=None):
    e = {"TimeCreated": time, "EventID": eid, "TargetUserName": user,
         "IpAddress": ip, "WorkstationName": host, "LogonType": logon}
    if proc:
        e["ProcessName"] = proc
    return e

# ── BASELINE ~9,800 normal events ─────────────────────────────────────────────
print("[*] Generating baseline (9,800+ events)...")

for user in LEGIT_USERS:
    for _ in range(random.randint(2, 4)):
        events.append(event(rand_ts(0,1800), 4624, user, random.choice(INTERNAL_IPS), random.choice(HOSTS), 2))
    for _ in range(random.randint(1, 2)):
        events.append(event(rand_ts(0, SHIFT_DURATION_SEC), 4625, user, random.choice(INTERNAL_IPS), random.choice(HOSTS), 2))

for _ in range(1200):
    events.append(event(rand_ts(0, SHIFT_DURATION_SEC), random.choice([4768,4769]),
        random.choice(LEGIT_USERS), random.choice(INTERNAL_IPS), random.choice(HOSTS)))

PROCS = ["C:\\Windows\\System32\\svchost.exe",
         "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
         "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
         "C:\\Windows\\System32\\cmd.exe","C:\\Windows\\System32\\powershell.exe",
         "C:\\Program Files\\Slack\\slack.exe","C:\\Windows\\explorer.exe"]

for _ in range(5500):
    events.append(event(rand_ts(0, SHIFT_DURATION_SEC), 4688,
        random.choice(LEGIT_USERS), "N/A", random.choice(HOSTS), proc=random.choice(PROCS)))

for _ in range(80):
    events.append(event(rand_ts(0, SHIFT_DURATION_SEC), 4698,
        "SYSTEM", "N/A", random.choice(HOSTS), proc="C:\\Windows\\System32\\taskhost.exe"))

for _ in range(2500):
    events.append(event(rand_ts(3600, SHIFT_DURATION_SEC), 4634,
        random.choice(LEGIT_USERS), random.choice(INTERNAL_IPS), random.choice(HOSTS), 2))

for _ in range(300):
    events.append(event(rand_ts(0, SHIFT_DURATION_SEC), 4672,
        random.choice(["adavis","rpatil"]), random.choice(INTERNAL_IPS), random.choice(HOSTS), 2))

print(f"    Baseline total: {len(events):,}")

# ── ATTACK: T1110 Brute-Force at 10:00 AM (T+7200s) ──────────────────────────
ATTACK_START    = 7200
COMPROMISE_TIME = ATTACK_START + 190

print("[*] Injecting T1110 – Brute Force (47 attempts)...")
for i in range(47):
    events.append(event(ts(ATTACK_START + i*3.8), 4625, "jsmith", ATTACKER_IP, "WS-UNKNOWN", 3))
events.append(event(ts(COMPROMISE_TIME), 4624, "jsmith", ATTACKER_IP, "WS-UNKNOWN", 3))

# ── ATTACK: T1021 Lateral Movement at 10:03 AM ────────────────────────────────
LATERAL_START = COMPROMISE_TIME + 120
lateral_hosts = ["WS-FINANCE01","WS-HR02","SERVER-APP03","DC-BACKUP02","DC-PROD01"]

print("[*] Injecting T1021 – Lateral Movement (5 hosts)...")
for i, host in enumerate(lateral_hosts):
    events.append(event(ts(LATERAL_START + i*55), 4624, "jsmith", ATTACKER_IP, host, 3))
    events.append(event(ts(LATERAL_START + i*55+5), 4648, "jsmith", ATTACKER_IP, host, 3))

# ── ATTACK: T1550.002 Pass-the-Hash at 10:10 AM ───────────────────────────────
PTH_START = LATERAL_START + 5*55 + 120

print("[*] Injecting T1550.002 – Pass-the-Hash...")
for i in range(6):
    events.append(event(ts(PTH_START + i*30), 4776,
        random.choice(["administrator","jsmith"]), ATTACKER_IP, "DC-PROD01", 3))

# ── ATTACK: T1003 Credential Dumping at 10:15 AM ─────────────────────────────
DUMP_TIME = PTH_START + 300

print("[*] Injecting T1003 – Credential Dumping (mimikatz)...")
events.append(event(ts(DUMP_TIME), 4688, "jsmith", ATTACKER_IP, "DC-PROD01",
    proc="C:\\Users\\jsmith\\AppData\\Local\\Temp\\mimikatz.exe"))
events.append(event(ts(DUMP_TIME+12), 4688, "jsmith", ATTACKER_IP, "DC-PROD01",
    proc="C:\\Windows\\System32\\procdump.exe"))
events.append(event(ts(DUMP_TIME+45), 7045, "jsmith", "N/A", "DC-PROD01",
    proc="C:\\Windows\\System32\\malware_svc.exe"))

# ── WRITE ─────────────────────────────────────────────────────────────────────
events.sort(key=lambda e: e["TimeCreated"])
Path("logs/sample").mkdir(parents=True, exist_ok=True)

with open("logs/sample/windows_events.json", "w") as f:
    json.dump({"events": events}, f, indent=2)

attack = sum(1 for e in events if e.get("IpAddress") == ATTACKER_IP)
print(f"\n[+] Generated {len(events):,} events → logs/sample/windows_events.json")
print(f"    Benign: {len(events)-attack:,}  |  Attack: {attack}")
print(f"    Time window: 08:00–16:00 (8-hour shift simulation)")
print(f"    Techniques: T1110, T1021, T1550.002, T1003")
