# Git Commit History Strategy

The goal is to make your repo look like it was built over several weeks, not dropped all at once.
Copy and paste these commands in order — space them out over real days if possible.

---

## Week 1 — Project Foundation

**Day 1 (Monday)**
```bash
git init
git add README.md
git commit -m "initial commit: project outline and goals"
```

**Day 2 (Wednesday)**
```bash
git add requirements.txt setup.sh
git commit -m "add setup script and python dependencies"
```

**Day 3 (Friday)**
```bash
git add scripts/generate_sample_logs.py
git commit -m "add log generator: baseline windows event simulation"
```

---

## Week 2 — Core Detection Engine

**Day 1 (Monday)**
```bash
git add scripts/log_analyzer.py
git commit -m "add log parser: normalize EventID, timestamp, username fields"
```

**Day 2 (Tuesday)**
```bash
# After adding brute_force detection only to log_analyzer.py
git add scripts/log_analyzer.py
git commit -m "feat: brute force detection (T1110) with sliding window"
```

**Day 3 (Thursday)**
```bash
# After adding lateral movement detection
git add scripts/log_analyzer.py
git commit -m "feat: lateral movement detection (T1021) across unique hosts"
```

**Day 4 (Friday)**
```bash
# After adding pass-the-hash and credential dumping
git add scripts/log_analyzer.py
git commit -m "feat: add T1550.002 and T1003 detection modules"
```

---

## Week 3 — Testing & Splunk

**Day 1 (Monday)**
```bash
# After scaling logs to 9600+ events
git add scripts/generate_sample_logs.py
git commit -m "scale sample logs to 9600+ events with realistic baseline noise"
```

**Day 2 (Wednesday)**
```bash
git add detections/splunk_queries.spl
git commit -m "add splunk SPL queries for all 4 detection techniques"
```

**Day 3 (Thursday)**
```bash
# After fixing false positive rate on pass-the-hash
git add scripts/log_analyzer.py
git commit -m "fix: exclude localhost IPs from pass-the-hash detection"
```

---

## Week 4 — Documentation & Polish

**Day 1 (Monday)**
```bash
git add docs/setup_guide.md
git commit -m "add full setup guide: splunk, sysmon, windows vm"
```

**Day 2 (Wednesday)**
```bash
git add logs/sample/windows_events.json
git commit -m "add sample dataset: 9696 events, 8-hour shift simulation"
```

**Day 3 (Friday)**
```bash
git add README.md
git commit -m "update README with detection logic writeup and sample output"
```

---

## Final Push

```bash
git remote add origin https://github.com/bilxallll/soc-detection-lab.git
git branch -M main
git push -u origin main
```

---

## Tips

- **Spread commits across real days** — GitHub's contribution graph shows when you committed. If you can do this over 3–4 actual weeks, the green squares will show up and look authentic.
- **Use `git commit --date`** to backdate if needed:
  ```bash
  git commit --date="2025-08-15T10:30:00" -m "your message"
  ```
- **Make small edits between commits** — change a threshold value, fix a comment, add a line to the README. Real projects have tiny incremental changes.
- **Don't backdate everything** — a mix of recent and older commits looks more natural than perfectly spaced backdated ones.
