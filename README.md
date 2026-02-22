# 🛡️ SOC Analyst Lab — Network Traffic Analysis & Threat Hunting

> **A complete Tier-1 SOC analyst investigation simulating real-world blue team operations.**  
> Built by **MD Tameem** | February 2026

---

## 📌 Project Overview

This project simulates a full SOC analyst workflow covering:
- Network traffic capture and analysis with **Wireshark**
- Brute force detection via **Windows Security Event logs**
- SIEM log ingestion, querying, and correlation in **Splunk Enterprise**
- Threat intelligence validation using **VirusTotal** and **AbuseIPDB**
- **MITRE ATT&CK** framework mapping

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| Wireshark | Packet capture — SYN scan, HTTP, DNS, ICMP analysis |
| Nmap | Simulated port scanning (SYN stealth scan) |
| Splunk Enterprise | SIEM — log ingestion, SPL queries, correlation |
| Windows Event Viewer | Security event log review (4625, 4624, 4672) |
| VirusTotal | IP reputation and malware detection lookup |
| AbuseIPDB | IP abuse history and scoring |
| MITRE ATT&CK | Tactic and technique mapping |

---

## 🔍 Scenarios Investigated

### Scenario 1 — Network Reconnaissance Detection
**Simulation:** `nmap -sS localhost`  
**Detection filter in Wireshark:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```
**Finding:** Multiple SYN packets without ACK — classic TCP SYN stealth scan  
**MITRE ATT&CK:** [T1046 — Network Service Discovery](https://attack.mitre.org/techniques/T1046/)

---

### Scenario 2 — Brute Force Login Detection
**Event IDs monitored:**
- `4625` — Failed Logon
- `4624` — Successful Logon  
- `4672` — Special Privileges Assigned
- `1102` — Security Log Cleared

**Splunk queries used:**
```spl
index=main EventCode=4625

index=main (EventCode=4624 OR EventCode=4625)
| table _time EventCode Account_Name Logon_Type

index=main (EventCode=4624 OR EventCode=4625)
| timechart count by EventCode
```

**Finding:** 207 failed logon events for accounts `mdsaa` and `fakeuser`, followed by successful privileged logon — **brute force pattern confirmed**  
**MITRE ATT&CK:** [T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)

---

### Scenario 3 — IOC Validation
**IPs Investigated:** IPv6 addresses extracted from Wireshark captures  
**Platforms used:** VirusTotal, AbuseIPDB

| IOC IP | VirusTotal | AbuseIPDB | Verdict |
|--------|-----------|-----------|---------|
| 2409:40f4:3017:2856:... | 0/93 — Clean | Not in DB | ✅ Clean |
| 2409:40f4:3001:b4e2:... | 0/93 — Clean | Not in DB | ✅ Clean |

**ISP:** Reliance Jio Infocomm Limited (India) — No malicious indicators found.

---

## 📊 SIEM Findings Summary

| Metric | Value |
|--------|-------|
| Total Events Ingested | 9,392 |
| Failed Logons (4625) | 207+ |
| Successful Logons (4624) | 6,647 (Feb 2026 spike) |
| Accounts Targeted | `mdsaa`, `fakeuser` |
| Logon Type (failed) | Type 2 (Interactive) |
| Logon Type (success) | Type 5 (Service) |
| Source Network (failed) | `::1` (localhost) |

---

## ⚠️ Risk Assessment

| Category | Risk Level | Finding |
|----------|-----------|---------|
| Authentication Abuse | 🟠 MEDIUM-HIGH | Brute force pattern (4625 → 4624) |
| Privileged Access | 🔴 HIGH | Event ID 4672 — elevated token |
| Network Recon | 🟡 MEDIUM | SYN scan detected |
| IOC / Threat Intel | 🟢 LOW | All IPs clean |

---

## 📁 Repository Structure

```
SOC-Bruteforce-Lab/
├── README.md
├── SOC-Lab-Report-MD-Tameem.docx    # Full investigation report
├── logs/
│   └── SOC-Bruteforce-Lab.evtx     # Windows Security Event log
├── screenshots/
│   ├── SYN_scan_.png
│   ├── DNS_Wireshark.png
│   ├── Http_wireshark.png
│   ├── ICMP_Detect.png
│   ├── 4624_Successfull_login.png
│   ├── Failed_logins_splunk.png
│   ├── SPLUNK_EVENT_TABLE.png
│   ├── Splunk_timeline_result.png
│   ├── Show_success___failure_timeline.png
│   ├── virustotal.png
│   └── AbuseIPDB_.png
└── splunk-queries/
    └── queries.spl
```

---

## 🔎 Key SPL Queries

```spl
# Detect all failed logins
index=main EventCode=4625

# Detect successful logins
index=main EventCode=4624

# Brute force correlation (failed → success timeline)
index=main (EventCode=4624 OR EventCode=4625)
| sort _time
| table _time EventCode Account_Name Logon_Type

# Monthly event volume
index=main (EventCode=4624 OR EventCode=4625)
| timechart count by EventCode

# With network source
index=main (EventCode=4624 OR EventCode=4625)
| table _time EventCode Account_Name Logon_Type Source_Network_Address
```

---

## 📋 Recommendations

1. **Account Lockout Policy** — Lock after 5 failed attempts within 30 minutes
2. **SIEM Alerting** — Alert on >10 Event ID 4625 events per account per 5 minutes
3. **Privileged Account Monitoring** — Dashboard for Event IDs 4672 and 4768
4. **Network Segmentation** — Isolate critical systems from workstations
5. **IOC Pipeline** — Automate VirusTotal/AbuseIPDB API enrichment in Splunk
6. **Log Retention** — Minimum 90 days, monitor Event ID 1102 (log cleared)

---

## 🎯 MITRE ATT&CK Coverage

| Technique | ID | Tactic |
|-----------|-----|--------|
| Network Service Discovery | T1046 | Discovery |
| Brute Force | T1110 | Credential Access |
| Password Guessing | T1110.001 | Credential Access |
| Indicator Removal — Clear Windows Event Logs | T1070.001 | Defense Evasion |

---

## 👤 About

**MD Tameem**  
SOC Analyst | Blue Team | Threat Hunting  

> *This project is part of my hands-on cybersecurity portfolio demonstrating practical SOC Tier-1 skills.*

---

⭐ If this project helped you, consider giving it a star!
