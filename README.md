# Windows APT Log Investigation

A hands-on SOC investigation project analysing suspicious Windows endpoint activity using **Splunk Cloud**.

## Project Overview

This project investigates Windows endpoint logs from a simulated attack scenario dated 22 December 2024.

The objective was to analyse suspicious activity, identify potential attack behaviours, correlate events, document indicators, and reach an evidence-based verdict.

## Investigation Environment

- **SIEM:** Splunk Cloud
- **Log source:** Windows endpoint telemetry (`22-December.csv`)
- **Host:** `windows-apt-2025`
- **Investigation date:** 22 December 2024

## Investigation Highlights

The investigation identified:

- Suspicious execution of `splunkd.exe` from `C:\Users\Public\`.
- Local account and credential discovery commands.
- 7-Zip archive-related activity.
- PowerShell download and Mimikatz execution attempt.
- Suspicious DLL manipulation and system configuration activity.
- References to the IP address `172.31.234.82`.

## Tools and Techniques

- Splunk Cloud Search & Reporting
- SPL (Search Processing Language)
- Windows endpoint log analysis
- Process and command-line investigation
- Event correlation
- MITRE ATT&CK mapping

## Key Deliverables

| File | Purpose |
|---|---|
| `notes.md` | Investigation notes |
| `searches.md` | SPL queries used |
| `timeline.md` | Chronological event timeline |
| `report/investigation-report.md` | Final investigation report |
| `evidence/screenshots/` | Supporting Splunk screenshots |
| `evidence/exports/` | Exported search results |

## Final Assessment

**Verdict: True Positive — Suspicious Activity Observed**

Multiple suspicious behaviours were identified. However, successful credential extraction, data exfiltration, persistence, and command-and-control communication were not confirmed by the available evidence.

## Project Scope

This is a lab-based investigation using supplied log data. It demonstrates SOC Level 1 investigation and documentation skills; it is not professional incident response experience or evidence of a real-world breach.