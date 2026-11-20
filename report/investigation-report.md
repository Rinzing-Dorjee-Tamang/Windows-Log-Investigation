# Windows APT Log Investigation Report

## 1. Executive Summary

This investigation analysed Windows endpoint telemetry collected on **22 December 2024** using Splunk Cloud.

The investigation identified suspicious process execution, account and credential discovery commands, archive-related activity, a Mimikatz execution attempt, and DLL manipulation.

The activity involved the account `DESKTOP-QGB4EQH\mari` on the host `windows-apt-2025`.

The findings indicate potentially malicious endpoint activity. However, the available logs do not confirm that credentials were successfully extracted, data was successfully exfiltrated, or persistence was established.

**Final Verdict:** True Positive — suspicious activity observed.

**Investigation scope:** Supplied lab dataset; this report does not establish a real-world compromise.

## 2. Investigation Details

| Field | Details |
|---|---|
| Platform | Splunk Cloud |
| Data source | `22-December.csv` |
| Sourcetype | `csv` |
| Host | `windows-apt-2025` |
| Affected user | `DESKTOP-QGB4EQH\mari` |
| Activity date | 22 December 2024 |
| Investigation type | Windows endpoint threat investigation |
| Verdict | True Positive |

## 3. Key Findings

### 3.1 Suspicious Executable

A suspicious executable named `splunkd.exe` was observed at:

`C:\Users\Public\splunkd.exe`

The process command line referenced:

`http://172.31.234.82:8888`

and the group parameter:

`-group red`

File creation telemetry recorded multiple creation events for this executable.

**SHA256:**
`BADF4752413CB0CBDC03FB95820CA167F0CDC63B597CCDB5EF43111180E088B0`

**Assessment:** Suspicious executable and command-line activity requiring further investigation.

### 3.2 Account and Credential Discovery

Commands observed included:

- `net user`
- `dir c:\Users\`
- `cmdkey.exe /list`
- `net localgroup "Users"`
- `net localgroup`

These commands can be used to enumerate local accounts, inspect user directories, discover saved credentials, and identify group memberships.

**Assessment:** Account and credential discovery activity was observed.

### 3.3 Archive Activity

The logs showed a command involving 7-Zip:

`7z.exe u archive.7z *txt -pblue`

The command attempted to update an archive containing text files and specified a password.

**Assessment:** Archive-related activity was observed. Successful archive creation or preparation for exfiltration was not independently confirmed.

### 3.4 Mimikatz Download and Execution Attempt

PowerShell activity showed a download of `Invoke-Mimikatz.ps1` from GitHub, followed by:

`Invoke-Mimikatz -DumpCreds`

This command is associated with credential-dumping activity.

**Assessment:** A credential-dumping attempt was observed. The available evidence does not confirm successful credential extraction.

### 3.5 DLL Manipulation and Possible Defense Evasion

The logs showed commands involving:

- Copying `amsi.dll`
- Renaming it to `WinAppXRT.dll`
- Renaming it to `ualapi.dll`
- Copying DLL files into `C:\Windows\System32\`
- Setting the `APPX_PROCESS` registry value
- Modifying the Windows Print Spooler service configuration

These actions may indicate an attempt to manipulate security-related components or system configuration.

**Assessment:** Suspicious DLL and system-configuration activity was observed. Successful defense evasion or persistence was not confirmed.

### 3.6 Additional PowerShell Activity

PowerShell commands defined functions with names associated with PowerSploit capabilities, including `Invoke-Mimikatz`, `PowerView`, and `Get-Keystrokes`.

However, the recorded function bodies included the text `Pretending to invoke`.

**Assessment:** The function definitions alone do not establish that the named capabilities actually executed.

### 3.7 Network Indicator

The IP address `172.31.234.82` appeared in the investigation data. The suspicious executable command line referenced port `8888`.

A search for this IP returned 13 events. Separate telemetry showed listening ports associated with a Python process on that IP.

**Assessment:** The IP is an investigation indicator. The available endpoint evidence does not independently confirm a successful connection or data transfer.

## 4. Investigation Timeline

The timeline is documented separately in [`timeline.md`](../timeline.md).

It records the observed process, file, account discovery, archive, PowerShell, and DLL-related events using the source event timestamps.

## 5. Indicators of Compromise (IOCs)

| Indicator | Value |
|---|---|
| Suspicious file | `C:\Users\Public\splunkd.exe` |
| SHA256 | `BADF4752413CB0CBDC03FB95820CA167F0CDC63B597CCDB5EF43111180E088B0` |
| MD5 | `2B40C98ED0F7A1D3B091A3E8353132DC` |
| SHA1 | `DF79C86FDD11B9CCB89148458E509F879C72566C` |
| IP address | `172.31.234.82` |
| Referenced port | `8888` |
| Archive name | `archive.7z` |
| Suspicious script | `Invoke-Mimikatz.ps1` |

These indicators are based on the supplied dataset and should be validated before being used in a production environment.

## 6. MITRE ATT&CK Mapping

| Technique ID | Technique | Observed evidence |
|---|---|---|
| T1059.001 | PowerShell | PowerShell download and command execution |
| T1059.003 | Windows Command Shell | `cmd.exe` command execution |
| T1087.001 | Account Discovery: Local Account | `net user` |
| T1069.001 | Permission Groups Discovery: Local Groups | `net localgroup` |
| T1560.001 | Archive Collected Data: Archive via Utility | 7-Zip archive command |
| T1003.001 | OS Credential Dumping: LSASS Memory | Mimikatz credential-dumping attempt |
| T1562.001 | Impair Defenses: Disable or Modify Tools | Possible AMSI-related DLL manipulation |

**Note:** These mappings describe the apparent intent of observed commands. They do not confirm successful execution or impact.

## 7. Final Verdict

**True Positive — Suspicious Activity Observed**

The investigation identified multiple suspicious activities on the Windows endpoint, including account discovery, credential-dumping attempts, archive-related commands, suspicious executable execution, and DLL manipulation.

The combination of these behaviours supports classifying the activity as suspicious rather than benign.

However, the available logs do not prove successful credential theft, data exfiltration, persistence, or successful command-and-control communication.

## 8. Recommended Response Actions

If this activity were detected in a production environment:

1. Isolate the affected endpoint from the network while preserving forensic evidence.
2. Escalate the investigation to the appropriate incident response team.
3. Collect and preserve relevant process, file, PowerShell, registry, and network telemetry.
4. Investigate the suspicious executable and validate its hashes using approved security tools.
5. Review account activity and reset potentially exposed credentials if evidence supports exposure.
6. Investigate the IP address and any related network connections.
7. Review system configuration changes and restore security controls if unauthorized modifications are confirmed.
8. Continue monitoring for related suspicious activity.

## 9. Evidence and Supporting Files

Supporting evidence is organised in the project directory:

- `evidence/screenshots/` — Splunk investigation screenshots.
- `evidence/exports/` — CSV exports of relevant search results.
- `searches.md` — Investigation queries.
- `timeline.md` — Chronological event timeline.
- `notes.md` — Investigation notes.

## 10. Conclusion

This investigation demonstrates a structured SOC-style approach to analysing suspicious Windows endpoint activity using Splunk Cloud.

By correlating process execution, file creation, account discovery, PowerShell activity, archive commands, and DLL manipulation, the investigation identified behaviour consistent with a potential attack sequence.

The final assessment is based on the available telemetry, with unconfirmed actions clearly distinguished from observed events.