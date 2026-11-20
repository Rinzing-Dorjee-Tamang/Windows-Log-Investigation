# Windows APT Log Investigation — Event Timeline

**Host:** `windows-apt-2025`  
**Affected User:** `DESKTOP-QGB4EQH\mari`  
**Activity Date:** 22 December 2024  
**Time Reference:** Splunk display timestamps

| No. | Timestamp | Process / Activity | Observed Evidence | Security Significance |
|---:|---|---|---|---|
| 1 | 09:04:52.929 | Executable creation | PowerShell created `C:\Users\Public\splunkd.exe` (Sysmon Event ID 11) | Initial observed creation of the suspicious executable |
| 2 | 10:34:46.322 | Executable creation | PowerShell created `C:\Users\Public\splunkd.exe` again | Repeated executable creation |
| 3 | 10:42:14.759 | Executable creation | Another file creation event for `splunkd.exe` | Continued suspicious file activity |
| 4 | 11:04:04.191 | Executable creation | Another file creation event for `splunkd.exe` | Repeated creation of the same executable |
| 5 | 12:07:06.794 | Account and system discovery | `cmd.exe` executed `net user`, `cmdkey.exe /list`, `net localgroup` and directory listing commands | Local account, group and saved-credential discovery |
| 6 | 12:09:28.140 | Archive-related activity | Commands checked/installed 7-Zip, created test files and executed `7z.exe u archive.7z *txt -pblue` | Archive creation/update attempt; success unconfirmed |
| 7 | 12:12:22.460 | VBS script execution | Script executed `whoami` | User-context discovery |
| 8 | 12:12:25.541 | PowerShell file manipulation | PowerShell was copied to `%APPDATA%\updater.exe`; `amsi.dll` was copied to AppData | Suspicious executable and DLL manipulation |
| 9 | 12:12:33.671 | Credential-dumping attempt | PowerShell downloaded `Invoke-Mimikatz.ps1` and attempted `Invoke-Mimikatz -DumpCreds` | Possible credential access; successful extraction unconfirmed |
| 10 | 12:13:48.115 | DLL and registry manipulation | `amsi.dll` was renamed to `WinAppXRT.dll`, copied into System32 and associated registry modification activity was observed | Possible security-control evasion; successful effect unconfirmed |
| 11 | 12:13:51.828 | PowerShell function definitions | PowerShell defined PowerSploit-style function names; output included `Pretending to invoke` | Placeholder execution; actual execution of the named tools not established |
| 12 | 12:14:59.952 | DLL and service configuration | DLL was renamed to `ualapi.dll`, copied into System32 and `sc config Spooler start=auto` was executed | Possible security-control and service configuration changes; success unconfirmed |
| 13 | 12:55:44.181 | Executable creation | PowerShell created `C:\Users\Public\splunkd.exe` (Sysmon Event ID 11) | Further creation of the suspicious executable |
| 14 | 14:10:34.874–14:11:46.822 | Further DLL-related activity | Additional similar DLL copying/renaming and registry/service commands were observed | Continued suspicious manipulation |
| 15 | 14:13:45.660 | Further DLL-related activity | Another similar DLL and registry/service-related activity was observed | Continued suspicious activity; successful changes unconfirmed |

## Network Investigation Note

The suspicious executable referenced:

`172.31.234.82:8888`

A search for this IP address returned 13 events. Additional collected output showed listening ports associated with `7427/python3` on that address.

However, the available results did not establish a successful connection from the Windows endpoint to the referenced address.

## Timeline Assessment

The observed sequence includes repeated creation of a suspicious executable, account and system discovery, archive-related activity, PowerShell execution, a credential-dumping attempt and DLL/service manipulation.

These events support a True Positive assessment for suspicious activity in the supplied lab logs. They do not independently establish successful credential theft, persistence, command-and-control communication or data exfiltration.

**Timestamp note:** The table uses Splunk display timestamps recorded during the investigation. These may differ from the raw UTC timestamps in the event data.