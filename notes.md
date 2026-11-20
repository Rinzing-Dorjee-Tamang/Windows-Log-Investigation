# Windows APT Log Investigation — Working Notes

## 1. Investigation Context

- **Project:** Windows APT Log Investigation
- **Platform:** Splunk Cloud
- **Source file:** `22-December.csv`
- **Sourcetype:** `csv`
- **Host:** `windows-apt-2025`
- **Affected user:** `DESKTOP-QGB4EQH\mari`
- **Log date:** 22 December 2024
- **Log type:** Windows endpoint events, including Sysmon/Wazuh-style records

**Note:** Timestamps below are Splunk display timestamps unless otherwise stated.

## 2. Suspicious Executable

- **Filename:** `splunkd.exe`
- **Location:** `C:\Users\Public\splunkd.exe`
- **SHA256:** `BADF4752413CB0CBDC03FB95820CA167F0CDC63B597CCDB5EF43111180E088B0`
- **MD5:** `2B40C98ED0F7A1D3B091A3E8353132DC`
- **SHA1:** `DF79C86FDD11B9CCB89148458E509F879C72566C`

Observed command-line arguments:

`-server http://172.31.234.82:8888 -group red`

The executable was located in `C:\Users\Public\` and appeared as the parent process of multiple suspicious activities.

**Assessment:** The executable's location, command-line arguments and child-process activity made it suspicious. Its maliciousness was not independently established through reputation analysis.

## 3. File Creation Activity

Five Sysmon Event ID 11 records showed PowerShell creating:

`C:\Users\Public\splunkd.exe`

Observed timestamps:

- 09:04:52.929
- 10:34:46.322
- 10:42:14.759
- 11:04:04.191
- 12:55:44.181

**Assessment:** Repeated creation of the executable was observed.

## 4. Account and System Discovery

**Timestamp:** 12:07:06.794

A `cmd.exe` process executed:

- `net user`
- `dir C:\Users\`
- `cmdkey.exe /list`
- `net localgroup "Users"`
- `net localgroup`

**Assessment:** These commands were used to enumerate local accounts, user directories, saved credentials and group membership.

## 5. Archive-Related Activity

**Timestamp:** 12:09:28.140

A `cmd.exe` process executed commands that:
- Checked for or installed 7-Zip.
- Created an Atomic Red Team test directory.
- Wrote `encrypted_file.txt`.
- Ran `7z.exe u archive.7z *txt -pblue`.

**Assessment:** An archive creation/update attempt was observed. Successful archive creation was not confirmed.

## 6. Script and PowerShell Activity

**Timestamp:** 12:12:22.460

A VBS script executed `whoami`.

**Timestamp:** 12:12:25.541

Observed activity included:
- Copying PowerShell to `%APPDATA%\updater.exe`.
- Copying `amsi.dll` to `%APPDATA%\amsi.dll`.
- Running `updater.exe` with `-Command exit`.

**Assessment:** These file and process operations were suspicious and required investigation. Their intended effect was not established.

## 7. Credential-Dumping Attempt

**Timestamp:** 12:12:33.671

PowerShell:
- Downloaded `Invoke-Mimikatz.ps1` from GitHub.
- Attempted to execute `Invoke-Mimikatz -DumpCreds`.

A separate event at 12:13:51.828 showed PowerShell defining function names such as `Invoke-Mimikatz`, `PowerView` and `Get-Keystrokes`. Their function bodies printed messages such as `Pretending to invoke`.

**Assessment:** A credential-dumping attempt was observed. The placeholder functions do not establish that the named tools actually executed. Successful credential extraction was not confirmed.

## 8. DLL and Registry Manipulation

Observed activity included:
- Copying `amsi.dll`.
- Renaming copies to `WinAppXRT.dll` and `ualapi.dll`.
- Copying renamed files into `C:\Windows\System32\`.
- Adding the registry value `APPX_PROCESS=1` under `HKCU\Environment`.

Related activity appeared around 12:12:33.671 and 12:13:48.115, with further similar activity later.

**Assessment:** These operations may indicate an attempt at security-control evasion or AMSI-related manipulation. Successful bypass was not confirmed.

## 9. Service Configuration

**Timestamp:** 12:14:59.952

Observed command:

`sc config Spooler start=auto`

Further similar DLL and service-related activity appeared later.

**Assessment:** A service configuration change was attempted. Successful modification was not confirmed.

## 10. Network Investigation

The suspicious executable's command line referenced:

`172.31.234.82:8888`

Searches for `172.31.234.82` returned 13 events.

Other collected output showed listening ports on `172.31.234.82` associated with `7427/python3`, including TCP ports 8022 and 8888 and UDP port 8853.

A search for:

`source_data_win_system_eventID=3`

returned zero matching events.

**Assessment:** The available results did not confirm a successful connection from the Windows endpoint to the referenced address. Listening-port output alone is not proof of endpoint communication.

## 11. Investigation Limitations

The available logs do not establish:

- Successful credential extraction.
- Successful archive creation.
- Successful AMSI bypass or DLL replacement.
- Successful service configuration changes.
- Successful communication with the referenced server.
- Successful data exfiltration.

Commands and attempts must not be presented as confirmed outcomes.

## 12. Preliminary Verdict

**True Positive — Suspicious activity observed.**

The logs contain multiple suspicious process and command-line activities, including account discovery, archive-related commands, a credential-dumping attempt and DLL manipulation.

The evidence supports identifying the activity as suspicious, but does not establish that every attempted action succeeded.

This project is a hands-on investigation of supplied lab logs, not evidence of a confirmed real-world compromise.