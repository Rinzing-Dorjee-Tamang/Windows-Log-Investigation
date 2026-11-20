# Splunk Investigation Searches

**Platform:** Splunk Cloud  
**Dataset:** Windows-APT 2025  
**Index:** `main`  
**Source:** `22-December.csv`  
**Host under investigation:** `window-agent3`  
**Time range used:** All time, unless stated otherwise

---

1. Identify Available Hosts

**Purpose:** Identify the endpoint names and event counts in the supplied dataset.

**Query:**

```spl
index=main source="22-December.csv"
| stats count by source_agent_name
```

**Result:**
- `window-agent3`: 717 events
- Other hosts were also present in the dataset.

**Analysis:** Identified `window-agent3` as the endpoint selected for further investigation.

---

2. Identify High-Severity Alerts

**Purpose:** Check the number of events classified at Wazuh rule level 12.

**Query**

```spl
index=main source="22-December.csv"
| search source_rule_level=12
| stats count
```

**Result:** 77 events.

**Analysis:** These higher-severity events provided a starting point for examining suspicious endpoint activity.

---

3. Investigate Processes Launched by the Suspicious Parent

**Purpose:** Identify processes whose parent image was `splunkd.exe` and inspect their command lines.

**Query**

```spl
index=main source="22-December.csv" source_agent_name="window-agent3" source_data_win_eventdata_parentImage="*splunkd.exe"
| table source__timestamp source_data_win_eventdata_user source_data_win_eventdata_parentImage source_data_win_eventdata_parentCommandLine source_data_win_eventdata_image source_data_win_eventdata_commandLine
| sort 0 source__timestamp
```

**Result:** 11 events.

**Important observations:**
- Parent executable: `C:\Users\Public\splunkd.exe`
- Parent command line included: `-server http://172.31.234.82:8888 -group red`
- Related activity included account discovery, archive-related commands and PowerShell execution.

**Analysis:** The unusual executable location and its child-process activity justified further investigation.

---

4. Investigate File Creation — Sysmon Event ID 11

**Purpose:** Identify file creation events involving `splunkd.exe`.

**Query**

```spl
index=main source="22-December.csv" source_agent_name="window-agent3" source_data_win_system_eventID=11 source_data_win_eventdata_targetFilename="*splunkd.exe"
| table source__timestamp source_data_win_eventdata_image source_data_win_eventdata_targetFilename
| sort 0 source__timestamp
```

**Result:** 5 events.

**Observed timestamps:**
- 09:04:52.929
- 10:34:46.322
- 10:42:14.759
- 11:04:04.191
- 12:55:44.181

**Analysis:** The events showed PowerShell creating `C:\Users\Public\splunkd.exe` at five different times.

---

5. Investigate Account Discovery Commands

**Purpose:** Find commands involving `net user` and examine the associated process details.

**Query**

```spl
index=main source="22-December.csv" source_agent_name="window-agent3" source_data_win_eventdata_commandLine="*net user*"
| table source__timestamp source_data_win_eventdata_user source_data_win_eventdata_parentImage source_data_win_eventdata_image source_data_win_eventdata_commandLine
| sort 0 source__timestamp
```

**Result:** 15 events.

**Important observations:**
Commands included:
- `net user`
- `net localgroup`
- `cmdkey.exe /list`
- `dir C:\Users\`

**Analysis:** The commands were consistent with account, group and saved-credential discovery.

---

6. Investigate PowerShell Activity

**Purpose:** Find PowerShell process events and inspect their parent processes and command lines.

**Query**

```spl
index=main source="22-December.csv" source_agent_name="window-agent3" source_data_win_eventdata_image="*powershell.exe"
| table source__timestamp source_data_win_eventdata_user source_data_win_eventdata_parentImage source_data_win_eventdata_commandLine
| sort 0 source__timestamp
```

**Result:** 38 events.

**Analysis:** The results provided PowerShell activity for further investigation, including suspicious script execution and DLL-related commands.

---

7. Investigate DownloadString and Mimikatz Activity

**Purpose:** Search for PowerShell commands containing `DownloadString` or `Invoke-Mimikatz`.

**Query**

```spl
index=main source="22-December.csv" source_agent_name="window-agent3"
| search source_data_win_eventdata_commandLine="*DownloadString*" OR source_data_win_eventdata_commandLine="*Invoke-Mimikatz*"
| table source__timestamp source_data_win_eventdata_user source_data_win_eventdata_parentImage source_data_win_eventdata_image source_data_win_eventdata_commandLine
| sort 0 source__timestamp
```

**Result:** 2 events.

**Important observations:**
- 09:12:33.671 — PowerShell download command followed by an `Invoke-Mimikatz -DumpCreds` attempt.
- 09:13:51.828 — PowerShell activity defining function names, including `Invoke-Mimikatz`, with placeholder output such as `Pretending to invoke`.

**Analysis:** Credential-dumping activity was attempted, but successful credential extraction was not established.

---

8. Investigate Credential-Related Activity

**Purpose:** Examine the two credential-related events returned by the investigation and distinguish actual command attempts from placeholder execution.

**Query**

```spl
index=main source="22-December.csv" source_agent_name="window-agent3"
| search source_data_win_eventdata_commandLine="*DownloadString*" OR source_data_win_eventdata_commandLine="*Invoke-Mimikatz*"
| table source__timestamp source_data_win_eventdata_user source_data_win_eventdata_parentImage source_data_win_eventdata_image source_data_win_eventdata_commandLine
| sort 0 source__timestamp
```

**Result:** 2 events.

**Analysis:** This search returned the same two relevant events documented in the previous section. The first showed a Mimikatz invocation attempt; the second contained placeholder functions. Neither result proves successful credential extraction.

---

9. Investigate LSASS-Related Activity

**Purpose:** Search for events referencing `lsass.exe` in image and target fields.

**Query**

```spl
index=main source="22-December.csv" source_agent_name="window-agent3"
| search source_data_win_eventdata_targetImage="*lsass.exe" OR source_data_win_eventdata_targetFilename="*lsass*" OR source_data_win_eventdata_image="*lsass.exe"
| table source__timestamp source_data_win_system_eventID source_data_win_eventdata_image source_data_win_eventdata_targetImage source_data_win_eventdata_targetFilename source_data_win_eventdata_accessMask
| sort 0 source__timestamp
```

**Result:** The result count was not recorded in the recovered investigation notes.

**Analysis:** This query was intended to check for LSASS-related process or file activity. Do not treat the search itself as proof of credential dumping.

---

10. Search for Archive-Related Activity

**Purpose:** Find events containing the archive filename.

**Query**

```spl
index=* "archive.7z"
```

**Time range:** All time.

**Result:** 1 event.

**Observation:** The event contained a 7-Zip command updating `archive.7z` with text files and a password.

**Analysis:** An archive creation/update attempt was observed. Successful creation was not confirmed.

---

11. Search for the Suspicious Network Address

**Purpose:** Find events containing the address referenced in the suspicious executable's command line.

**Query**

```spl
index=* "172.31.234.82"
```

**Time range:** All time.

**Result:** 13 events.

**Analysis:** The address appeared in the collected logs. These results alone did not confirm a successful connection from the investigated endpoint.

---

12. Search for the Address and Port Together

**Purpose:** Narrow the search to events containing both the suspicious address and port `8888`.

**Query**

```spl
index=* "172.31.234.82" "8888"
```

**Time range:** All time.

**Result:** 13 events.

**Analysis:** The matching events contained the address and port combination. This did not independently establish successful endpoint-to-server communication.

---

13. Check for Sysmon Network Connection Events

**Purpose:** Check for matching Sysmon Event ID 3 records.

**Query**

```spl
index=* source_data_win_system_eventID=3
```

**Time range:** All time.

**Result:** 0 events.

**Analysis:** No matching records were returned by this query. This does not prove that no network communication occurred.

---

## Investigation Summary

The searches identified:
- 717 events associated with `window-agent3`.
- 77 events at Wazuh rule level 12.
- 11 events involving the suspicious `splunkd.exe` parent process.
- 5 file creation events involving `splunkd.exe`.
- 15 account-discovery-related events.
- 38 PowerShell process events.
- 2 events involving `DownloadString` or `Invoke-Mimikatz`.
- Archive-related activity and references to `172.31.234.82`.

**Overall assessment:** The collected logs show suspicious attacker-like activity. Several commands indicate attempted actions, but their successful outcomes were not established.