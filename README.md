# 🧠 CHEAT SHEET – T1053.005 (Scheduled Tasks Detection)

## 📌 MITRE ATT&CK
**T1053.005 – Scheduled Task / Job (Windows Task Scheduler)**

### Use Case
- Persistence  
- Privilege escalation  
- Malware execution  
- Execution automation  

---

# 🔍 1. KEY LOGS TO MONITOR

## 🥇 OSQuery (primary source)
- scheduled_tasks  
- process_events  
- windows_events  

## 🥈 Sysmon (critical)
**Event ID 1 – Process Creation**

Monitor:
- `schtasks.exe`
- `taskeng.exe`
- `cmd.exe`

## 🥉 Task Scheduler Logs
| Event ID | Meaning |
|----------|--------|
| 106 | Task created |
| 140 | Task modified |
| 141 | Task deleted |

---

# ⚙️ 2. DETECTION SIGNATURES

## schtasks activity
```text
schtasks.exe /create
schtasks.exe /change
schtasks.exe /delete
Suspicious payload execution

Tasks launching:

powershell.exe
cmd.exe
mshta.exe
rundll32.exe
wscript.exe
cscript.exe
encoded commands (-enc)
🚩 3. HIGH RISK INDICATORS
/ru SYSTEM
/rl HIGHEST
/sc minute
Fake task names (e.g. “Automatic Updates”)
LOLBins usage (mshta, powershell)
Execution from ProgramData
🧬 4. TYPICAL ATTACK FLOW
cmd.exe
   ↓
schtasks.exe /create
   ↓
SYSTEM execution
   ↓
mshta.exe (payload execution)
   ↓
persistence (minute-based execution)
   ↓
schtasks.exe /delete (cleanup)
🧱 5. TASK CREATION ANALYSIS
Key Indicators
Parent process: cmd.exe
User: Administrator / SYSTEM
Session: non-interactive (TerminalSessionId = 0)
Interpretation
Scripted execution
Service-based execution
Attacker tooling
🧪 6. BENIGN vs MALICIOUS
✅ Benign activity
Scheduled daily/weekly jobs
Windows / AV / software updaters
No encoded payloads
No SYSTEM + minute execution
🚨 Malicious activity
SYSTEM + HIGHEST privileges
Execution every minute
mshta / PowerShell payloads
Disguised task names
Self-deleting tasks
🌐 7. NETWORK INDICATORS
Suspicious patterns
\\127.0.0.1\ADMIN$
Possible techniques
WMI execution
PsExec-like behavior
Lateral movement tooling
Sysmon Event ID 3
mshta.exe outbound connections
PowerShell C2 traffic
cmd.exe download activity
🧠 8. KEY EVENT IDS
Event ID	Source	Meaning
1	Sysmon	Process creation
3	Sysmon	Network connection
106	Task Scheduler	Task created
140	Task Scheduler	Task modified
141	Task Scheduler	Task deleted
4624	Security	Logon
4672	Security	Admin privileges
🧾 9. SPL QUERIES
Find schtasks execution
index=metasploitable System.EventID=1 EventData.Image="*\\schtasks.exe"
Suspicious task creation
CommandLine="*/create*" OR CommandLine="*mshta*"
Network activity check
System.EventID=3 (mshta OR powershell OR cmd.exe)
🧾 10. INTERVIEW ANSWER TEMPLATE
How was the task created?

The scheduled task was created programmatically via cmd.exe using schtasks.exe under an Administrator or SYSTEM account in a non-interactive session, indicating scripted or automated execution rather than manual GUI interaction.

Was it benign?

No. The combination of SYSTEM execution, high privileges, minute-based scheduling, and execution of mshta.exe strongly indicates malicious persistence activity.

Network activity?

No direct external C2 connection was observed; however, local SMB/WMI-like execution via ADMIN$ suggests possible remote execution tooling behavior.

🚀 SUMMARY

T1053.005 = schtasks abuse + SYSTEM execution + LOLBins + suspicious scheduling + optional WMI/SMB artifacts

🚩 3. HIGH RISK INDICATORS
/ru SYSTEM
/rl HIGHEST
/sc minute
Fake task names (e.g. “Automatic Updates”)
LOLBins usage (mshta, powershell)
Execution from ProgramData
🧬 4. TYPICAL ATTACK FLOW
cmd.exe
   ↓
schtasks.exe /create
   ↓
SYSTEM execution
   ↓
mshta.exe (payload execution)
   ↓
persistence (minute-based execution)
   ↓
schtasks.exe /delete (cleanup)
🧱 5. TASK CREATION ANALYSIS
Key Indicators
Parent process: cmd.exe
User: Administrator / SYSTEM
Session: non-interactive (TerminalSessionId = 0)
Interpretation
Scripted execution
Service-based execution
Attacker tooling
🧪 6. BENIGN vs MALICIOUS
✅ Benign activity
Scheduled daily/weekly jobs
Windows / AV / software updaters
No encoded payloads
No SYSTEM + minute execution
🚨 Malicious activity
SYSTEM + HIGHEST privileges
Execution every minute
mshta / PowerShell payloads
Disguised task names
Self-deleting tasks
🌐 7. NETWORK INDICATORS
Suspicious patterns
\\127.0.0.1\ADMIN$
Possible techniques
WMI execution
PsExec-like behavior
Lateral movement tooling
Sysmon Event ID 3
mshta.exe outbound connections
PowerShell C2 traffic
cmd.exe download activity
🧠 8. KEY EVENT IDS
Event ID	Source	Meaning
1	Sysmon	Process creation
3	Sysmon	Network connection
106	Task Scheduler	Task created
140	Task Scheduler	Task modified
141	Task Scheduler	Task deleted
4624	Security	Logon
4672	Security	Admin privileges
🧾 9. SPL QUERIES
Find schtasks execution
index=metasploitable System.EventID=1 EventData.Image="*\\schtasks.exe"
Suspicious task creation
CommandLine="*/create*" OR CommandLine="*mshta*"
Network activity check
System.EventID=3 (mshta OR powershell OR cmd.exe)
🧾 10. INTERVIEW ANSWER TEMPLATE
How was the task created?

The scheduled task was created programmatically via cmd.exe using schtasks.exe under an Administrator or SYSTEM account in a non-interactive session, indicating scripted or automated execution rather than manual GUI interaction.

Was it benign?

No. The combination of SYSTEM execution, high privileges, minute-based scheduling, and execution of mshta.exe strongly indicates malicious persistence activity.

Network activity?

No direct external C2 connection was observed; however, local SMB/WMI-like execution via ADMIN$ suggests possible remote execution tooling behavior.

🚀 SUMMARY

T1053.005 = schtasks abuse + SYSTEM execution + LOLBins + suspicious scheduling + optional WMI/SMB artifacts
---
