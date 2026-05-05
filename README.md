📌 MITRE ATT&CK

T1053.005 – Scheduled Task / Job (Windows Task Scheduler)

➡️ Použití
Persistence
Privilege escalation
Malware execution
Execution automation
🔍 1. NEJDŮLEŽITĚJŠÍ LOGY
🥇 OSQuery (nejlepší zdroj)
scheduled_tasks
process_events
windows_events
🥈 Sysmon (Event ID 1 – klíčový)

System Event ID = 1 (Process Create)

➡️ sleduj hlavně:

schtasks.exe
taskeng.exe
cmd.exe chain
🥉 Task Scheduler logs
Event ID 106 → task created
Event ID 140 → modified
Event ID 141 → deleted
⚙️ 2. DETEKČNÍ SIGNATURY
🧨 schtasks activity
schtasks.exe /create
schtasks.exe /change
schtasks.exe /delete
⚠️ Suspicious payloads

Task spouští:

powershell.exe
cmd.exe
mshta.exe
rundll32.exe
wscript / cscript
encoded commands (-enc)
🔥 3. HIGH RISK PATTERN
🚩 Red flags
/ru SYSTEM
/rl HIGHEST
/sc minute
fake názvy („Automatic Updates“)
LOLBins (mshta, powershell)
execution z ProgramData
🧬 4. TYPOVÝ ATTACK FLOW
cmd.exe
   ↓
schtasks.exe /create
   ↓
SYSTEM execution
   ↓
mshta.exe / HTA payload
   ↓
persistence (every minute)
   ↓
schtasks.exe /delete (cleanup)
🧱 5. HOW WAS TASK CREATED?
Klíčové znaky:
Parent: cmd.exe
User: Administrator nebo SYSTEM
Non-interactive session (TerminalSessionId = 0)

➡️ indikace:

script execution
service execution
attacker tooling
🧪 6. BENIGN vs MALICIOUS
❌ BENIGN
scheduled daily/weekly jobs
legit updaters (Adobe, Windows, AV)
žádné mshta / encoded payloads
žádné SYSTEM + minute interval
🚨 MALICIOUS
SYSTEM + HIGHEST
execution každou minutu
mshta / powershell payload
disguised names („Automatic Updates“)
self-delete task
🌐 7. NETWORK INDICATORS
⚠️ Local abuse patterns
\\127.0.0.1\ADMIN$

➡️ indikace:

WMI execution
PsExec-like behavior
lateral movement tooling
Sysmon Event ID 3:
mshta.exe outbound connection
powershell C2 traffic
cmd.exe download activity
🧠 8. KEY SYSTEM EVENT IDs
Event ID	Meaning
1	Process creation (Sysmon)
3	Network connection
106	Task created
140	Task modified
141	Task deleted
4624	Logon
4672	Admin privileges
🧾 9. TYPICAL SPL QUERIES
Find schtasks:
index=metasploitable System.EventID=1 EventData.Image="*\\schtasks.exe"
Suspicious create:
CommandLine="*/create*" OR CommandLine="*mshta*"
Network check:
System.EventID=3 (mshta OR powershell OR cmd.exe)
🧾 10. FINAL INTERVIEW ANSWER TEMPLATE

HOW WAS TASK CREATED?
The scheduled task was created programmatically via cmd.exe using schtasks.exe under Administrator or SYSTEM account in a non-interactive session, indicating scripted or automated execution rather than manual GUI interaction.

WAS IT BENIGN?
No. The combination of SYSTEM execution, high privilege flags, minute-based scheduling, and execution of mshta.exe strongly indicates malicious persistence rather than legitimate administrative activity.

NETWORK ACTIVITY?
No clear external C2 connection was observed; however, unusual local SMB/WMI-style execution via ADMIN$ suggests potential remote execution tooling behavior.

🚀 ONE-LINE SUMMARY

T1053.005 = schtasks abuse + SYSTEM execution + LOLBins + suspicious scheduling + optional WMI/SMB artifacts
