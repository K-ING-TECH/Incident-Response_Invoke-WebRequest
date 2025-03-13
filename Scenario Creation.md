# Threat Event: Malicious PowerShell Web Requests

**Attackers Utilizing Legitimate PowerShell Commands to Download & Execute Suspicious Scripts**

---

## Steps the "Bad Actor" Took to Create Logs & IoCs

1. **Leverage PowerShell for External Downloads**  
   The adversary (or user unknowingly) uses PowerShell’s `Invoke-WebRequest` command to download malicious or testing scripts from a **GitHub** repository, blending into legitimate system activity.

2. **Drop Scripts on Target System**  
   Four separate scripts—**portscan.ps1**, **eicar.ps1**, **exfiltratedata.ps1**, and **pwncrypt.ps1**—were saved to **C:\programdata\** on the compromised machine (**windows-target-1**).

3. **Execute the Downloaded Scripts**  
   Each script runs locally, creating:
   - Log entries in **DeviceProcessEvents**  
   - Potential follow-on actions (network scanning, data exfiltration simulation, ransom encryption)

4. **Post-Exploitation Activities**  
   Once scripts are successfully invoked, the attacker (or the script itself) can:
   - Perform reconnaissance with `portscan.ps1`
   - Simulate malicious behavior or data exfiltration with `exfiltratedata.ps1`
   - Test AV detection using `eicar.ps1`
   - Encrypt files and leave a ransom note with `pwncrypt.ps1`

---

## Tables Used to Detect IoCs

| **Parameter** | **Description**                                                                                                                        |
|---------------|----------------------------------------------------------------------------------------------------------------------------------------|
| **Name**      | DeviceProcessEvents                                                                                                                    |
| **Info**      | [MS Docs: DeviceProcessEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table)                |
| **Purpose**   | Logs the details of all processes executed, including PowerShell usage. Critical for detecting suspicious commands like `Invoke-WebRequest`. |

| **Parameter** | **Description**                                                                                                                |
|---------------|-------------------------------------------------------------------------------------------------------------------------------|
| **Name**      | DeviceFileEvents                                                                                                               |
| **Info**      | [MS Docs: DeviceFileEvents Table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)      |
| **Purpose**   | Identifies file creation, modification, or deletion on endpoints. Useful for tracking the downloaded scripts (`.ps1` files).   |

---

## Related Queries

```kql
// Detecting PowerShell Download Actions
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where InitiatingProcessCommandLine contains "invoke-webrequest"
| project Timestamp=TimeGenerated, AccountName, DeviceName, ProcessCommandLine, FolderPath
| order by Timestamp desc
```

```
// Confirming Script Execution Locally
let ScriptNames = dynamic(["eicar.ps1", "exfiltratedata.ps1", "portscan.ps1", "pwncrypt.ps1"]);
DeviceProcessEvents
| where DeviceName == "windows-target-1"
| where ProcessCommandLine contains "-File" 
      and InitiatingProcessCommandLine has_any (ScriptNames)
| project TimeGenerated, AccountName, DeviceName, ProcessCommandLine
| order by TimeGenerated asc
```

```
// Monitoring for Potential Data Exfiltration
DeviceNetworkEvents
| where DeviceName == "windows-target-1"
| where RemoteUrl has_any ("blob.core.windows.net", "pastebin.com", "mega.nz", "transfer.sh", "gofile.io")
| project TimeGenerated, DeviceName, InitiatingProcessCommandLine, RemoteUrl
```

### Possible Outcomes
- Malicious Use of PowerShell

- Scripts downloaded & executed for malicious tasks (e.g., exfiltration, ransomware).
#### Containment: Isolate machine, remove malicious files, reimage if necessary.
Benign Testing / User Ignorance

User may be testing EICAR or running random scripts without malicious intent.

Remediate via awareness training, restricting usage of Invoke-WebRequest for non-admin accounts.
### NIST 800-61 Alignment
#### Preparation

- Ensure Defender for Endpoint and Sentinel are ingesting DeviceProcessEvents and DeviceFileEvents
- Maintain robust user awareness programs
#### Detection & Analysis

- Alert triggers when Invoke-WebRequest is used to fetch scripts from unknown or external sources
- Investigate if the commands are user-initiated or malicious
#### Containment, Eradication & Recovery

- Contain by isolating the endpoint, running full AV scans, removing suspicious .ps1 files
- Eradicate any malicious footholds by reimaging and redeploying the system
- Recover by applying stricter policy controls on PowerShell usage, training the user
#### Post-Incident Activity

- Lessons Learned: Evaluate baseline policies around PowerShell and enforce app controls.
- Policy Updates: Limit Invoke-WebRequest usage, enhance logging/alerting, and upgrade user awareness training
### Summary
This scenario demonstrates an attacker leveraging PowerShell’s Invoke-WebRequest to download multiple suspicious scripts onto **windows-target-1**. 

Each script, once executed, represents a different stage of a potential attack—ranging from port scanning to data exfiltration or ransomware simulation. 

Microsoft Defender for Endpoint and Sentinel telemetry (particularly DeviceProcessEvents) captured the entire sequence, enabling a quick response following **NIST 800-61** guidelines. 

By isolating the device, eradicating malicious files, and tightening PowerShell policies, organizations can effectively thwart or mitigate similar threats in the future.
