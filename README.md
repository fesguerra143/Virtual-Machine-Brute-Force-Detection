

# Virtual Machine Brute Force Detection 
## 🛡️ Incident Response: Brute-Force Attempts Detected

# Objective:
Identify and analyze potential brute-force logon attempts across the environment.

---
# Tools & Technology:
- Azure Virtual Machine
- Microsoft Sentinel
- Log Analytics Workspace
- KQL Query

---
# Table of contents

- [1. Summary](#1-summary)
- [2. Preparation](#2-preparation)
- [3. Data Collection](#3-data-collection)
- [4. Data Analysis](#4-data-analysis)
- [5. Investigation](#5-investigation)
- [6. Response](#6-response)
- [7. MITRE ATT&CK Mapping](#7-mitre-attck-mapping)
- [8. Lessons Learned / Improvement:](#8-lessons-learned--improvement)
- [9. Final Status](#9-final-status)
  
---



## 1. Summary
Date of Notes: June 21, 2025 <br />
Incident Type: Brute-Force Logon Attempts <br />
Status: Contained <br />


## 2. Initial Detection & Analysis
### Methodology:
An analytics rule (potentially in Microsoft Sentinel) was configured to detect a high volume of failed logon attempts. The following Kusto Query Language (KQL) query was utilized to identify devices experiencing a significant number of LogonFailed events within a 5-hour window:

```kql
DeviceLogonEvents
| where TimeGenerated >= ago(5h)
| where ActionType == "LogonFailed"
| summarize NumberOfFailures = count() by RemoteIP, ActionType, DeviceName
| where NumberOfFailures >= 10

```
![loganalytics1](https://github.com/user-attachments/assets/0bebfefd-9528-4265-adc0-0e091d19dbc6)

<img width="600" src="https://github.com/user-attachments/assets/0bebfefd-9528-4265-adc0-0e091d19dbc6" />

### Microsoft Sentinel: Configuration → Analytics Rule Creation
#### General Settings:
![analyticrulecreation1](https://github.com/user-attachments/assets/6c5e6703-b27d-474c-ad29-b778f9670970)

#### Set rule logic Settings:
![analyticrulecreation2](https://github.com/user-attachments/assets/d5f943cc-c7f0-4264-92bb-993c3b4f903d)

#### Incident Settings:

![analyticrulecreation3](https://github.com/user-attachments/assets/01a56ba6-c909-423b-9778-ce9994960127)


#### Review and Create: 
![analyticrulecreation4](https://github.com/user-attachments/assets/282d098e-0d13-44c4-9072-fc3fcbb969ef)

### Microsoft Sentinel: Threat Management → Incidents

