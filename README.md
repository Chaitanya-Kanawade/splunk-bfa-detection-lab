# Brute Force Attack Detection in Splunk Lab

## Overview

This project demonstrates the simulation and detection of a brute-force authentication attack in an isolated SOC lab environment using:

- Kali Linux
- Windows VM
- Splunk Enterprise (SIEM)
- VirtualBox

## Objective

To understand how Security Operations Centers detect brute-force login attacks by monitoring Windows Security Event Logs in Splunk, and to build detection queries that surface repeated failed logon attempts followed by a successful login.

---

## Lab Architecture

```
Kali Linux (Attacker)
        |
        v
Windows VM (Target - Security Event Logs)
        |
        v
Splunk SIEM (Detection & Analysis)
```

---

## Attack Simulation

Performed multiple failed login attempts from Kali Linux against the Windows VM using SMB-based credential brute-forcing, followed by a final successful login to simulate a real-world compromised-credential scenario.

[![Brute force attack execution](https://github.com/Chaitanya-Kanawade/splunk-bfa-detection-lab/raw/main/screenshot/BFA_Execution.png)](/Chaitanya-Kanawade/splunk-bfa-detection-lab/blob/main/screenshot/BFA_Execution.png)
*Executing the brute-force attack from Kali Linux against the Windows target*

---

## Detection Logic

Windows Security Event Logs were monitored in Splunk using:

- **Event ID 4625** → Failed Login Attempt
- **Event ID 4624** → Successful Login Attempt

---

## Detection Results

### Failed Login Attempts (Event ID 4625)

```
index=main source="WinEventLog:Security" EventCode=4625
| table _time Account_Name Source_Network_Address
```

[![Failed login attempts](https://github.com/Chaitanya-Kanawade/splunk-bfa-detection-lab/raw/main/screenshot/Failed_login_Attempts.png)](/Chaitanya-Kanawade/splunk-bfa-detection-lab/blob/main/screenshot/Failed_login_Attempts.png)
*Splunk results showing multiple failed login attempts (Event ID 4625) from the attacker's IP*

### Successful Login Attempts (Event ID 4624)

```
index=main source="WinEventLog:Security" EventCode=4624
| table _time Account_Name Source_Network_Address
```

[![Successful login attempts](https://github.com/Chaitanya-Kanawade/splunk-bfa-detection-lab/raw/main/screenshot/Successful_login_Attempts.png)](/Chaitanya-Kanawade/splunk-bfa-detection-lab/blob/main/screenshot/Successful_login_Attempts.png)
*Splunk results showing the successful login (Event ID 4624) that followed the failed attempts*

### Top Accounts/Sources by Failed Login Count

```
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name Source_Network_Address
| sort - count
```

[![Sorted list of failed login attempts](https://github.com/Chaitanya-Kanawade/splunk-bfa-detection-lab/raw/main/screenshot/Sorted_List_Of_Attempts.png)](/Chaitanya-Kanawade/splunk-bfa-detection-lab/blob/main/screenshot/Sorted_List_Of_Attempts.png)
*Failed login attempts aggregated and sorted by count, highlighting the account and source IP under brute-force attack*

### Advanced Detection: Brute Force Followed by Successful Login

```
index=main source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624)
| transaction Account_Name Source_Network_Address startswith=(EventCode=4625) endswith=(EventCode=4624) maxspan=10m
| where eventcount > 1
```

This query correlates repeated failed logons with a subsequent successful login from the same account and source within a 10-minute window — a strong indicator of a successful credential brute-force attack.

---

## Tools Used

- Splunk Enterprise
- Kali Linux
- Windows VM (Security Event Logging)
- VirtualBox

---

## MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Brute Force | T1110 |

---

## Key Learning Outcomes

- Hands-on understanding of how brute-force credential attacks appear in Windows Security Event Logs
- Building and configuring an isolated SOC lab (Kali Linux, Windows VM, Splunk)
- Writing SPL detection queries using Event IDs 4624 and 4625
- Correlating failed and successful logon events to detect compromised credentials
- Mapping detection logic to the MITRE ATT&CK framework
- End-to-end SOC workflow: simulate → log → ingest → detect → visualize
