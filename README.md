# Brute Force Attack Detection in Splunk Lab

## Overview
Built a hands-on SOC detection lab using Kali Linux, Windows VM, and Splunk SIEM to simulate brute force login attacks and detect suspicious authentication events.

## Objective
To understand how Security Operations Centers detect brute force attacks using Windows logs and SIEM monitoring.

## Lab Environment
- Kali Linux (Attacker Machine)
- Windows VM (Target Machine)
- Splunk Enterprise (SIEM)
- VirtualBox

## Attack Simulation
Performed multiple failed SMB login attempts from Kali Linux to Windows using security testing tools.

## Detection Logic
Monitored Windows Security Event Logs in Splunk using:

- Event ID 4625 → Failed Login Attempt
- Event ID 4624 → Successful Login

## Sample Splunk Query

```spl
index=main source="WinEventLog:Security" EventCode=4625
| stats count by Account_Name Source_Network_Address
| sort - count
