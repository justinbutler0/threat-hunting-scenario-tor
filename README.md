<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-05-09T06:21:23.170917Z`. These events began at `2025-05-09T06:00:01.0320115Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "wnx-2"
| where InitiatingProcessAccountName contains "RoidRagner"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-05-09T06:00:01.0320115Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName
```
<![image](https://github.com/user-attachments/assets/276813d6-1f2f-4907-8186-ad14583f1275)
>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-05-09T05:59:41.5704521Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.5.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "wnx-2"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.1.exe"
| project Timestamp, DeviceName, ActionType, FileName,FolderPath, SHA256, ProcessCommandLine, AccountName
```
<![image](https://github.com/user-attachments/assets/f0d148d5-fa8f-44ab-89d4-b7a549fcf3ba)
>

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2025-05-09T06:09:50.7465523Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "wnx-2"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe", "tor-launcher.exe", "start-tor-browser.exe", "tor-browser-setup.exe", "torbrowser-install.exe", "tor-browser-windows.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/d528addf-2013-4eb6-b3f1-fc5f2b1fa337)
>

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-05-09T06:10:00.7655826Z`, an employee on the "wnx-2" device successfully established a connection to the remote IP address `185.184.71.94` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "wnx-2"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9050", "9051", "9150", "9151", "9500", "9501")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<![image](https://github.com/user-attachments/assets/8e0a9201-6e67-43a7-8de0-4dfa5e50656f)>

---

## Chronological Event Timeline 

# Detailed Timeline of Tor Browser-Related Activities

### May 8, 2025 - 10:59 PM:
- **User:** 'RoidRagner' downloaded the Tor Browser installer named `tor-browser-windows-x86_64-portable-14.5.1.exe` to the Downloads folder (`C:\Users\RoidRagner\Downloads`).
- The download was executed as a silent installation using the `/S` flag, preventing any user interaction or prompts.
- File identified by the SHA-256 hash: `f563f1d863b08dd0bfe0435049865a9f74ec2d090995d2a73b70161bb2f34f10`.

### May 8, 2025 - 11:09 PM:
- The Tor Browser was launched for the first time under the process names:
  - `tor.exe` (associated with the Tor service)
  - `firefox.exe` (associated with the Tor Browser user interface)
- Processes were initiated from the following paths:
  - `C:\Users\RoidRagner\Desktop\Tor Browser\Browser\firefox.exe`
  - `C:\Users\RoidRagner\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### May 8, 2025 - 11:10:13 - 11:10:15 PM:
- Network connections were established through the Tor Browser using the following parameters:
  - **Process:** `tor.exe`
  - **Remote IP:** `185.184.71.94`
  - **Port:** `9001` (a known Tor network port)
- Another connection was made to IP `194.13.83.131` over port `9001`.
- Both connections are consistent with Tor entry/relay nodes, indicating active Tor circuits.

### May 8, 2025 - 11:16 - 11:21 PM:
- The process `firefox.exe` continued to run, indicating ongoing Tor Browser usage.
- During this period, several new files were created on the Desktop, including:
  - `tor-shopping-list.txt` - Created at `11:21 PM` with SHA-256 hash: `9e562e858f15ffd6a952080ce9b99acc503c7f0c8a1a68f6b8a25c7c4fe58357`.
  - `tor-shopping-list.lnk` - Created as a shortcut link, suggesting potential persistent access or quick access to the file.

### May 8, 2025 - 11:21 PM and Onward:
- Further connections to Tor network nodes were observed, with repeated connections to IP addresses associated with Tor relay nodes over port `9001`.
- Continuous execution of the `tor.exe` and `firefox.exe` processes, indicating ongoing use of the Tor network.



---

## Summary

Between 10:59 PM and 11:21 PM on May 8, 2025, the user 'RoidRagner' initiated the download and silent installation of the Tor Browser on the device wnx-2. The browser was executed multiple times as tor.exe and firefox.exe, establishing outbound connections to known Tor network IP addresses over port 9001. During this period, files named tor-shopping-list.txt and its associated shortcut link were created on the desktop, suggesting potential intent or planning involving Tor.

---

## Response Taken

TOR usage was confirmed on endpoint wnx-2 by the user Roidragner. The device was isolated and the user's direct manager was notified.


---
