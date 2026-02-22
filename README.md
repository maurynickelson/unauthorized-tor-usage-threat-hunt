
# Threat Hunting Scenario: Unauthorized TOR Browser Installation & Usage

## Environment
Microsoft Defender for Endpoint (Advanced Hunting)

## Objective
Management suspected employees may be using TOR browsers to bypass network security controls after unusual encrypted traffic patterns and connections to known TOR entry nodes were observed. The goal was to determine whether TOR usage occurred and assess associated security risks.

---

## TL;DR (Recruiter Summary)

Detected unauthorized installation and active use of the TOR Browser on a corporate endpoint using Microsoft Defender Advanced Hunting (KQL). Correlated file artifacts, silent installation flags, process lineage, and network telemetry to confirm anonymized browsing activity. Demonstrated behavioral detection methodology, insider risk assessment, and structured SOC containment workflow.

---

## Table of Contents

- [TL;DR (Recruiter Summary)](#tldr-recruiter-summary)
- [Incident Classification](#incident-classification)
- [1. Investigation Methodology](#1-investigation-methodology)
- [2. Detailed Findings](#2-detailed-findings)
  - [2.1 TOR Installer Download & File Creation](#21-tor-installer-download--file-creation)
  - [2.2 Silent Installation Execution](#22-silent-installation-execution)
  - [2.3 TOR Browser Execution](#23-tor-browser-execution)
  - [Process Lineage Analysis](#process-lineage-analysis)
  - [2.4 Network Connectivity Confirmation](#24-network-connectivity-confirmation)
  - [TOR Architecture Context](#tor-architecture-context)
  - [Known TOR-Related Ports Monitored](#known-tor-related-ports-monitored)
- [3. Chronological Timeline](#3-chronological-timeline)
- [Telemetry Correlation Summary](#telemetry-correlation-summary)
- [4. Risk Assessment](#4-risk-assessment)
- [5. Response Actions](#5-response-actions)
- [Evidence Artifacts (Telemetry Validation)](#evidence-artifacts-telemetry-validation)
- [Extracted Indicators of Interest](#extracted-indicators-of-interest)
- [6. Skills Demonstrated](#6-skills-demonstrated)
- [Detection Engineering Opportunities](#detection-engineering-opportunities)
- [7. MITRE ATT&CK Alignment](#7-mitre-attck-alignment)
- [Conclusion](#conclusion)

---

## Incident Classification

- **Category:** Unauthorized Software / Policy Violation
- **Threat Type:** Anonymization Tool Usage
- **Severity:** Medium/High
- **Scope:** Single Endpoint (notengo)
- **Malicious Activity Confirmed:** No
- **Containment Action Taken:** Endpoint Isolation

# 1. Investigation Methodology

The hunt followed a hypothesis-driven approach:

1. Search for TOR-related file artifacts
2. Identify installation execution
3. Confirm browser launch activity
4. Validate TOR service initialization
5. Correlate network connectivity
6. Assess user-generated artifacts
7. Determine risk and response action

Data sources used:

- DeviceFileEvents
- DeviceProcessEvents
- DeviceNetworkEvents

---

# 2. Detailed Findings

## 2.1 TOR Installer Download & File Creation

Initial pivot:

```kql
DeviceFileEvents
| where FileName contains "tor"
| where DeviceName contains "notengo"
| where Timestamp >= datetime(2026-01-12T02:27:18.9352196Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```

Findings:

- TOR installer downloaded
- Multiple TOR-related files extracted
- Creation of `tor-shopping-list.txt`
- Activity began at: **2026-01-12T02:27:18Z**

This confirmed user-initiated download and extraction behavior.

Reference: :contentReference[oaicite:1]{index=1}

---

## 2.2 Silent Installation Execution

```kql
DeviceProcessEvents
| where DeviceName == "notengo"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```

At **2026-01-12T02:28:16Z**, the installer executed with:

```
tor-browser-windows-x86_64-portable-15.0.3.exe /S
```

The `/S` flag indicates silent installation.

---

## 2.3 TOR Browser Execution

```kql
DeviceProcessEvents
| where DeviceName == "notengo"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```

At **2026-01-12T02:29:00Z**:

- `firefox.exe` (Tor Browser) launched
- `tor.exe` initialized background networking service

This confirmed active TOR session.

---

## Process Lineage Analysis

Observed parent-child execution chain:

- tor-browser-windows-x86_64-portable-15.0.3.exe → firefox.exe
- firefox.exe → tor.exe

This confirms legitimate TOR bundle execution rather than malicious process injection or masquerading. No abnormal parent processes or privilege escalation indicators were observed.

---

## 2.4 Network Connectivity Confirmation

```kql
DeviceNetworkEvents
| where DeviceName == "notengo"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443)
| project Timestamp,
          DeviceName,
          InitiatingProcessAccountName,
          ActionType,
          RemoteIP,
          RemotePort,
          RemoteUrl,
          InitiatingProcessFileName,
          InitiatingProcessFolderPath
```

At **2026-01-12T02:30:27Z**:

- Successful network connection observed
- Initiating process: `tor.exe`
- Path: `C:\Users\notengo\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

Network activity consistent with TOR operation.
---

### TOR Architecture Context

Connections to 127.0.0.1 are consistent with Tor’s local SOCKS proxy architecture. Tor Browser routes traffic through a local proxy (typically port 9050 or 9150) before forwarding encrypted traffic to external Tor entry nodes.

Monitoring localhost proxy activity combined with `tor.exe` execution is a strong behavioral indicator of active Tor usage, even when external node IP addresses rotate frequently.

---

### Known TOR-Related Ports Monitored

The following ports were monitored during investigation due to common TOR usage patterns:

- **9001** – ORPort (Onion Router traffic)
- **9030** – Directory Port
- **9040** – Transparent proxy
- **9050** – SOCKS proxy
- **9051** – Control port
- **9150** – TOR Browser proxy
- **80 / 443** – Standard HTTP/HTTPS exit traffic

Monitoring these ports combined with tor.exe process activity strengthens detection confidence.

---

## 2.5 User Artifact Creation

At **2026-01-12T02:36:54Z**, user created:

```
tor-shopping-list.txt
```

Indicates interactive usage session during TOR activity.

---

# 3. Chronological Timeline

| Time (UTC) | Event |
|------------|-------|
| 02:27:18 | Initial TOR file artifacts observed |
| 02:28:16 | Silent installer execution |
| 02:29:00 | TOR browser launched |
| 02:29:00 | TOR networking service started |
| 02:30:27 | TOR network connection established |
| 02:36:54 | User-created TOR-related text file |

---

# Telemetry Correlation Summary

This investigation correlated activity across three primary telemetry domains:

1. File Events → Confirmed TOR download and artifact creation  
2. Process Events → Confirmed silent installation and runtime execution  
3. Network Events → Confirmed TOR proxy initialization and connectivity  

Cross-domain validation strengthened investigative confidence and reduced false-positive assumptions.

---

# 4. Risk Assessment

Observed activity was:

- User-initiated
- Policy-violating (unauthorized anonymization tool)
- Not malware-related
- No evidence of exploitation or lateral movement

Risk concerns include:

- Bypass of network monitoring controls
- Anonymous browsing capability
- Potential data exfiltration concealment

---

# 5. Response Actions

- Endpoint isolated
- Management notified
- Usage documented
- No malware remediation required

---

# Evidence Artifacts (Telemetry Validation)

Raw telemetry exported from Microsoft Defender Advanced Hunting:

- `tor-download.csv` – File creation and download events  
- `Tor-install.csv` – Installer execution logs  
- `Tor-process-creation.csv` – Process creation telemetry  
- `Tor useage.csv` – Network activity logs  
- `New query.csv` – Supplemental detection query output  

These artifacts validate findings documented in this report and demonstrate direct telemetry analysis rather than screenshot-based investigation.

---

# Extracted Indicators of Interest

| Type | Value |
|------|-------|
| Installer File | tor-browser-windows-x86_64-portable-15.0.3.exe |
| Installation Flag | /S (silent install) |
| Executable | tor.exe |
| Browser Binary | firefox.exe (Tor Bundle) |
| Proxy IP | 127.0.0.1 |
| Desktop Artifact | tor-shopping-list.txt |
| Endpoint | notengo |

---

---

# Evidence Artifacts (Telemetry Validation)

Raw telemetry exports from Microsoft Defender Advanced Hunting are stored in the `/evidence/` directory of this repository.

These files represent direct query exports used to validate findings during investigation.

## Available Artifacts

- [tor-download.csv](./evidence/tor-download.csv)  
  File creation and TOR installer download activity.

- [Tor-install.csv](./evidence/Tor-install.csv)  
  Installer execution telemetry, including silent installation flags.

- [Tor-process-creation.csv](./evidence/Tor-process-creation.csv)  
  Process creation events confirming TOR browser launch and service initialization.

- [tor-usage.csv](./evidence/tor-usage.csv)  
  Network telemetry showing tor.exe connectivity and proxy behavior.

- [new-query.csv](./evidence/new-query.csv) 
  Supplemental Advanced Hunting query output used during investigative pivots.

These datasets demonstrate direct telemetry analysis rather than screenshot-based validation and support reproducibility of investigative findings.

---

# Extracted Indicators of Interest

| Type | Value |
|------|-------|
| Installer File | tor-browser-windows-x86_64-portable-15.0.3.exe |
| Installation Flag | /S (silent install) |
| Executable | tor.exe |
| Browser Binary | firefox.exe (Tor Bundle) |
| Proxy IP | 127.0.0.1 |
| Desktop Artifact | tor-shopping-list.txt |
| Endpoint | notengo |

---

## Telemetry Correlation Summary

This investigation correlated activity across three primary telemetry domains:

1. **File Events** → Confirmed TOR download and artifact creation  
2. **Process Events** → Confirmed silent installation and runtime execution  
3. **Network Events** → Confirmed TOR proxy initialization and anonymized connectivity  

Cross-domain validation strengthened investigative confidence and reduced false-positive assumptions.

---

# 6. Skills Demonstrated

## Threat Hunting & Detection

- IOC-driven hypothesis testing
- Behavioral detection of anonymization tools
- Cross-table telemetry correlation
- Silent installation detection via command-line analysis

## Endpoint & Process Analysis

- Identification of installation flags (`/S`)
- Process lineage validation
- Artifact correlation across file and process telemetry

## Network Analysis

- Detection of TOR-related port usage
- Process-to-network correlation
- Validation of encrypted anonymized traffic patterns

## Incident Documentation

- Timeline reconstruction
- Risk-based assessment
- Structured SOC-style reporting
- Management escalation workflow

---

# 7. MITRE ATT&CK Alignment

| Technique | Description |
|------------|------------|
| T1090 | Proxy / Anonymization |
| T1105 | Ingress Tool Transfer |
| T1071 | Application Layer Protocol |

---

# Conclusion

The investigation confirmed intentional installation and use of the TOR Browser on corporate endpoint "notengo." Activity was consistent with anonymized browsing behavior rather than malicious exploitation. Appropriate containment and notification procedures were followed.

