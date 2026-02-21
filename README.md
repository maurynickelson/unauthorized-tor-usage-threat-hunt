
# Threat Hunting Scenario: Unauthorized TOR Browser Installation & Usage

## Environment
Microsoft Defender for Endpoint (Advanced Hunting)

## Objective
Management suspected employees may be using TOR browsers to bypass network security controls after unusual encrypted traffic patterns and connections to known TOR entry nodes were observed. The goal was to determine whether TOR usage occurred and assess associated security risks.

---

## TL;DR (Recruiter Summary)

Detected unauthorized installation and active use of the TOR Browser on a corporate endpoint using Microsoft Defender Advanced Hunting (KQL). Correlated file artifacts, silent installation flags, process lineage, and network telemetry to confirm anonymized browsing activity. Demonstrated behavioral detection methodology, insider risk assessment, and structured SOC containment workflow.

---

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

