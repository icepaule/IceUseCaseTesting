# SIEM Use Case Katalog

## Purple Team Testing Framework - Mittelstaendische Bank

**Gesamt: 111 Use Cases, 188 Technique Mappings, 12 Taktiken**

---

## Uebersicht nach Taktik

| Taktik | Use Cases | Techniken | Schweregrade |
|--------|-----------|-----------|-------------|
| credential-access | 8 | 21 | critical |
| privilege-escalation | 5 | 8 | high |
| lateral-movement | 5 | 9 | high |
| defense-evasion | 20 | 44 | high |
| discovery | 20 | 32 | medium |
| execution | 8 | 14 | high |
| persistence | 9 | 16 | high |
| exfiltration | 7 | 8 | high |
| collection | 10 | 15 | medium |
| command-and-control | 6 | 8 | high |
| impact | 10 | 10 | critical |
| initial-access | 3 | 3 | medium |

---

## Credential Access

### UC-BANK-001: Credential Access Detection - Credential Dumping

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Erkennung von OS Credential Dumping (LSASS, SAM, NTDS, DCSync) |
| **MITRE Techniken** | T1003 (Credential Dumping), T1003.001 (OS Credential Dumping: LSASS Memory), T1003.002 (OS Credential Dumping: Security Account Manager), T1003.003 (OS Credential Dumping: NTDS), T1003.006 (OS Credential Dumping: DCSync), T1003.007 (OS Credential Dumping: Proc Filesystem), T1003.008 (OS Credential Dumping: /etc/passwd and /etc/shadow) |

### UC-BANK-002: Credential Access Detection - Network Sniffing

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Netzwerk-Traffic-Sniffing fuer Credential-Theft |
| **MITRE Techniken** | T1040 (Network Sniffing) |

### UC-BANK-003: Credential Access Detection - Process Injection: Portable Executable Injection

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Code-Injection in laufende Prozesse - Process Injection: Portable Executable Injection |
| **MITRE Techniken** | T1055.002 (Process Injection: Portable Executable Injection) |

### UC-BANK-004: Credential Access Detection - Brute Force: Password Spraying

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Brute-Force Angriff auf Zugangsdaten - Brute Force: Password Spraying |
| **MITRE Techniken** | T1110.003 (Brute Force: Password Spraying) |

### UC-BANK-005: Credential Access Detection - Steal Application Access Token

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Steal Application Access Token |
| **MITRE Techniken** | T1528 (Steal Application Access Token) |

### UC-BANK-006: Credential Access Detection - Unsecured Credentials

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Ungesicherte Credentials in Dateien/Registry |
| **MITRE Techniken** | T1552 (Unsecured Credentials), T1552.001 (Unsecured Credentials: Credentials In Files), T1552.002 (Unsecured Credentials: Credentials in Registry), T1552.003 (Unsecured Credentials: Bash History), T1552.004 (Unsecured Credentials: Private Keys), T1552.005 (Unsecured Credentials: Cloud Instance Metadata API) |

### UC-BANK-007: Credential Access Detection - Credentials from Password Stores: Credentials f...

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Browser-Credentials Extraktion |
| **MITRE Techniken** | T1555.003 (Credentials from Password Stores: Credentials from Web Browsers), T1555.004 (Credentials from Password Stores: Windows Credential Manager) |

### UC-BANK-008: Credential Access Detection - Steal or Forge Kerberos Tickets: Silver Ticket

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | credential-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Kerberos Ticket Manipulation - Steal or Forge Kerberos Tickets: Silver Ticket |
| **MITRE Techniken** | T1558.002 (Steal or Forge Kerberos Tickets: Silver Ticket), T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) |

## Privilege Escalation

### UC-BANK-020: Privilege Escalation Detection - Process Injection

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Code-Injection in laufende Prozesse |
| **MITRE Techniken** | T1055 (Process Injection) |

### UC-BANK-021: Privilege Escalation Detection - Access Token Manipulation: Token Impersonati...

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Token-Manipulation fuer erhoehte Rechte - Access Token Manipulation: Token Impersonation/Theft |
| **MITRE Techniken** | T1134.001 (Access Token Manipulation: Token Impersonation/Theft) |

### UC-BANK-022: Privilege Escalation Detection - Abuse Elevation Control Mechanism

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | UAC-Bypass und Rechteeskalation |
| **MITRE Techniken** | T1548 (Abuse Elevation Control Mechanism), T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid), T1548.002 (Abuse Elevation Control Mechanism: Bypass User Access Control) |

### UC-BANK-023: Privilege Escalation Detection - Hijack Execution Flow: Services File Permiss...

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Schwache Service-Binary-Berechtigungen |
| **MITRE Techniken** | T1574.010 (Hijack Execution Flow: Services File Permissions Weakness), T1574.011 (Hijack Execution Flow: Services Registry Permissions Weakness) |

### UC-BANK-024: Privilege Escalation Detection - Escape to Host

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | privilege-escalation |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Escape to Host |
| **MITRE Techniken** | T1611 (Escape to Host) |

## Lateral Movement

### UC-BANK-030: Lateral Movement Detection - Remote Services: Remote Desktop Protocol

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | RDP-basiertes Lateral Movement |
| **MITRE Techniken** | T1021.001 (Remote Services: Remote Desktop Protocol), T1021.002 (Remote Services: SMB/Windows Admin Shares), T1021.003 (Remote Services: Distributed Component Object Model), T1021.004 (Remote Services: SSH), T1021.006 (Remote Services: Windows Remote Management) |

### UC-BANK-031: Lateral Movement Detection - Boot or Logon Initialization Scripts: Startup Items

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Boot oder Logon Initialization Scripts - Boot or Logon Initialization Scripts: Startup Items |
| **MITRE Techniken** | T1037.005 (Boot or Logon Initialization Scripts: Startup Items) |

### UC-BANK-032: Lateral Movement Detection - Ingress Tool Transfer

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Download von Tools auf Zielsystem (Ingress Tool Transfer) |
| **MITRE Techniken** | T1105 (Ingress Tool Transfer) |

### UC-BANK-033: Lateral Movement Detection - Use Alternate Authentication Material: Pass the ...

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Use Alternate Authentication Material - Use Alternate Authentication Material: Pass the Hash |
| **MITRE Techniken** | T1550.002 (Use Alternate Authentication Material: Pass the Hash) |

### UC-BANK-034: Lateral Movement Detection - Lateral Tool Transfer

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | lateral-movement |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Lateral Tool Transfer |
| **MITRE Techniken** | T1570 (Lateral Tool Transfer) |

## Defense Evasion

### UC-BANK-040: Defense Evasion Detection - Indicator Removal on Host: File Deletion

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Indicator Removal on Host: File Deletion |
| **MITRE Techniken** | 7.A.5 (Indicator Removal on Host: File Deletion) |

### UC-BANK-041: Defense Evasion Detection - Direct Volume Access

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Direct Volume Access |
| **MITRE Techniken** | T1006 (Direct Volume Access) |

### UC-BANK-042: Defense Evasion Detection - Rootkit

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Rootkit |
| **MITRE Techniken** | T1014 (Rootkit) |

### UC-BANK-043: Defense Evasion Detection - Obfuscated Files or Information

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Verschleierte Dateien oder Informationen |
| **MITRE Techniken** | T1027 (Obfuscated Files or Information), T1027.002 (Obfuscated Files or Information: Software Packing), T1027.013 (Obfuscated Files or Information: Encrypted/Encoded File) |

### UC-BANK-044: Defense Evasion Detection - Masquerading: Masquerade Task or Service

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Tarnung als legitimer Prozess oder Datei (Masquerading) - Masquerading: Masquerade Task or Service |
| **MITRE Techniken** | T1036.004 (Masquerading: Masquerade Task or Service), T1036.005 (Masquerading: Match Legitimate Name or Location) |

### UC-BANK-045: Defense Evasion Detection - Process Injection: Dynamic-link Library Injection

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Code-Injection in laufende Prozesse - Process Injection: Dynamic-link Library Injection |
| **MITRE Techniken** | T1055.001 (Process Injection: Dynamic-link Library Injection) |

### UC-BANK-046: Defense Evasion Detection - Indicator Removal on Host

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Loeschung von Indikatoren und Spuren |
| **MITRE Techniken** | T1070 (Indicator Removal on Host), T1070.001 (Indicator Removal on Host: Clear Windows Event Logs), T1070.003 (Indicator Removal on Host: Clear Command History), T1070.004 (Indicator Removal on Host: File Deletion), T1070.006 (Indicator Removal on Host: Timestomp), T1070.008 (Email Collection: Mailbox Manipulation) |

### UC-BANK-047: Defense Evasion Detection - Modify Registry

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Windows Registry Modifikation |
| **MITRE Techniken** | T1112 (Modify Registry) |

### UC-BANK-048: Defense Evasion Detection - Access Token Manipulation

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Token-Manipulation fuer erhoehte Rechte |
| **MITRE Techniken** | T1134 (Access Token Manipulation), T1134.002 (Access Token Manipulation: Create Process with Token) |

### UC-BANK-049: Defense Evasion Detection - Deobfuscate/Decode Files or Information

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Deobfuskation/Dekodierung von Dateien |
| **MITRE Techniken** | T1140 (Deobfuscate/Decode Files or Information) |

### UC-BANK-050: Defense Evasion Detection - Indirect Command Execution

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Indirect Command Execution |
| **MITRE Techniken** | T1202 (Indirect Command Execution) |

### UC-BANK-051: Defense Evasion Detection - Rogue Domain Controller

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Rogue Domain Controller |
| **MITRE Techniken** | T1207 (Rogue Domain Controller) |

### UC-BANK-052: Defense Evasion Detection - Signed Script Proxy Execution

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Signed Script Proxy Execution |
| **MITRE Techniken** | T1216 (Signed Script Proxy Execution) |

### UC-BANK-053: Defense Evasion Detection - Signed Binary Proxy Execution

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | System Binary Proxy Execution |
| **MITRE Techniken** | T1218 (Signed Binary Proxy Execution), T1218.003 (Signed Binary Proxy Execution: CMSTP), T1218.004 (Signed Binary Proxy Execution: InstallUtil), T1218.005 (Signed Binary Proxy Execution: Mshta), T1218.007 (Signed Binary Proxy Execution: Msiexec), T1218.008 (Signed Binary Proxy Execution: Odbcconf), T1218.009 (Signed Binary Proxy Execution: Regsvcs/Regasm) |

### UC-BANK-054: Defense Evasion Detection - XSL Script Processing

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | XSL Script Processing |
| **MITRE Techniken** | T1220 (XSL Script Processing) |

### UC-BANK-055: Defense Evasion Detection - File and Directory Permissions Modification

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von File and Directory Permissions Modification |
| **MITRE Techniken** | T1222 (File and Directory Permissions Modification), T1222.001 (File and Directory Permissions Modification: Windows File and Directory Permissions Modification), T1222.002 (File and Directory Permissions Modification: FreeBSD, Linux and Mac File and Directory Permissions Modification) |

### UC-BANK-056: Defense Evasion Detection - Virtualization/Sandbox Evasion: System Checks

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Sandbox-Erkennung und Umgehung - Virtualization/Sandbox Evasion: System Checks |
| **MITRE Techniken** | T1497.001 (Virtualization/Sandbox Evasion: System Checks), T1497.003 (Virtualization/Sandbox Evasion: Time Based Evasion) |

### UC-BANK-057: Defense Evasion Detection - Subvert Trust Controls: Mark-of-the-Web Bypass

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Subvert Trust Controls: Mark-of-the-Web Bypass |
| **MITRE Techniken** | T1553.005 (Subvert Trust Controls: Mark-of-the-Web Bypass) |

### UC-BANK-058: Defense Evasion Detection - Impair Defenses

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Deaktivierung von Sicherheitsmechanismen |
| **MITRE Techniken** | T1562 (Impair Defenses), T1562.001 (Impair Defenses: Disable or Modify Tools), T1562.010 (Impair Defenses: Downgrade Attack), T1562.012 (Impair Defenses: Disable or Modify Linux Audit System) |

### UC-BANK-059: Defense Evasion Detection - Hide Artifacts: Hidden Users

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | defense-evasion |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Hide Artifacts: Hidden Users |
| **MITRE Techniken** | T1564.002 (Hide Artifacts: Hidden Users), T1564.004 (Hide Artifacts: NTFS File Attributes), T1574.001 (Hijack Execution Flow - DLL Search Order Hijacking), T1612 (Build Image on Host) |

## Discovery

### UC-BANK-060: Discovery and Reconnaissance Detection - System Service Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System Service Discovery |
| **MITRE Techniken** | T1007 (System Service Discovery) |

### UC-BANK-061: Discovery and Reconnaissance Detection - Application Window Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Anwendungsfenster-Enumeration |
| **MITRE Techniken** | T1010 (Application Window Discovery) |

### UC-BANK-062: Discovery and Reconnaissance Detection - Query Registry

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Windows Registry Abfrage |
| **MITRE Techniken** | T1012 (Query Registry) |

### UC-BANK-063: Discovery and Reconnaissance Detection - System Network Configuration Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Netzwerkkonfigurations-Enumeration |
| **MITRE Techniken** | T1016 (System Network Configuration Discovery), T1016.001 (System Network Configuration Discovery: Internet Connection Discovery) |

### UC-BANK-064: Discovery and Reconnaissance Detection - Remote System Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von Remote-System-Discovery und Host-Scanning |
| **MITRE Techniken** | T1018 (Remote System Discovery) |

### UC-BANK-065: Discovery and Reconnaissance Detection - Password Policy Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Nutzung von Remote-Services fuer Lateral Movement |
| **MITRE Techniken** | T1021 (Password Policy Discovery) |

### UC-BANK-066: Discovery and Reconnaissance Detection - System Owner/User Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System Owner/User Discovery |
| **MITRE Techniken** | T1033 (System Owner/User Discovery) |

### UC-BANK-067: Discovery and Reconnaissance Detection - Network Service Scanning

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Netzwerk-Service-Scanning |
| **MITRE Techniken** | T1046 (Network Service Scanning) |

### UC-BANK-068: Discovery and Reconnaissance Detection - System Network Connections Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System-Netzwerkverbindungen auflisten |
| **MITRE Techniken** | T1049 (System Network Connections Discovery) |

### UC-BANK-069: Discovery and Reconnaissance Detection - Process Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Prozess-Auflistung und -Discovery |
| **MITRE Techniken** | T1057 (Process Discovery) |

### UC-BANK-070: Discovery and Reconnaissance Detection - Permission Groups Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Berechtigungsgruppen-Discovery |
| **MITRE Techniken** | T1069 (Permission Groups Discovery), T1069.001 (Permission Groups Discovery: Local Groups), T1069.002 (Permission Groups Discovery: Domain Groups) |

### UC-BANK-071: Discovery and Reconnaissance Detection - System Information Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | System-Informationssammlung |
| **MITRE Techniken** | T1082 (System Information Discovery) |

### UC-BANK-072: Discovery and Reconnaissance Detection - File and Directory Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Dateisystem-Enumeration |
| **MITRE Techniken** | T1083 (File and Directory Discovery) |

### UC-BANK-073: Discovery and Reconnaissance Detection - Account Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Benutzerkonten-Enumeration |
| **MITRE Techniken** | T1087 (Account Discovery), T1087.001 (Account Discovery: Local Account), T1087.002 (Account Discovery: Domain Account) |

### UC-BANK-074: Discovery and Reconnaissance Detection - Peripheral Device Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von Peripheral Device Discovery |
| **MITRE Techniken** | T1120 (Peripheral Device Discovery) |

### UC-BANK-075: Discovery and Reconnaissance Detection - System Time Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von System Time Discovery |
| **MITRE Techniken** | T1124 (System Time Discovery) |

### UC-BANK-076: Discovery and Reconnaissance Detection - Network Share Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Netzwerk Share Discovery |
| **MITRE Techniken** | T1135 (Network Share Discovery) |

### UC-BANK-077: Discovery and Reconnaissance Detection - Password Policy Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Password Policy Discovery |
| **MITRE Techniken** | T1201 (Password Policy Discovery) |

### UC-BANK-078: Discovery and Reconnaissance Detection - Browser Bookmark Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Browser Information Discovery |
| **MITRE Techniken** | T1217 (Browser Bookmark Discovery) |

### UC-BANK-079: Discovery and Reconnaissance Detection - Domain Trust Discovery

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | discovery |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Recon-Phase |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Domain Trust Enumeration |
| **MITRE Techniken** | T1482 (Domain Trust Discovery), T1518 (Software Discovery), T1518.001 (Software Discovery: Security Software Discovery), T1526 (Cloud Service Discovery), T1580 (Cloud Infrastructure Discovery), T1614.001 (System Location Discovery: System Language Discovery), T1654 (Log Enumeration), TA0007 (host discovery) |

## Execution

### UC-BANK-080: Suspicious Execution Detection - Masquerading: Right-to-Left Override

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Tarnung als legitimer Prozess oder Datei (Masquerading) - Masquerading: Right-to-Left Override |
| **MITRE Techniken** | T1036.002 (Masquerading: Right-to-Left Override) |

### UC-BANK-081: Suspicious Execution Detection - Windows Management Instrumentation

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Windows Management Instrumentation Ausfuehrung |
| **MITRE Techniken** | T1047 (Windows Management Instrumentation) |

### UC-BANK-082: Suspicious Execution Detection - Scheduled Task/Job: Scheduled Task

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Persistenz via geplante Aufgaben (Scheduled Task/Job) - Scheduled Task/Job: Scheduled Task |
| **MITRE Techniken** | T1053.005 (Scheduled Task/Job: Scheduled Task) |

### UC-BANK-083: Suspicious Execution Detection - Command and Scripting Interpreter: PowerShell

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | PowerShell-basierte Ausfuehrung |
| **MITRE Techniken** | T1059.001 (Command and Scripting Interpreter: PowerShell), T1059.002 (Command and Scripting Interpreter: AppleScript), T1059.003 (Command and Scripting Interpreter: Windows Command Shell), T1059.004 (Command and Scripting Interpreter: Bash), T1059.005 (Command and Scripting Interpreter: Visual Basic), T1059.006 (Command and Scripting Interpreter: Python) |

### UC-BANK-084: Suspicious Execution Detection - Native API

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Native API Ausfuehrung |
| **MITRE Techniken** | T1106 (Native API) |

### UC-BANK-085: Suspicious Execution Detection - User Execution: Malicious File

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | User Execution - User Execution: Malicious File |
| **MITRE Techniken** | T1204.002 (User Execution: Malicious File) |

### UC-BANK-086: Suspicious Execution Detection - System Services: Launchctl

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Ausfuehrung via System-Services - System Services: Launchctl |
| **MITRE Techniken** | T1569.001 (System Services: Launchctl), T1569.002 (System Services: Service Execution) |

### UC-BANK-087: Suspicious Execution Detection - Cloud Administration Command

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | execution |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Cloud Administration Command |
| **MITRE Techniken** | T1651 (Cloud Administration Command) |

## Persistence

### UC-BANK-090: Persistence Mechanism Detection - Scheduled Task/Job: Cron

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Persistenz via geplante Aufgaben (Scheduled Task/Job) - Scheduled Task/Job: Cron |
| **MITRE Techniken** | T1053.003 (Scheduled Task/Job: Cron) |

### UC-BANK-091: Persistence Mechanism Detection - Create Account: Local Account

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erstellung neuer Benutzerkonten - Create Account: Local Account |
| **MITRE Techniken** | T1136.001 (Create Account: Local Account), T1136.002 (Create Account: Domain Account), T1136.003 (Create Account: Cloud Account) |

### UC-BANK-092: Persistence Mechanism Detection - Office Application Startup: Outlook Home Page

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Office Application Startup: Outlook Home Page |
| **MITRE Techniken** | T1137.004 (Office Application Startup: Outlook Home Page) |

### UC-BANK-093: Persistence Mechanism Detection - Signed Binary Proxy Execution: Rundll32

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | System Binary Proxy Execution - Signed Binary Proxy Execution: Rundll32 |
| **MITRE Techniken** | T1218.011 (Signed Binary Proxy Execution: Rundll32) |

### UC-BANK-094: Persistence Mechanism Detection - Scheduled Task/Job: Cron

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Scheduled Task/Job: Cron |
| **MITRE Techniken** | T1503.003 (Scheduled Task/Job: Cron) |

### UC-BANK-095: Persistence Mechanism Detection - Server Software Component: Transport Agent

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Server Software Component: Transport Agent |
| **MITRE Techniken** | T1505.002 (Server Software Component: Transport Agent), T1505.003 (Server Software Component: Web Shell) |

### UC-BANK-096: Persistence Mechanism Detection - Create or Modify System Process: Systemd Se...

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | System-Service-Erstellung und -Manipulation - Create or Modify System Process: Systemd Service |
| **MITRE Techniken** | T1543.002 (Create or Modify System Process: Systemd Service), T1543.003 (Create or Modify System Process: Windows Service) |

### UC-BANK-097: Persistence Mechanism Detection - Event Triggered Execution: Windows Manageme...

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Event Triggered Execution - Event Triggered Execution: Windows Management Instrumentation Event Subscription |
| **MITRE Techniken** | T1546.003 (Event Triggered Execution: Windows Management Instrumentation Event Subscription), T1546.011 (Application Shimming) |

### UC-BANK-098: Persistence Mechanism Detection - Boot or Logon Autostart Execution: Registry...

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | persistence |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Boot/Logon Autostart Execution - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| **MITRE Techniken** | T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder), T1547.004 (Boot or Logon Autostart Execution: Winlogon Helper DLL), T1547.009 (Boot or Logon Autostart Execution: Shortcut Modification) |

## Exfiltration

### UC-BANK-100: Data Exfiltration Detection - Automated Exfiltration

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Automatisierte Datenexfiltration |
| **MITRE Techniken** | T1020 (Automated Exfiltration) |

### UC-BANK-101: Data Exfiltration Detection - Scheduled Transfer

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Geplante automatische Datenuebertragung |
| **MITRE Techniken** | T1029 (Scheduled Transfer) |

### UC-BANK-102: Data Exfiltration Detection - Data Transfer Size Limits

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Aufgeteilte Datenexfiltration in kleinen Stuecken |
| **MITRE Techniken** | T1030 (Data Transfer Size Limits) |

### UC-BANK-103: Data Exfiltration Detection - Exfiltration Over C2 Channel

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Datenexfiltration ueber C2-Kanal |
| **MITRE Techniken** | T1041 (Exfiltration Over C2 Channel) |

### UC-BANK-104: Data Exfiltration Detection - Exfiltration Over Unencrypted/Obfuscated Non-C2...

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Exfiltration ueber alternativen Protokollkanal - Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol |
| **MITRE Techniken** | T1048.003 (Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol) |

### UC-BANK-105: Data Exfiltration Detection - Transfer Data to Cloud Account

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Exfiltration zu Cloud-Accounts |
| **MITRE Techniken** | T1537 (Transfer Data to Cloud Account) |

### UC-BANK-106: Data Exfiltration Detection - Exfiltration to Code Repository

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | exfiltration |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Exfiltration ueber Webdienste - Exfiltration to Code Repository |
| **MITRE Techniken** | T1567.001 (Exfiltration to Code Repository), T1567.002 (Exfiltration to Cloud Storage) |

## Collection

### UC-BANK-110: Data Collection Detection - Input Capture: Keylogging

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Input Capture: Keylogging |
| **MITRE Techniken** | 8.A.2 (Input Capture: Keylogging) |

### UC-BANK-111: Data Collection Detection - Data from Local System

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Zugriff auf sensible lokale Dateien und Daten |
| **MITRE Techniken** | T1005 (Data from Local System) |

### UC-BANK-112: Data Collection Detection - Data from Removable Media

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Data from Removable Media |
| **MITRE Techniken** | T1025 (Data from Removable Media) |

### UC-BANK-113: Data Collection Detection - Data from Network Shared Drive

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Daten von Network Shared Drive |
| **MITRE Techniken** | T1039 (Data from Network Shared Drive) |

### UC-BANK-114: Data Collection Detection - Input Capture: Keylogging

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Input Capture - Tastatureingaben abfangen - Input Capture: Keylogging |
| **MITRE Techniken** | T1056.001 (Input Capture: Keylogging) |

### UC-BANK-115: Data Collection Detection - Data Staged: Local Data Staging

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Lokales Sammeln von Daten in Staging-Verzeichnissen |
| **MITRE Techniken** | T1074.001 (Data Staged: Local Data Staging) |

### UC-BANK-116: Data Collection Detection - Screen Capture

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Bildschirmaufnahme / Screen Capture |
| **MITRE Techniken** | T1113 (Screen Capture) |

### UC-BANK-117: Data Collection Detection - Email Collection: Local Email Collection

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Email Collection: Local Email Collection |
| **MITRE Techniken** | T1114.001 (Email Collection: Local Email Collection), T1114.003 (Email Collection: Email Forwarding Rule) |

### UC-BANK-118: Data Collection Detection - Clipboard Data

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Clipboard-Daten abgreifen |
| **MITRE Techniken** | T1115 (Clipboard Data) |

### UC-BANK-119: Data Collection Detection - Automated Collection

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | collection |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Automatisierte Datensammlung |
| **MITRE Techniken** | T1119 (Automated Collection), T1123 (Audio Capture), T1125 (Video Capture), T1530 (Data from Cloud Storage Object), T1560.001 (Archive Collected Data - Archive via Utility) |

## Command And Control

### UC-BANK-120: C2 Communication Detection - Application Layer Protocol

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | C2-Kommunikation ueber Anwendungsprotokolle |
| **MITRE Techniken** | T1071 (Application Layer Protocol), T1071.001 (Application Layer Protocol: Web Protocols), T1071.004 (Application Layer Protocol: DNS) |

### UC-BANK-121: C2 Communication Detection - Proxy: Internal Proxy

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Proxy: Internal Proxy |
| **MITRE Techniken** | T1090.001 (Proxy: Internal Proxy) |

### UC-BANK-122: C2 Communication Detection - Data Encoding: Standard Encoding

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Data Encoding fuer C2 - Data Encoding: Standard Encoding |
| **MITRE Techniken** | T1132.001 (Data Encoding: Standard Encoding) |

### UC-BANK-123: C2 Communication Detection - Traffic Signaling

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Erkennung von Traffic Signaling |
| **MITRE Techniken** | T1205 (Traffic Signaling) |

### UC-BANK-124: C2 Communication Detection - Non-Standard Port

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Non-Standard Port C2 |
| **MITRE Techniken** | T1571 (Non-Standard Port) |

### UC-BANK-125: C2 Communication Detection - Protocol Tunneling

| Feld | Wert |
|------|------|
| **Schweregrad** | HIGH |
| **Taktik** | command-and-control |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | hoch |
| **Beschreibung** | Protocol Tunneling |
| **MITRE Techniken** | T1572 (Protocol Tunneling) |

## Impact

### UC-BANK-130: System Impact Detection - Data Encrypted for Impact

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Ransomware-Verschluesselung (Data Encrypted for Impact) |
| **MITRE Techniken** | T1486 (Data Encrypted for Impact) |

### UC-BANK-131: System Impact Detection - Service Stop

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Stoppen kritischer Dienste (Service Stop) |
| **MITRE Techniken** | T1489 (Service Stop) |

### UC-BANK-132: System Impact Detection - Inhibit System Recovery

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Inhibit System Recovery |
| **MITRE Techniken** | T1490 (Inhibit System Recovery) |

### UC-BANK-133: System Impact Detection - Defacement

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Defacement / Hinterlassen von Ransomware-Nachrichten |
| **MITRE Techniken** | T1491 (Defacement) |

### UC-BANK-134: System Impact Detection - Resource Hijacking

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Crypto-Mining auf Bankinfrastruktur (Resource Hijacking) |
| **MITRE Techniken** | T1496 (Resource Hijacking) |

### UC-BANK-135: System Impact Detection - Endpoint Denial of Service

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | System-Shutdown oder Endpoint DoS |
| **MITRE Techniken** | T1499 (Endpoint Denial of Service) |

### UC-BANK-136: System Impact Detection - System Shutdown/Reboot

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | System Shutdown/Reboot |
| **MITRE Techniken** | T1529 (System Shutdown/Reboot) |

### UC-BANK-137: System Impact Detection - Account Access Removal

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Erkennung von Account Access Removal |
| **MITRE Techniken** | T1531 (Account Access Removal) |

### UC-BANK-138: System Impact Detection - Disk Wipe: Disk Content Wipe

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Erkennung von Disk Wipe: Disk Content Wipe |
| **MITRE Techniken** | T1561.001 (Disk Wipe: Disk Content Wipe) |

### UC-BANK-139: System Impact Detection - Data Manipulation: Stored Data Manipulation

| Feld | Wert |
|------|------|
| **Schweregrad** | CRITICAL |
| **Taktik** | impact |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Active-Phase |
| **Bank-Relevanz** | sehr_hoch |
| **Beschreibung** | Manipulation gespeicherter Daten |
| **MITRE Techniken** | T1565.001 (Data Manipulation: Stored Data Manipulation) |

## Initial Access

### UC-BANK-140: Initial Access Detection - Valid Accounts

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | initial-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Initial-Compromise |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Verwendung valider Accounts |
| **MITRE Techniken** | T1078 (Valid Accounts) |

### UC-BANK-141: Initial Access Detection - Drive-By Compromise

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | initial-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Initial-Compromise |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Drive-by Compromise |
| **MITRE Techniken** | T1189 (Drive-By Compromise) |

### UC-BANK-142: Initial Access Detection - Phishing: Spearphishing Link

| Feld | Wert |
|------|------|
| **Schweregrad** | MEDIUM |
| **Taktik** | initial-access |
| **DORA Artikel** | Art.25 |
| **TIBER Phase** | Initial-Compromise |
| **Bank-Relevanz** | mittel |
| **Beschreibung** | Erkennung von Phishing: Spearphishing Link |
| **MITRE Techniken** | T1566.002 (Phishing: Spearphishing Link) |

---

## Compliance Checkliste

| UseCase ID | Name | Schweregrad | DORA | Getestet | Erkannt | Status |
|-----------|------|-------------|------|----------|---------|--------|
| UC-BANK-001 | Credential Access Detection - Credential | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-002 | Credential Access Detection - Network Sn | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-003 | Credential Access Detection - Process In | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-004 | Credential Access Detection - Brute Forc | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-005 | Credential Access Detection - Steal Appl | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-006 | Credential Access Detection - Unsecured  | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-007 | Credential Access Detection - Credential | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-008 | Credential Access Detection - Steal or F | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-020 | Privilege Escalation Detection - Process | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-021 | Privilege Escalation Detection - Access  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-022 | Privilege Escalation Detection - Abuse E | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-023 | Privilege Escalation Detection - Hijack  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-024 | Privilege Escalation Detection - Escape  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-030 | Lateral Movement Detection - Remote Serv | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-031 | Lateral Movement Detection - Boot or Log | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-032 | Lateral Movement Detection - Ingress Too | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-033 | Lateral Movement Detection - Use Alterna | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-034 | Lateral Movement Detection - Lateral Too | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-040 | Defense Evasion Detection - Indicator Re | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-041 | Defense Evasion Detection - Direct Volum | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-042 | Defense Evasion Detection - Rootkit | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-043 | Defense Evasion Detection - Obfuscated F | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-044 | Defense Evasion Detection - Masquerading | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-045 | Defense Evasion Detection - Process Inje | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-046 | Defense Evasion Detection - Indicator Re | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-047 | Defense Evasion Detection - Modify Regis | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-048 | Defense Evasion Detection - Access Token | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-049 | Defense Evasion Detection - Deobfuscate/ | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-050 | Defense Evasion Detection - Indirect Com | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-051 | Defense Evasion Detection - Rogue Domain | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-052 | Defense Evasion Detection - Signed Scrip | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-053 | Defense Evasion Detection - Signed Binar | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-054 | Defense Evasion Detection - XSL Script P | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-055 | Defense Evasion Detection - File and Dir | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-056 | Defense Evasion Detection - Virtualizati | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-057 | Defense Evasion Detection - Subvert Trus | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-058 | Defense Evasion Detection - Impair Defen | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-059 | Defense Evasion Detection - Hide Artifac | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-060 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-061 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-062 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-063 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-064 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-065 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-066 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-067 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-068 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-069 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-070 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-071 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-072 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-073 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-074 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-075 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-076 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-077 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-078 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-079 | Discovery and Reconnaissance Detection - | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-080 | Suspicious Execution Detection - Masquer | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-081 | Suspicious Execution Detection - Windows | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-082 | Suspicious Execution Detection - Schedul | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-083 | Suspicious Execution Detection - Command | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-084 | Suspicious Execution Detection - Native  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-085 | Suspicious Execution Detection - User Ex | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-086 | Suspicious Execution Detection - System  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-087 | Suspicious Execution Detection - Cloud A | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-090 | Persistence Mechanism Detection - Schedu | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-091 | Persistence Mechanism Detection - Create | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-092 | Persistence Mechanism Detection - Office | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-093 | Persistence Mechanism Detection - Signed | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-094 | Persistence Mechanism Detection - Schedu | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-095 | Persistence Mechanism Detection - Server | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-096 | Persistence Mechanism Detection - Create | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-097 | Persistence Mechanism Detection - Event  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-098 | Persistence Mechanism Detection - Boot o | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-100 | Data Exfiltration Detection - Automated  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-101 | Data Exfiltration Detection - Scheduled  | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-102 | Data Exfiltration Detection - Data Trans | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-103 | Data Exfiltration Detection - Exfiltrati | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-104 | Data Exfiltration Detection - Exfiltrati | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-105 | Data Exfiltration Detection - Transfer D | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-106 | Data Exfiltration Detection - Exfiltrati | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-110 | Data Collection Detection - Input Captur | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-111 | Data Collection Detection - Data from Lo | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-112 | Data Collection Detection - Data from Re | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-113 | Data Collection Detection - Data from Ne | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-114 | Data Collection Detection - Input Captur | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-115 | Data Collection Detection - Data Staged: | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-116 | Data Collection Detection - Screen Captu | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-117 | Data Collection Detection - Email Collec | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-118 | Data Collection Detection - Clipboard Da | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-119 | Data Collection Detection - Automated Co | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-120 | C2 Communication Detection - Application | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-121 | C2 Communication Detection - Proxy: Inte | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-122 | C2 Communication Detection - Data Encodi | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-123 | C2 Communication Detection - Traffic Sig | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-124 | C2 Communication Detection - Non-Standar | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-125 | C2 Communication Detection - Protocol Tu | high | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-130 | System Impact Detection - Data Encrypted | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-131 | System Impact Detection - Service Stop | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-132 | System Impact Detection - Inhibit System | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-133 | System Impact Detection - Defacement | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-134 | System Impact Detection - Resource Hijac | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-135 | System Impact Detection - Endpoint Denia | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-136 | System Impact Detection - System Shutdow | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-137 | System Impact Detection - Account Access | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-138 | System Impact Detection - Disk Wipe: Dis | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-139 | System Impact Detection - Data Manipulat | critical | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-140 | Initial Access Detection - Valid Account | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-141 | Initial Access Detection - Drive-By Comp | medium | Art.25 | [ ] | [ ] | [ ] |
| UC-BANK-142 | Initial Access Detection - Phishing: Spe | medium | Art.25 | [ ] | [ ] | [ ] |
