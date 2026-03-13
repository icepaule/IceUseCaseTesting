# Systemarchitektur

> Datenfluss und Komponentenübersicht

## Gesamtarchitektur

![Architecture Overview](images/01_architecture_overview.png)

```mermaid
graph TB
    subgraph Caldera["MITRE Caldera Server"]
        API[REST API :8888]
        ADV[6 Adversary Profile]
        AB[162+ Abilities]
        PL[16 Plugins]
        SC[Sandcat Agent Builder]
    end

    subgraph Targets["Zielsysteme - Isoliertes Netz"]
        TW[Windows Targets]
        TL[Linux Targets]
    end

    subgraph Publisher["Data Publisher"]
        PUB[publish-to-splunk.sh]
        B64[Base64 Decoder]
        MITRE_L[MITRE Lookup]
        ART[Artifact Classifier]
    end

    subgraph Splunk["Splunk SIEM"]
        HEC[HEC Endpoint :8088]
        IDX1[(Index: caldera)]
        IDX2[(Index: siem_summary)]
        SS[15 Saved Searches]
        KC[Kill Chain Correlation]
        DASH[Dashboard]
        ALERT[Alerting → SOC]
    end

    subgraph Orchestrator["Automatisierung"]
        ORCH[run-bank-adversaries.sh]
    end

    ORCH -->|"1. Start Operations"| API
    API -->|"2. C2 Commands"| TW & TL
    TW & TL -->|"3. Results"| API
    ORCH -->|"4. Trigger Publish"| PUB
    API -->|"5. Fetch Results"| PUB
    PUB --> B64 --> MITRE_L --> ART
    ART -->|"6. Enriched JSON"| HEC
    HEC --> IDX1
    IDX1 -->|"7. Korrelation"| SS
    SS -->|"8. Trigger"| IDX2
    IDX2 --> KC -->|"9. Kill Chain"| IDX2
    IDX1 & IDX2 -->|"10. Visualisierung"| DASH
    SS -->|"11. Alerts"| ALERT
```

## Datenfluss im Detail

![Data Flow](images/04_data_flow.png)

```mermaid
sequenceDiagram
    participant O as Orchestrator
    participant C as Caldera
    participant T as Target
    participant P as Publisher
    participant S as Splunk

    Note over O,S: Phase 1: Test-Ausführung
    O->>C: POST /operations (Adversary-Profil)
    C->>T: Ability ausführen (via C2)
    T-->>C: Ergebnis + Output (ggf. Base64)
    C->>T: Nächste Ability...
    T-->>C: Ergebnis

    Note over O,S: Phase 2: Daten-Enrichment
    O->>P: Trigger publish-to-splunk.sh
    P->>C: GET /operations (alle Ergebnisse)
    C-->>P: Operations + Chain + Commands
    P->>P: Base64-Decode
    P->>P: MITRE-Lookup (CSV)
    P->>P: Artefakt-Klassifikation
    P->>P: UseCase-Zuordnung

    Note over O,S: Phase 3: SIEM-Verarbeitung
    P->>S: POST HEC (Enriched Events)
    S->>S: Index: caldera
    S->>S: Saved Searches (alle 5 Min)
    S->>S: Pattern Matching → UseCase Trigger
    S->>S: collect → siem_summary
    S->>S: Kill Chain Korrelation (alle 10 Min)
```

## Verzeichnisstruktur

```
/opt/caldera/                        # Caldera Installation
├── server.py                        # Hauptprogramm
├── conf/
│   ├── default.yml                  # Standard-Konfiguration
│   └── local.yml                    # Lokale Konfiguration (NICHT committen!)
├── data/
│   ├── adversaries/
│   │   ├── bank-ransomware-chain.yml
│   │   ├── bank-apt-espionage.yml
│   │   ├── bank-insider-threat.yml
│   │   ├── bank-lateral-movement.yml
│   │   ├── bank-defense-evasion.yml
│   │   └── bank-data-exfil.yml
│   └── backup/
└── plugins/
    └── stockpile/data/abilities/    # 162 vordefinierte Abilities

/opt/caldera-splunk/                 # Splunk-Integration
├── publish-to-splunk.sh             # Enrichment + HEC Publisher
├── run-bank-adversaries.sh          # Test-Orchestrator
├── install-splunk-app.sh            # Splunk Remote-Installer
├── siem/
│   ├── siem_usecases_savedsearches.conf
│   ├── indexes.conf
│   ├── props.conf
│   └── transforms.conf
├── dashboards/
│   └── bank_purple_team_dashboard.xml
├── lookups/
│   └── mitre_attack_bank_mapping.csv
└── docs/
    └── SIEM_USECASES_DOKUMENTATION.md
```

## Artefakt-Klassifikation

```mermaid
graph LR
    CMD[Command Output] --> CLS{Klassifikation}
    CLS -->|"mimikatz, lsass, procdump"| CR[Credential Artifact]
    CLS -->|"net use, psexec, ssh"| LM[Lateral Movement Artifact]
    CLS -->|"crontab, schtasks, service"| PE[Persistence Artifact]
    CLS -->|"compress, zip, exfil, ftp"| EX[Exfiltration Artifact]
    CLS -->|"defender, disable, inject"| EV[Evasion Artifact]
    CLS -->|"whoami, netstat, arp"| DI[Discovery Artifact]
    CLS -->|"encrypt, ransom, shutdown"| IM[Impact Artifact]
    CLS -->|"screenshot, clipboard"| CO[Collection Artifact]

    style CR fill:#dc4e41,color:#fff
    style LM fill:#dc4e41,color:#fff
    style EX fill:#dc4e41,color:#fff
    style EV fill:#f1813f,color:#fff
    style IM fill:#dc4e41,color:#fff
    style DI fill:#0877a6,color:#fff
    style CO fill:#f8be34,color:#000
    style PE fill:#f1813f,color:#fff
```
