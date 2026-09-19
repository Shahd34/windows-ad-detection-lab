# windows-ad-detection-lab

# Windows AD Security & Detection Engineering Lab

## Project Overview

This project is a hands-on **security operations and detection engineering lab** designed to simulate a small enterprise Windows environment.

The current work focuses on **Active Directory, Windows endpoint telemetry, Wazuh SIEM, and custom detection engineering**. The lab is used to generate controlled security events, investigate alerts, identify false positives, tune detection logic, and document the results.

---



## Lab Architecture

```text
                          
                         ──────────────────
                              LAB LAN
                           172.16.0.0/24
                         ─────────┬────────
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
              ┌─────▼─────┐               ┌─────▼─────┐
              │   DC      │               │ CLIENT1   │
              │  Windows  │               │  Windows  │
              │    AD     │               │ Endpoint  |
              |172.16.0.60│               |172.16.0.61│
              └─────┬─────┘               └─────┬─────┘
                    │                             │
                 Sysmon                        Sysmon
                    │                             │
              Wazuh Agent                  Wazuh Agent
                    │                             │
                    └─────────────┬───────────────┘
                                  │
                                  ▼
                           ┌────────────┐
                           │   Wazuh    │
                           │ SIEM / XDR │
                           └────────────┘
```

| Component     | Role / Tool                        | Current Use                                                                                                                                                                       |
| ------------- | ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DC-22**     | Windows Server (2022) / Domain Controller | Active Directory, DNS, domain authentication, user and group management, and Windows security events                                                                              |
| **CLIENT-22** | Windows Endpoint (10)                  | Domain-joined workstation and endpoint used for authentication and security event generation                                                                                      |
| **Sysmon**    | Windows System Monitoring          | Detailed endpoint telemetry including process creation, network connections, and other system activity. Installed on the Windows endpoints but not yet used in an attack scenario |
| **Wazuh**     | Ubuntu Server 24.04 LTS + Wazuh    | Central SIEM, Windows log collection, analysis, alerting, custom detection rules, and investigation                                                                               |




---

## Detection Engineering

The main focus of the project is developing and improving security detections from collected telemetry.

Current detection scenarios focus primarily on **Windows authentication and security events** collected by Wazuh.

Each detection is investigated to understand:

* What triggered the alert
* What the underlying Windows event contains
* Whether the activity is expected or suspicious
* Whether the detection produced a false positive
* How the detection can be tuned
* How the resulting detection maps to MITRE ATT&CK

Future development will expand the detection coverage to include **Sysmon telemetry, network telemetry from pfSense and Suricata, and larger multi-stage attack scenarios**.

---



```
