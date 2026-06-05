# 🏗️ OT/ICS Network Security Monitor

> **Career Stage:** OT Cybersecurity Engineer  
> **Author:** Mohammed Satar  
> **Standard:** ISA/IEC 62443 | NIST SP 800-82

---

## 📋 Overview

A Python-based **Operational Technology (OT) network security monitor** that analyzes industrial network traffic for:
- Rogue devices communicating on OT protocols
- Unauthorized Modbus write operations (could change setpoints!)
- Protocol anomalies on Modbus TCP, DNP3, S7comm, EtherNet/IP

This is the OT equivalent of a **SIEM** (Security Information and Event Management) for industrial networks.

---

## 🔍 What It Detects

| Threat | Severity | Description |
|--------|----------|-------------|
| Unknown device on OT network | 🔴 CRITICAL | Rogue device not in asset whitelist |
| Modbus WRITE from untrusted host | 🟠 HIGH | Could change PLC setpoints or coil states |
| Port scan on OT ports | 🟠 HIGH | Reconnaissance activity |
| S7comm communication | 🔵 INFO | Siemens PLC comms detected |
| Protocol on wrong segment | 🟡 MEDIUM | Zone/conduit violation (ISA 62443) |

---

## 🏭 OT Protocols Monitored

| Port | Protocol | System |
|------|---------|--------|
| 502 | Modbus TCP | Any PLC/RTU |
| 102 | S7comm | Siemens S7 PLCs |
| 44818 | EtherNet/IP | Allen Bradley PLCs |
| 20000 | DNP3 | RTUs, substations |
| 4840 | OPC-UA | Modern SCADA |

---

## 🚀 Run Demo

```bash
python ot_monitor.py
# Simulates real industrial network traffic and generates security events
```

---

## 📜 Standards Referenced

- **ISA/IEC 62443** — Industrial Cybersecurity
- **NIST SP 800-82** — ICS Security Guide
- **IEC 61511** — Safety Instrumented Systems

---

## 📜 License

MIT License — Mohammed Satar, 2024
