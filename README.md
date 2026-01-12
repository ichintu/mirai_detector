# mirai_detector
Zeek Plugin to detect Mirai Botnet network scans

# Mirai Detector — `mirai.zeek`

A **Zeek (formerly Bro) network security monitoring script** that detects network behaviors associated with the **Mirai IoT botnet** family.

This script is part of the **mirai_detector** project and is intended for use with Zeek to monitor network traffic for suspicious patterns linked to Mirai-style infections and activity.

---

## 🚀 Overview

Mirai is a well-known malware botnet that targets insecure IoT devices to carry out large-scale Distributed Denial of Service (DDoS) attacks and other malicious activities. Once infected, devices communicate with command-and-control (C2) servers and initiate scanning, exploitation, and attack traffic. :contentReference[oaicite:0]{index=0}

The `mirai.zeek` script analyzes network traffic via Zeek’s event engine and generates alerts when host traffic matches patterns typically indicative of Mirai botnet activity, such as:

- Unusual scanning behavior
- Known Mirai C2 protocol signatures
- Suspicious connections on common ports used by Mirai variants
- Notice generation for threat hunting and incident response

---

## 🧠 What It Detects

This script inspects Zeek logs to identify network behaviors that may correlate with Mirai botnet traffic. Typical detections include:

- Connections to known Mirai command-and-control endpoints
- High-volume scanning from internal hosts
- Traffic anomalies that align with Mirai network signatures

> **Note:** Detection is based on network patterns, not on analysis of malware binaries or host-level compromise.

---

## 🧩 Requirements

To use this script you need:

- **Zeek (v4.x or later)** — The network security monitoring platform used to inspect and log traffic patterns. :contentReference[oaicite:1]{index=1}
- A network tap or mirrored port capturing relevant traffic
- Basic familiarity with Zeek scripts and deployment

---

## 📦 Installation & Deployment

1. **Clone or copy** `mirai.zeek` into your Zeek scripts directory (e.g., `${ZEEK_BASE}/share/zeek/site`):

   ```bash
   cp mirai.zeek /usr/local/zeek/share/zeek/site/
