# MySQL Database Ransomware Investigation

---

# Project Overview

This project documents the process of building, monitoring, exposing, and investigating an internet-facing MySQL server hosted in Microsoft Azure. The environment was initially secured and configured with **Microsoft Defender for Endpoint (MDE)**, **Azure Monitor**, and **MySQL General Query Logging** to establish a clean baseline and capture detailed telemetry before exposing the server to the internet.

After logging and monitoring were verified, the environment was intentionally exposed to observe real-world attacker activity. An unexpected ransomware attack targeted the MySQL database, resulting in the deletion of multiple databases and the creation of a ransom note. The remainder of this project focuses on reconstructing the attack, analyzing forensic evidence, and demonstrating the incident response process using **Microsoft Defender telemetry**, **Azure Monitor**, and **Kusto Query Language (KQL)**.

The original plan was to continue through the **eradication** and **recovery** phases by remediating the compromised system. However, the attack left the virtual machine in a state where it could no longer be trusted. Rather than attempting to recover an untrusted system, the VM was wiped, rebuilt from a known-good state, and the MySQL environment was reconstructed. This reflects a common real-world incident response decision: when the integrity of a system cannot be confidently verified, rebuilding from a known-good baseline is often the safest and most reliable recovery strategy.

This project highlights practical skills in **Azure security**, **threat hunting**, **digital forensics**, and **incident response** by analyzing a real-world attack from initial exposure through post-incident investigation.
