# MySQL Database Ransomware Investigation

---

## Project Overview

This project documents the process of building, monitoring, exposing, and investigating an internet-facing MySQL server hosted in Microsoft Azure. The environment was initially secured and configured with **Microsoft Defender for Endpoint (MDE)**, **Azure Monitor**, and **MySQL General Query Logging** to establish a clean baseline and capture detailed telemetry before exposing the server to the internet.

After logging and monitoring were verified, the environment was intentionally exposed to observe real-world attacker activity. An unexpected ransomware attack targeted the MySQL database, resulting in the deletion of multiple databases and the creation of a ransom note. The remainder of this project focuses on reconstructing the attack, analyzing forensic evidence, and demonstrating the incident response process using **Microsoft Defender telemetry**, **Azure Monitor**, and **Kusto Query Language (KQL)**.

The original plan was to continue through the **eradication** and **recovery** phases by remediating the compromised system. However, the attack left the virtual machine in a state where it could no longer be trusted. Rather than attempting to recover an untrusted system, the VM was wiped, rebuilt from a known-good state, and the MySQL environment was reconstructed. This reflects a common real-world incident response decision: when the integrity of a system cannot be confidently verified, rebuilding from a known-good baseline is often the safest and most reliable recovery strategy.

This project highlights practical skills in **Azure security**, **threat hunting**, **digital forensics**, and **incident response** by analyzing a real-world attack from initial exposure through post-incident investigation.

---

## Environment Overview
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/0bffc556-d51e-4a4c-9d91-2f040fefa1ab" />

This project was built in Microsoft Azure to observe and investigate real-world attacks against an internet-facing MySQL server. The environment consists of a Windows 11 virtual machine (`CORP-EP-SH231`) running MySQL Server inside an Azure Virtual Network. **Microsoft Defender for Endpoint (MDE)** was deployed to collect endpoint telemetry, while all MySQL queries and MySQL logon attempts were recorded in **`mysql_general.log`** and forwarded to an Azure **Log Analytics Workspace** for analysis. Before exposing the system to the internet, a clean baseline was established to verify that logging, monitoring, and telemetry were functioning correctly.

Once the environment was fully instrumented, the **Network Security Group (NSG)** was reconfigured to allow inbound traffic, making the MySQL service accessible from the internet. As attackers interacted with the server, every MySQL query and logon attempt was captured in the MySQL General Query Log, while Microsoft Defender collected endpoint telemetry such as process creation, network connections, file activity, and security events. By correlating database logs with endpoint telemetry, it was possible to reconstruct the attack, identify the attacker's actions, and perform a complete incident investigation following the compromise.

---

## Phase 1 – Build and Secure the Honeypot

A Windows 11 virtual machine named **CORP-EP-SH231** was deployed in Microsoft Azure with a public IP address and a strong local administrator account (`g_berkin`). Before exposing the system to the internet, the **Network Security Group (NSG)** was configured to block all inbound traffic while **Microsoft Defender for Endpoint (MDE)** was installed and validated to ensure endpoint telemetry was being collected. Once the onboarding process was complete, the device successfully appeared in the Microsoft Defender portal and began reporting to the **DeviceInfo** table, confirming the environment was fully monitored and ready for the next phase.

> - Azure VM deployment
> - Azure NSG showing all inbound traffic blocked
> - Microsoft Defender for Endpoint onboarding
> - Device visible in **Assets → Devices**
> - Device reporting in the **DeviceInfo** table

---

## Phase 2 – Install and Configure MySQL

MySQL was installed on **CORP-EP-SH231** after first installing the required **Microsoft Visual C++ 2019 Redistributable (x64)** dependency. The **Developer Default** installation option was selected to install both **MySQL Server** and **MySQL Workbench**. A strong root password was configured during setup, and a new local connection was created in MySQL Workbench to verify the installation. After confirming connectivity, a sample corporate database (`ironpeak_corp_01`) was imported to simulate a production environment. Finally, the **MySQL General Query Log** was enabled so that every MySQL connection, authentication attempt, and SQL query would be written to **`mysql_general.log`**, providing the primary forensic evidence used throughout the remainder of this investigation.

> - Microsoft Visual C++ 2019 Redistributable installation
> - MySQL Installer (Developer Default)
> - MySQL Workbench connection
> - Imported Database: [db_info_import.sql](https://docs.google.com/document/d/1FCaBPP71vzG8B2ZMM1tm1UdtDCH3px8eFLeVq5dfubA/edit?usp=sharing)
> - Successful data import
> - MySQL General Query Log enabled
> - `SHOW VARIABLES LIKE 'general_log%';` output

 Enable MySQL General Query Logging

The following SQL commands were executed to enable the MySQL General Query Log and configure MySQL to write all connection activity, authentication attempts, and SQL queries to a log file.

```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'FILE';
SHOW VARIABLES LIKE 'general_log%';
```
