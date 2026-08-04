# MySQL Database Ransomware Investigation

---

## Skills Demonstrated

- Microsoft Defender for Endpoint
- Microsoft Defender XDR
- Azure Virtual Machines
- Azure Log Analytics
- Azure Monitor Agent
- Data Collection Rules (DCR)
- Kusto Query Language (KQL)
- Threat Hunting
- Digital Forensics
- Incident Response
- MySQL Administration
- MITRE ATT&CK Mapping
- Network Security
- Azure Network Security Groups

---

## Project Overview

This project documents the process of building, monitoring, exposing, and investigating an internet-facing MySQL server hosted in Microsoft Azure. The environment was initially secured and configured with **Microsoft Defender for Endpoint (MDE)**, **Azure Monitor Agent (AMA)**, and **MySQL General Query Logging** to establish a clean baseline and capture detailed telemetry before exposing the server to the internet.

After logging and monitoring were verified, the environment was intentionally exposed to observe real-world attacker activity. A database extortion attack targeted the MySQL database, resulting in the deletion of multiple databases and the creation of a ransom note. The remainder of this project focuses on reconstructing the attack, analyzing forensic evidence, and demonstrating the incident response process using **Microsoft Defender telemetry**, **Azure Monitor Agent (AMA)**, and **Kusto Query Language (KQL)**.

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

### Enable MySQL General Query Logging

The following SQL commands were executed to enable the MySQL General Query Log and configure MySQL to write all connection activity, authentication attempts, and SQL queries to a log file.

```sql
SET GLOBAL general_log = 'ON';
SET GLOBAL log_output = 'FILE';
SHOW VARIABLES LIKE 'general_log%';
```
---

## Phase 3 – Configure MySQL Logging in Azure Log Analytics

In this phase, we configure **Azure Monitor Agent (AMA)** and a **Data Collection Rule (DCR)** to continuously collect MySQL General Query Logs from the virtual machine and send them to **Azure Log Analytics**. This allows all MySQL activity to be centrally collected and searched using Kusto Query Language (KQL).

Rather than relying on the local MySQL General Query Log stored on the virtual machine, forwarding the logs to Azure Log Analytics ensured that forensic evidence remained available even if the attacker deleted databases or attempted to remove local artifacts. Centralized logging is a common security practice because it preserves evidence independently of the compromised system and enables investigators to correlate database activity with endpoint telemetry during incident response.

### Step 1 – Verify Defender Telemetry

Before configuring log collection, Microsoft Defender telemetry was verified to ensure the endpoint was successfully reporting to the Log Analytics Workspace.

```kusto
DeviceInfo
| where DeviceName startswith "corp-ep-sh231"
| order by TimeGenerated asc
```

Successful results confirmed that **CORP-EP-SH231** was onboarded correctly and actively reporting device telemetry.

<img width="1432" height="884" alt="image" src="https://github.com/user-attachments/assets/d8c8a9c4-4dc3-4522-8cd3-e00b4a7864ae" />

### Step 2 – Create the Data Collection Rule (DCR)

A custom **Data Collection Rule (DCR)** was created to continuously monitor the MySQL General Query Log and forward new entries to Azure Log Analytics.

Configuration:

| Setting | Value |
|---------|------|
| Data Source | Custom Text Log |
| Log File | `C:\ProgramData\MySQL\MySQL Server 8.0\Data\mysql_general.log` |
| Destination | `LAW_Cyber_Range` |
| Output Table | `MySQLAudit_CL` |

Once the DCR was assigned, Azure automatically installed the **Azure Monitor Agent (AMA)** on the virtual machine to begin collecting log data.

### Step 3 – Verify Log Collection

After the Azure Monitor Agent was installed, log ingestion was verified by querying the newly created **MySQLAudit_CL** table.

This confirmed that SQL connections, authentication attempts, and queries were successfully being forwarded from the MySQL server into Azure Log Analytics.

```kusto
MySQLAudit_CL
| where _ResourceId endswith "CORP-EP-SH231"
| project TimeGenerated, RawData
| order by TimeGenerated desc
```

Successful query results confirmed that the logging pipeline was functioning correctly and that all future MySQL activity would be available for threat hunting and forensic analysis.

<img width="2015" height="763" alt="image" src="https://github.com/user-attachments/assets/9e5d87ef-cd3e-4598-89a5-760e52bb1dc9" />

---

## Phase 4 – Deliberately Expose the Environment

**Step 1 – Configure Local Accounts**

Using **Computer Management (`compmgmt.msc`)**, the local accounts were configured to intentionally reduce authentication security within the lab environment.

The following changes were made:

- Enabled the local **Administrator** account.
- Verified the account was a member of the **Administrators** group.
- Configured a weak password for the Administrator account.
- Enabled the local **Guest** account.
- Added the Guest account to the **Users** group.
- Configured Guest account logon permissions.
- Updated Local Security Policy settings.
- Applied the new policy using powershell:
```
gpupdate /force
```
**Step 2 – Configure Remote MySQL Authentication**

To simulate an insecure database deployment, a remote MySQL administrative account was created.

The following SQL statements were executed:

```sql
CREATE USER 'root'@'%' IDENTIFIED BY 'root';

GRANT ALL PRIVILEGES
ON *.*
TO 'root'@'%'
WITH GRANT OPTION;

FLUSH PRIVILEGES;
```

**What These Commands Do**

| Command | Purpose |
|----------|---------|
| `CREATE USER` | Creates a new MySQL user account. |
| `'%'` | Allows connections from any IP address. |
| `GRANT ALL PRIVILEGES` | Gives the account full administrative access. |
| `WITH GRANT OPTION` | Allows the account to grant permissions to other users. |
| `FLUSH PRIVILEGES` | Immediately applies the permission changes. |

**Step 3 – Capture a Baseline Investigation Package**

Before exposing the virtual machine, a **Microsoft Defender for Endpoint Investigation Package** was collected.

This package serves as the **pre-compromise baseline** and was later compared with a second investigation package collected after the attack.

The comparison helped identify:

- New files
- Running processes
- Network connections
- Registry changes
- Installed software
- System configuration changes
- Potential persistence mechanisms

**Step 4 – Increase System Discoverability**

After confirming that all monitoring solutions were functioning correctly, the environment was intentionally made easier to discover.

The following changes were made:

- Windows Firewall disabled.
- Azure Network Security Group (NSG) updated to allow inbound traffic.
  - Exact exposure timestamp "2026-07-20T14:02:47.9214895Z" (used to determine how long it took for the breach to happen)

 ---

## Phase 5 – Detect the Breach

After intentionally exposing **CORP-EP-SH231** to the internet, the environment was continuously monitored using **Microsoft Defender for Endpoint**, **Azure Log Analytics**, and the **MySQL General Query Log**.

The objective of this phase was to determine how quickly an internet-facing MySQL server would be discovered and compromised while collecting every stage of the attack for forensic analysis.

### Exposure Timestamp

The virtual machine was intentionally exposed to the internet at:

```text
2026-07-20T14:02:47.9214895Z
```
This timestamp marks the beginning of the incident investigation window.

### Time to Compromise

Analysis of the MySQL General Query Log showed the first confirmed malicious activity began approximately **20 minutes later**.

```text
Exposure Time:
2026-07-20T14:02:47.9214895Z

First Confirmed Malicious SQL Activity:
2026-07-20 14:22:57 UTC

Time to Compromise:
≈ 20 Minutes
```
Observation

This demonstrates how rapidly exposed internet-facing services can be discovered by automated scanning infrastructure. Even in a controlled lab environment, the database was compromised in approximately twenty minutes after becoming publicly accessible.

### Attack Timeline

| Time (UTC) | Stage | Description |
|------------|-------|-------------|
| **14:02:47** | Environment Exposed | VM intentionally exposed to the Internet |
| **14:22:57** | Reconnaissance | Attacker begins querying MySQL configuration |
| **14:24:36** | Initial Access | Successful remote authentication from **64.89.163.79** |
| **14:24:36+** | Discovery | Databases, tables, and columns enumerated |
| **Immediately After** | Impact | Business tables and databases deleted |
| **Immediately After** | Recovery Inhibition | Binary logs purged and reset |
| **Immediately After** | Extortion | Bitcoin ransom note inserted |

### Stage 1 – Initial Access

Approximately twenty minutes after exposure, the first successful remote MySQL authentication was observed.

The attacker authenticated remotely using the MySQL **root** account.

Example log entry:

```text
2026-07-20T14:24:36.790055Z
Connect root@64.89.163.79 using TCP/IP
```

This confirmed the attacker had successfully connected to the exposed MySQL server.

> <img width="1779" height="465" alt="image" src="https://github.com/user-attachments/assets/6477326f-50d0-48fc-b89a-ed9748cba940" />
>
> Captures the first successful `root@64.89.163.79` connection.

### Stage 2 – Reconnaissance

After connecting, the attacker began identifying the database environment.

Queries observed included:

```sql
SELECT ... FROM INFORMATION_SCHEMA.FILES;

SHOW VARIABLES LIKE 'lower_case_table_names';

SHOW DATABASES;
```

The attacker then enumerated the business database.

```sql
SHOW FULL TABLES FROM ironpeak_corp_01;

SHOW FULL COLUMNS FROM ironpeak_corp_01.customers;

SHOW FULL COLUMNS FROM ironpeak_corp_01.orders;
```

#### Purpose

These commands allowed the attacker to determine:

- Available databases
- Business tables
- Sensitive columns
- Server configuration

### Stage 3 – Database Destruction

Once reconnaissance was complete, the attacker immediately began deleting business data.

The following destructive SQL statements were observed in the MySQL General Query Log:

```sql
DROP TABLE customers;

DROP TABLE orders;

DROP TABLE payments;

DROP TABLE credentials;

DROP DATABASE ironpeak_corp_01;
```

### Observed Impact

The attacker destroyed:

- Customer records
- Payment history
- Orders
- Stored credentials
- Primary business database

This represented the primary impact of the attack.

### Stage 4 – Recovery Inhibition

The attacker attempted to make recovery more difficult by modifying the MySQL binary logs.

Observed SQL:

```sql
PURGE BINARY LOGS;

RESET MASTER;
```
These commands reduce the ability to perform point-in-time database recovery.


### Stage 5 – Ransom Note

After deleting the original databases, the attacker created a replacement database.

```sql
CREATE DATABASE recover_your_data;
```

The attacker then inserted a Bitcoin ransom message into the new database.

```sql
INSERT INTO recover_your_data
VALUES (...Bitcoin ransom note...)
```

When MySQL Workbench was opened after the attack, the original **ironpeak_corp_01** database had been completely replaced by **recover_your_data**.

This confirmed the attacker had completed the attack.

> <img width="1706" height="866" alt="MySQL_workbench_compromised" src="https://github.com/user-attachments/assets/1cbaab82-b59c-4e4e-bdfe-df750173b3ca" />

> <img width="2012" height="326" alt="image" src="https://github.com/user-attachments/assets/2bc23dbe-ea10-4d46-b214-f4587fc43ab2" />

---

## Post-Incident Summary & Threat Assessment

Following completion of the forensic investigation, the decision was made to rebuild the virtual machine rather than attempt to repair the compromised MySQL instance.

The investigation confirmed that the MySQL database had been successfully compromised and destroyed; however, there was no conclusive evidence that the Windows operating system itself had been infected with traditional file-encrypting ransomware or that a persistent Windows malware payload remained on the host. Microsoft Defender Investigation Packages collected before and after the incident did not identify obvious persistence mechanisms, malicious Windows services, or unauthorized software installations.

Instead, the attacker targeted the exposed MySQL service directly. Analysis of the MySQL General Query Log showed that the attacker successfully authenticated to the exposed database, performed reconnaissance by enumerating databases and tables, deleted the business data, removed recovery information by modifying MySQL binary logs, and replaced the production database with a new database containing a Bitcoin ransom note.

Because this was a controlled lab environment and the original **ironpeak_corp_01** database had been backed up prior to exposure, rebuilding the environment was determined to be the fastest, safest, and most reliable recovery strategy. Rather than attempting to manually repair the damaged database, the compromised virtual machine was discarded, a new virtual machine was deployed, MySQL Server was reinstalled, and the backed-up database was restored.

This recovery approach provided several advantages:

- Eliminated any uncertainty regarding the integrity of the compromised environment.
- Restored the lab to a known-good state using trusted installation media.
- Allowed the production database to be restored quickly from backup.
- Preserved the compromised virtual machine and collected evidence for future forensic analysis.
- Reduced overall recovery time compared to attempting manual database repair.


### Threat Assessment

Based on the forensic evidence collected during this investigation, the incident is assessed to be an **opportunistic automated database extortion campaign** targeting an internet-exposed MySQL server.

Several factors support this assessment.

The virtual machine was intentionally exposed to the internet at:

```text
2026-07-20T14:02:47.9214895Z
```

The first confirmed malicious SQL activity was observed approximately **20 minutes later**, demonstrating how quickly exposed internet-facing services can be discovered by automated scanning infrastructure.

The attack followed a structured and repeatable sequence:

```text
Internet Discovery
        │
        ▼
Remote MySQL Authentication
        │
        ▼
Database Enumeration
        │
        ▼
Table Enumeration
        │
        ▼
DROP TABLE
        │
        ▼
DROP DATABASE
        │
        ▼
PURGE BINARY LOGS
        │
        ▼
RESET MASTER
        │
        ▼
CREATE DATABASE recover_your_data
        │
        ▼
INSERT Bitcoin Ransom Note
```

The attacker systematically connected to the exposed MySQL service, gathered information about the database environment, deleted the business tables and databases, attempted to hinder recovery by purging MySQL binary logs, and finally replaced the production database with a Bitcoin ransom note.

Analysis of the Microsoft Defender Investigation Packages found no evidence of traditional Windows ransomware, malicious Windows services, or persistent malware. Instead, every confirmed malicious action occurred through legitimate SQL commands executed against the exposed MySQL service. This strongly suggests the attacker achieved their objective without compromising the Windows operating system itself.

Although the ransom note claimed that the database had been copied before deletion, the evidence collected during this investigation does **not** confirm successful data exfiltration. Additional network telemetry, including Microsoft Defender `DeviceNetworkEvents`, Azure Virtual Network Flow Logs, Azure Firewall logs, or packet captures, would be required to determine whether any data was transmitted outside the environment.

Based on the timing of the compromise, the sequence of SQL commands, the Microsoft Defender findings, and the overall attack workflow, this incident is most consistent with an **opportunistic automated database extortion campaign** rather than a targeted intrusion against the organization. The exposed MySQL service was likely discovered through automated internet scanning, after which a scripted sequence of reconnaissance, destructive SQL commands, recovery inhibition, and extortion was executed.

---

### Confidence Assessment

| Finding | Confidence |
|----------|------------|
| MySQL database successfully compromised | **High** |
| Business data intentionally destroyed | **High** |
| Recovery logs intentionally removed | **High** |
| Bitcoin extortion attempt | **High** |
| Automated attack workflow | **High** |
| Traditional Windows ransomware | **Low** |
| Windows Operating System Compromise | **Low** |
| Data exfiltration | **Not Confirmed** |

---

### Lessons Learned

This project demonstrated how quickly an exposed internet-facing database can become the target of automated attacks. Within approximately **20 minutes** of exposure, the MySQL service was discovered, authenticated against, and subjected to a complete database extortion attack.

The investigation reinforced several important security principles:

- Internet-facing databases should never be publicly accessible unless absolutely necessary.
- Weak credentials and unrestricted remote administrative access dramatically increase risk.
- Database activity logs provide critical forensic evidence during incident response.
- Collecting baseline forensic evidence before an incident greatly improves post-incident analysis.
- Reliable backups provide the fastest and safest path to recovery following destructive attacks.
- Comprehensive logging and centralized telemetry enable investigators to accurately reconstruct an attack timeline and distinguish confirmed evidence from assumptions.

While the attacker successfully destroyed the MySQL database and left a Bitcoin ransom note, the available evidence does **not** support the conclusion that the Windows operating system was fully compromised or that data was successfully exfiltrated. Rebuilding the virtual machine and restoring the backed-up database returned the environment to a known-good state while preserving the compromised system for forensic analysis.

---

## Industry Context

During this investigation, the evidence indicated that the attack was most consistent with an opportunistic automated database extortion campaign targeting an exposed MySQL service.

Although this investigation found no evidence that artificial intelligence was used during the attack, recent industry research demonstrates that database-focused extortion campaigns continue to evolve. In July 2026, researchers at Sysdig documented **JadePuffer**, which they described as the first publicly documented end-to-end ransomware campaign autonomously executed by a large language model (LLM). The campaign targeted an internet-facing application, pivoted to a production MySQL database, destroyed data, and issued an extortion demand without a human operator directing each technical step.

While my investigation does not attribute this incident to JadePuffer or any other specific threat actor, the similarities reinforce an important defensive lesson: internet-facing database services remain attractive targets for automated extortion campaigns, regardless of whether they are driven by traditional scripts or increasingly autonomous tooling.

---

## References

- **[Sysdig / Dark Reading – JadePuffer: The First Complete LLM-Driven Ransomware Attack](https://www.darkreading.com/cyberattacks-data-breaches/jadepuffer-first-complete-llm-driven-ransomware-attack)**

- **[CISA – #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)**
