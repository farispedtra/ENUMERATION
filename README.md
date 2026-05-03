> **Victim Machine:** Metasploitable 2 (`192.168.56.104`)  
> **Attacker Machine:** Kali Linux  
> **Tools Used:** Nmap, Zenmap, nmblookup, Netcat, FTP, dig, nslookup  
> **Challenges Completed:** 10 Challenges  

---

## Setup

| Item | Details |
|------|---------|
| Victim | Metasploitable 2 — `192.168.56.104` |
| Attacker | Kali Linux — `192.168.56.1` |
| Network | VirtualBox Host-Only Adapter |
| Hypervisor | VirtualBox |

Connectivity test:
```bash
ping 192.168.56.104
# 64 bytes from 192.168.56.104: icmp_seq=1 ttl=64 time=1.74 ms ✓
```

---

## Challenge 1 — NetBIOS Enumeration

**Objective:** Identify the NetBIOS name table of the target to discover hostname, domain membership, and active services via UDP port 137.

**Command:**
```bash
nmblookup -A 192.168.56.104
```

**Output:**
```
Looking up status of 192.168.56.104
        METASPLOITABLE  <00> -         B <ACTIVE>
        METASPLOITABLE  <03> -         B <ACTIVE>
        METASPLOITABLE  <20> -         B <ACTIVE>
        WORKGROUP       <00> - <GROUP> B <ACTIVE>
```

**Findings:**

| Code | Meaning |
|------|---------|
| `<00>` UNIQUE | Hostname: METASPLOITABLE |
| `<00>` GROUP | Domain: WORKGROUP |
| `<20>` UNIQUE | File Server (SMB) is active ⚠️ |
| `<03>` UNIQUE | Messenger service is active |

**Analysis:**  
The NetBIOS scan successfully revealed the machine name and workgroup domain. The presence of the `<20>` entry confirms that SMB file sharing is active, which is a significant attack surface. NetBIOS over TCP/IP should be disabled if not required in production environments.

**Risk Level:** `HIGH`

---

## Challenge 2 — Fast Nmap Scan

**Objective:** Perform a quick scan of the 100 most commonly used ports to obtain a rapid overview of the target's attack surface.

**Command:**
```bash
nmap -F 192.168.56.104
```

**Output:**
```
PORT     STATE  SERVICE
21/tcp   open   ftp
22/tcp   open   ssh
23/tcp   open   telnet
25/tcp   open   smtp
80/tcp   open   http
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3306/tcp open   mysql
5432/tcp open   postgresql
8180/tcp open   http-proxy
```

**Findings:**

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Anonymous login + backdoor CVE-2011-2523 |
| 23 | Telnet | Plaintext transmission — highly insecure ⚠️ |
| 445 | SMB | Outdated Samba — CVE-2007-2447 |
| 3306 | MySQL | Database exposed externally |

**Analysis:**  
More than 10 ports are open on a single machine. Telnet (23) and FTP (21) are particularly dangerous as both transmit credentials in plaintext. MySQL and PostgreSQL being exposed externally indicates a significant database compromise risk.

**Risk Level:** `CRITICAL`

---

## Challenge 3 — DNS Records

**Objective:** Enumerate DNS records of a public domain to map its infrastructure including mail servers, name servers, and IP mappings.

**Commands:**
```bash
nslookup google.com
dig ANY google.com
dig MX google.com
```

**Output:**
```
google.com.  300   IN  A      142.250.185.46
google.com.  300   IN  AAAA   2404:6800:4004:820::200e
google.com.  3600  IN  MX  10 smtp.google.com.
google.com.  3600  IN  NS     ns1.google.com.
```

**Findings:**

| Record | Value |
|--------|-------|
| A | 142.250.185.46 (IPv4 address) |
| AAAA | 2404:6800:4004:820::200e (IPv6 address) |
| MX | smtp.google.com (priority 10) |
| NS | ns1-ns4.google.com |

**Analysis:**  
DNS enumeration successfully retrieved all major record types. MX records expose mail server infrastructure that can be targeted for SMTP enumeration. In a real penetration test, this information enables more targeted attacks against mail infrastructure and helps identify subdomains.

**Risk Level:** `LOW`

---

## Challenge 5 — TTL OS Fingerprinting

**Objective:** Use the TTL value in ICMP ping replies to passively determine the operating system of the target host.

**Command:**
```bash
ping -c 4 192.168.56.104
```

**Output:**
```
64 bytes from 192.168.56.104: icmp_seq=1 ttl=64 time=1.74 ms
64 bytes from 192.168.56.104: icmp_seq=2 ttl=64 time=1.42 ms
64 bytes from 192.168.56.104: icmp_seq=3 ttl=64 time=1.23 ms
64 bytes from 192.168.56.104: icmp_seq=4 ttl=64 time=1.33 ms
```

**TTL Reference:**

| TTL Value | OS Guess |
|-----------|---------|
| **64** | **Linux / Unix ✓ (Metasploitable 2 confirmed)** |
| 128 | Windows |
| 255 | Cisco / BSD |

**Analysis:**  
A TTL value of 64 confirms the target is running a Linux/Unix-based operating system, consistent with Metasploitable 2 running Ubuntu. TTL fingerprinting is a passive technique that generates minimal network noise, making it useful for stealthy reconnaissance.

**Risk Level:** `LOW`

---

## Challenge 7 — SMTP VRFY / EXPN

**Objective:** Connect to the SMTP server on port 25 and use VRFY and EXPN commands to confirm the existence of user accounts on the target system.

**Command:**
```bash
echo -e "VRFY root\nVRFY admin\nVRFY nobody\nEXPN root\nQUIT" | nc 192.168.56.104 25
```

**Output:**
```
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
252 2.0.0 root
252 2.0.0 admin
550 5.1.1 <nobody>: User unknown
252 2.0.0 root
221 2.0.0 Bye
```

**Findings:**

| Command | Response | Meaning |
|---------|---------|---------|
| VRFY root | 252 | User **exists**  |
| VRFY admin | 252 | User **exists**  |
| VRFY nobody | 550 | User does not exist |

**Analysis:**  
The SMTP server allows VRFY and EXPN commands, confirming that system accounts such as root and admin exist on the machine. This enables targeted brute-force attacks against SSH or other authentication services. Fix: add `disable_vrfy_command = yes` in Postfix configuration.

**Risk Level:** `MEDIUM`

---

## Challenge 9 — FTP Banner

**Objective:** Capture the FTP service banner to identify the software version and associated CVEs.

**Command:**
```bash
nc 192.168.56.104 21
```

**Output:**
```
220 (vsFTPd 2.3.4)
```

**Findings:**

| Item | Details |
|------|---------|
| Software | vsFTPd version 2.3.4 |
| CVE | CVE-2011-2523 |
| CVSS Score | 10.0 (CRITICAL) |
| Exploit Type | Backdoor command execution |
| Trigger | Username containing `:)` smiley face |
| Result | Root shell opens on port 6200 |
| Metasploit Module | `exploit/unix/ftp/vsftpd_234_backdoor` |

**Analysis:**  
vsFTPd 2.3.4 contains a well-known backdoor inserted into the software distribution in 2011. When a username containing `:)` is entered, the backdoor opens a root shell on port 6200 with no authentication required. Service banners should always be hidden in production environments to prevent version disclosure.

**Risk Level:** `CRITICAL`

---

## Challenge 10 — Anonymous FTP Login

**Objective:** Determine whether the FTP server allows unauthenticated access using the username `anonymous`.

**Command:**
```bash
ftp 192.168.56.104
# Name: anonymous
# Password: guest@test.com
```

**Output:**
```
Connected to 192.168.56.104.
220 (vsFTPd 2.3.4)
230 Login successful.

ftp> ls
drwxr-xr-x  2 0  65534  4096 Mar 17 2010 pub
226 Directory send OK.

ftp> pwd
257 "/" is the current directory
```

**Findings:**

| Item | Result |
|------|--------|
| Anonymous Login |  Successful — 230 Login successful |
| Directory | `/pub` accessible without authentication |
| Protocol | Plaintext — credentials can be sniffed |

**Analysis:**  
Anonymous FTP login is enabled, allowing any unauthenticated user to browse the FTP server. Combined with the vsFTPd 2.3.4 backdoor, this machine is critically compromised. FTP should be replaced with SFTP or FTPS, and anonymous access must be disabled.

**Risk Level:** `HIGH`

---

## Challenge 11 — SMB NSE Enumeration

**Objective:** Use Nmap Scripting Engine (NSE) scripts to enumerate SMB information including OS version, domain name, and user accounts via port 445.

**Commands:**
```bash
nmap --script smb-os-discovery -p445 192.168.56.104
nmap --script smb-enum-users -p445 192.168.56.104
```

**Output:**
```
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   NetBIOS computer name: METASPLOITABLE
|   Workgroup: WORKGROUP

| smb-enum-users:
|   METASPLOITABLE\administrator (RID: 500)
|   METASPLOITABLE\guest (RID: 501)
|   METASPLOITABLE\msfadmin (RID: 1000)
|_  METASPLOITABLE\service (RID: 1001)
```

**Findings:**

| Item | Details |
|------|---------|
| OS | Unix — Samba 3.0.20-Debian |
| CVE | CVE-2007-2447 — Remote Code Execution |
| Users Discovered | administrator, guest, msfadmin, service |
| Metasploit Module | `exploit/multi/samba/usermap_script` |

**Analysis:**  
Samba 3.0.20 has CVE-2007-2447, which allows unauthenticated remote code execution. The exposed user list enables targeted brute-force attacks. Immediate upgrade to a current Samba version and restricting SMB access via firewall rules is required.

**Risk Level:** `CRITICAL`

---

## Challenge 16 — Version Detection

**Objective:** Use Nmap version detection to identify the exact software versions of all running services and correlate them with known CVEs.

**Command:**
```bash
nmap -sV 192.168.56.104
```

**Output:**
```
PORT     STATE  SERVICE      VERSION
21/tcp   open   ftp          vsftpd 2.3.4
22/tcp   open   ssh          OpenSSH 4.7p1 Debian
23/tcp   open   telnet       Linux telnetd
25/tcp   open   smtp         Postfix smtpd
80/tcp   open   http         Apache httpd 2.2.8
445/tcp  open   netbios-ssn  Samba smbd 3.0.20-Debian
3306/tcp open   mysql        MySQL 5.0.51a
5432/tcp open   postgresql   PostgreSQL DB 8.3.0
8180/tcp open   http         Apache Tomcat 5.5
```

**Vulnerability Summary:**

| Service | Version | CVE | Severity |
|---------|---------|-----|---------|
| vsFTPd | 2.3.4 | CVE-2011-2523 |  CRITICAL |
| Samba | 3.0.20 | CVE-2007-2447 |  CRITICAL |
| Apache | 2.2.8 | CVE-2017-7679 |  HIGH |
| OpenSSH | 4.7p1 | CVE-2008-0166 |  HIGH |
| Tomcat | 5.5 | CVE-2007-0450 |  HIGH |
| MySQL | 5.0.51a | CVE-2009-2446 |  MEDIUM |

**Analysis:**  
Every service on Metasploitable 2 runs an outdated version with known critical vulnerabilities. This highlights the critical importance of a consistent patch management programme. Each of these services has an exploit module available in Metasploit Framework.

**Risk Level:** `CRITICAL`

---

## Challenge 17 — OS Detection

**Objective:** Use Nmap OS detection to identify the target's operating system through TCP/IP stack fingerprinting.

**Command:**
```bash
nmap -O 192.168.56.104
```

**Output:**
```
Device type: VoIP adapter|bridge|general purpose
Running (JUST GUESSING): AT&T embedded (93%), Oracle Virtualbox (92%)
OS CPE: cpe:/o:oracle:virtualbox
No exact OS matches for host (test conditions non-ideal).
```

**Findings:**

| Item | Result |
|------|--------|
| OS Guess | AT&T embedded (93%), VirtualBox (92%) |
| Kernel Confirmation | TTL=64 from C5 → Linux confirmed |
| Open Ports | 20+ ports detected |
| Note | Less accurate in VM environment |

**Analysis:**  
OS detection is less accurate in a VM environment. However, combining this result with Challenge 5 (TTL=64) confirms the target is running Linux. The detection of 20+ open ports indicates a very broad attack surface on this machine.

**Risk Level:** `HIGH`

---

## Summary Table

| No. | Challenge | Command | Key Finding | Risk | 
|-----|-----------|---------|-------------|------|
| C1 | NetBIOS Enumeration | `nmblookup -A` | SMB active, Hostname: METASPLOITABLE | HIGH |
| C2 | Fast Nmap Scan | `nmap -F` | 10+ open ports including Telnet, FTP, MySQL | CRITICAL |
| C3 | DNS Records | `dig` / `nslookup` | A, AAAA, MX, NS records retrieved | LOW |
| C5 | TTL Fingerprinting | `ping` | TTL=64 → Linux confirmed | LOW |
| C7 | SMTP VRFY/EXPN | `nc port 25` | root & admin accounts confirmed | MEDIUM |
| C9 | FTP Banner | `nc port 21` | vsFTPd 2.3.4 — CVE-2011-2523 backdoor | CRITICAL |
| C10 | Anonymous FTP | `ftp` | Anonymous login successful, /pub accessible | HIGH |
| C11 | SMB NSE | `nmap --script` | Samba 3.0.20, 4 user accounts exposed | CRITICAL |
| C16 | Version Detection | `nmap -sV` | All services running outdated versions with CVEs | CRITICAL |
| C17 | OS Detection | `nmap -O` | Linux kernel 2.6.x, 20+ open ports detected | HIGH |
