> **Victim Machine:** Metasploitable 2 (`192.168.56.104`)  
> **Attacker Machine:** Kali Linux  
> **Tools Used:** Nmap, nmblookup, Netcat, FTP, dig, nslookup  
> **Challenges Completed:** 10 Challenges  

---

## Setup

| Item | Details |
|------|---------|
| Victim | Metasploitable 2 — `192.168.56.104` |
| Attacker | Kali Linux |
| Network | VirtualBox Host-Only Adapter |
| Hypervisor | Oracle VirtualBox |

**Victim IP Verification (`ifconfig`):**
```
eth0   inet addr:192.168.56.104   Bcast:192.168.56.255   Mask:255.255.255.0
       HWaddr 08:00:27:52:58:0a
       UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
```

**Connectivity Test:**
```
ping 192.168.56.104
64 bytes from 192.168.56.104: icmp_seq=1 ttl=64 time=1.74 ms 
```

---

## Challenge 1 — NetBIOS Enumeration

**Objective:** Identify the NetBIOS name table of the target to discover hostname, domain membership, and active services via UDP port 137.

**Command:**
```bash
nmblookup -A 192.168.56.104
```

**Actual Output:**
```
Looking up status of 192.168.56.104
        METASPLOITABLE  <00> -         B <ACTIVE>
        METASPLOITABLE  <03> -         B <ACTIVE>
        METASPLOITABLE  <20> -         B <ACTIVE>
        WORKGROUP       <00> - <GROUP> B <ACTIVE>
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>

        MAC Address = 00-00-00-00-00-00
```

**Findings:**

| Code | Meaning |
|------|---------|
| `<00>` UNIQUE | Hostname: METASPLOITABLE |
| `<00>` GROUP | Domain: WORKGROUP |
| `<20>` UNIQUE | File Server (SMB) is active  |
| `<03>` UNIQUE | Messenger service is active |
| `<1e>` GROUP | Browser service elections |

**Analysis:**  
The NetBIOS scan successfully revealed the machine name (METASPLOITABLE) and workgroup domain (WORKGROUP). The presence of the `<20>` entry confirms that SMB file sharing is active — a significant attack surface. NetBIOS over TCP/IP should be disabled if not required in production environments.

**Risk Level:** `HIGH`

---

## Challenge 2 — Fast Nmap Scan

**Objective:** Perform a quick scan of the 100 most commonly used ports to obtain a rapid overview of the target's attack surface.

**Command:**
```bash
nmap -F 192.168.56.104
```

**Actual Output:**
```
Starting Nmap 7.99 ( https://nmap.org ) at 2026-05-03 02:48 -0400
Nmap scan report for 192.168.56.104
Host is up (0.0019s latency).
Not shown: 82 filtered tcp ports (no-response)
PORT      STATE  SERVICE
21/tcp    open   ftp
22/tcp    open   ssh
23/tcp    open   telnet
25/tcp    open   smtp
53/tcp    open   domain
80/tcp    open   http
111/tcp   open   rpcbind
139/tcp   open   netbios-ssn
445/tcp   open   microsoft-ds
513/tcp   open   login
514/tcp   open   shell
2049/tcp  open   nfs
2121/tcp  open   ccproxy-ftp
3306/tcp  open   mysql
5432/tcp  open   postgresql
5900/tcp  open   vnc
6000/tcp  open   X11
8009/tcp  open   ajp13

Nmap done: 1 IP address (1 host up) scanned in 2.23 seconds
```

**Findings:**

| Port | Service | Risk |
|------|---------|------|
| 21 | FTP | Anonymous login + backdoor CVE-2011-2523 |
| 23 | Telnet | Plaintext transmission — highly insecure  |
| 445 | SMB | Outdated Samba — CVE-2007-2447 |
| 3306 | MySQL | Database exposed externally |
| 5900 | VNC | Remote desktop exposed |
| 514 | Shell (rsh) | Unauthenticated remote shell  |

**Analysis:**  
18 ports are open on a single machine. The presence of Telnet (23), rsh/shell (514), and FTP (21) is particularly dangerous as these protocols transmit credentials in plaintext. VNC (5900) being exposed externally allows remote desktop access. NFS (2049) exposure could allow unauthorized file system mounting.

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

**Actual Output — nslookup:**
```
Server:         192.168.100.1
Address:        192.168.100.1#53

Non-authoritative answer:
Name:   google.com
Address: 142.250.193.238
Name:   google.com
Address: 2404:6800:4001:804::200e
```

**Actual Output — dig ANY:**
```
;; ANSWER SECTION:
google.com.    72    IN  AAAA   2404:6800:4001:804::200e
google.com.    20490 IN  HTTPS  1 . alpn="h2,h3"
google.com.    27    IN  SOA    ns1.google.com. dns-admin.google.com.
google.com.    51    IN  A      142.250.193.238
google.com.    34945 IN  NS     ns4.google.com.
google.com.    34945 IN  NS     ns3.google.com.
google.com.    34945 IN  NS     ns1.google.com.
google.com.    34945 IN  NS     ns2.google.com.
```

**Actual Output — dig MX:**
```
;; ANSWER SECTION:
google.com.    300   IN  MX  10 smtp.google.com.
```

**Findings:**

| Record | Value |
|--------|-------|
| A | 142.250.193.238 (IPv4 address) |
| AAAA | 2404:6800:4001:804::200e (IPv6 address) |
| MX | smtp.google.com (priority 10) |
| NS | ns1.google.com, ns2.google.com, ns3.google.com, ns4.google.com |
| SOA | ns1.google.com (primary nameserver) |

**Analysis:**  
DNS enumeration successfully retrieved all major record types. MX records expose the mail server infrastructure that can be targeted for SMTP enumeration. The presence of HTTPS records indicates HTTP/2 and HTTP/3 support. In a real penetration test, this information enables more targeted attacks against mail infrastructure and helps identify subdomains.

**Risk Level:** `LOW`

---

## Challenge 5 — TTL OS Fingerprinting

**Objective:** Use the TTL value in ICMP ping replies to passively determine the operating system of the target host.

**Command:**
```bash
ping 192.168.56.104
```

**Actual Output:**
```
PING 192.168.56.104 (192.168.56.104) 56(84) bytes of data.
64 bytes from 192.168.56.104: icmp_seq=1 ttl=64 time=1.74 ms
64 bytes from 192.168.56.104: icmp_seq=2 ttl=64 time=1.42 ms
64 bytes from 192.168.56.104: icmp_seq=3 ttl=64 time=1.23 ms
64 bytes from 192.168.56.104: icmp_seq=4 ttl=64 time=1.33 ms
64 bytes from 192.168.56.104: icmp_seq=5 ttl=64 time=1.27 ms
64 bytes from 192.168.56.104: icmp_seq=6 ttl=64 time=1.83 ms
64 bytes from 192.168.56.104: icmp_seq=7 ttl=64 time=1.18 ms
64 bytes from 192.168.56.104: icmp_seq=8 ttl=64 time=1.18 ms
```

**TTL Reference:**

| TTL Value | OS Guess |
|-----------|---------|
| **64** | **Linux / Unix** |
| 128 | Windows |
| 255 | Cisco / BSD |

**Analysis:**  
A consistent TTL value of 64 across all 8 packets confirms the target is running a Linux/Unix-based operating system, consistent with Metasploitable 2 running Ubuntu. Zero packet loss confirms the host is stable and reachable. TTL fingerprinting is a passive technique that generates minimal network noise, making it useful for stealthy reconnaissance.

**Risk Level:** `LOW`

---

## Challenge 7 — SMTP VRFY / EXPN

**Objective:** Connect to the SMTP server on port 25 and use VRFY and EXPN commands to confirm the existence of user accounts on the target system.

**Command:**
```bash
echo -e "VRFY root\nVRFY admin\nVRFY nobody\nEXPN root\nQUIT" | nc 192.168.56.104 25
```

**Actual Output:**
```
220 metasploitable.localdomain ESMTP Postfix (Ubuntu)
252 2.0.0 root
550 5.1.1 <admin>: Recipient address rejected: User unknown in local recipient table
252 2.0.0 nobody
502 5.5.2 Error: command not recognized
221 2.0.0 Bye
```

**Findings:**

| Command | Response | Meaning |
|---------|---------|---------|
| VRFY root | 252 | User **exists**  |
| VRFY admin | 550 | User does **not** exist |
| VRFY nobody | 252 | User **exists**  |
| EXPN root | 502 | Command not recognized (disabled) |

**Analysis:**  
The SMTP server running Postfix on Ubuntu responds to VRFY commands, confirming that `root` and `nobody` accounts exist on the system. The `admin` account does not exist. EXPN is disabled (502), showing partial hardening. However, VRFY being enabled still allows user enumeration. This information can be used to target brute-force attacks against SSH. Fix: add `disable_vrfy_command = yes` in Postfix configuration.

**Risk Level:** `MEDIUM`

---

## Challenge 9 — FTP Banner

**Objective:** Capture the FTP service banner to identify the software version and associated CVEs.

**Command:**
```bash
nc 192.168.56.104 21
```

**Actual Output:**
```
220 (vsFTPd 2.3.4)
quit
221 Goodbye.
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
vsFTPd 2.3.4 contains a well-known backdoor that was deliberately inserted into the software distribution in 2011. When a username containing a smiley `:)` is entered, the backdoor opens a root shell on port 6200 with no authentication required. This is one of the most famous vulnerabilities in Metasploitable 2 with a CVSS score of 10.0. Service banners should always be hidden in production environments to prevent version disclosure.

**Risk Level:** `CRITICAL`

---

## Challenge 10 — Anonymous FTP Login

**Objective:** Determine whether the FTP server allows unauthenticated access using the username `anonymous`.

**Command:**
```bash
ftp 192.168.56.104
```

**Actual Output:**
```
Connected to 192.168.56.104.
220 (vsFTPd 2.3.4)
Name (192.168.56.104:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||55470|).
150 Here comes the directory listing.
226 Directory send OK.
ftp> pwd
Remote directory: /
ftp> bye
221 Goodbye.
```

**Findings:**

| Item | Result |
|------|--------|
| Anonymous Login |  Successful — 230 Login successful |
| Root Directory | `/` accessible without authentication |
| Directory Listing | Empty — no files exposed in root |
| Protocol | Plaintext — credentials can be sniffed |

**Analysis:**  
Anonymous FTP login is enabled, allowing any unauthenticated user to connect to the FTP server. The root directory `/` is accessible though currently empty. Combined with the vsFTPd 2.3.4 backdoor, this machine is critically compromised. FTP transmits all data including credentials in plaintext and should be replaced with SFTP or FTPS. Anonymous access should be disabled.

**Risk Level:** `HIGH`

---

## Challenge 11 — SMB NSE Enumeration

**Objective:** Use Nmap Scripting Engine (NSE) scripts to enumerate SMB information including OS version, domain name, and user accounts via port 445.

**Commands:**
```bash
nmap --script smb-os-discovery -p445 192.168.56.104
nmap --script smb-enum-users -p445 192.168.56.104
```

**Actual Output — smb-os-discovery:**
```
PORT      STATE  SERVICE
445/tcp   open   microsoft-ds

Host script results:
| smb-os-discovery:
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: metasploitable
|   NetBIOS computer name:
|   Domain name: localdomain
|   FQDN: metasploitable.localdomain
|_  System time: 2026-05-03T03:14:00-04:00
```

**Actual Output — smb-enum-users (partial):**
```
| smb-enum-users:
|   METASPLOITABLE\backup (RID: 1068)
|   METASPLOITABLE\bin (RID: 1004)
|   METASPLOITABLE\bind (RID: 1210)
|   METASPLOITABLE\daemon (RID: 1002)
|   METASPLOITABLE\dhcp (RID: 1202)
|   METASPLOITABLE\distccd (RID: 1222)
|   METASPLOITABLE\ftp (RID: 1214)
|   METASPLOITABLE\games (RID: 1010)
|   METASPLOITABLE\gnats (RID: 1082)
|   METASPLOITABLE\irc (RID: 1078)
|   METASPLOITABLE\klog (RID: 1206)
|   METASPLOITABLE\libuuid (RID: 1200)
|   METASPLOITABLE\list (RID: 1076)
|   METASPLOITABLE\lp (RID: 1014)
|   METASPLOITABLE\mail (RID: 1016)
|   METASPLOITABLE\man (RID: 1012)
|   ... (more accounts)
```

**Findings:**

| Item | Details |
|------|---------|
| OS | Unix — Samba 3.0.20-Debian |
| Domain | localdomain |
| FQDN | metasploitable.localdomain |
| CVE | CVE-2007-2447 — Remote Code Execution |
| Users Discovered | 15+ system accounts enumerated |
| Metasploit Module | `exploit/multi/samba/usermap_script` |

**Analysis:**  
Samba 3.0.20 has CVE-2007-2447, which allows unauthenticated remote code execution. The user enumeration revealed more than 15 system accounts including service accounts (ftp, mail, irc, bind). This extensive user list provides attackers with multiple targets for brute-force attacks. Immediate upgrade to a current Samba version and restricting SMB access via firewall rules is required.

**Risk Level:** `CRITICAL`

---

## Challenge 16 — Version Detection

**Objective:** Use Nmap version detection to identify the exact software versions of all running services and correlate them with known CVEs.

**Command:**
```bash
nmap -sV 192.168.56.104
```

**Actual Output:**
```
PORT      STATE  SERVICE     VERSION
21/tcp    open   ftp         vsftpd 2.3.4
22/tcp    open   ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp    open   telnet      Linux telnetd
25/tcp    open   smtp        Postfix smtpd
53/tcp    open   domain      ISC BIND 9.4.2
80/tcp    open   http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)
111/tcp   open   rpcbind     2 (RPC #100000)
139/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
512/tcp   open   exec        netkit-rsh rexecd
513/tcp   open   login?
514/tcp   open   shell       Netkit rshd
1524/tcp  open   bindshell   Metasploitable root shell
2049/tcp  open   nfs         2-4 (RPC #100003)
3306/tcp  open   mysql       MySQL 5.0.51a-3ubuntu5
5432/tcp  open   postgresql  PostgreSQL DB 8.3.0 - 8.3.7
5900/tcp  open   vnc         VNC (protocol 3.3)
6000/tcp  open   X11         (access denied)
6667/tcp  open   irc         UnrealIRCd
8009/tcp  open   ajp13       Apache Jserv (Protocol v1.3)
8180/tcp  open   http        Apache Tomcat/Coyote JSP engine 1.1

OS: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

**Vulnerability Summary:**

| Service | Version | CVE | Severity |
|---------|---------|-----|---------|
| vsFTPd | 2.3.4 | CVE-2011-2523 |  CRITICAL |
| Samba | 3.0.20 | CVE-2007-2447 |  CRITICAL |
| UnrealIRCd | - | CVE-2010-2075 |  CRITICAL |
| bindshell | port 1524 | Backdoor |  CRITICAL |
| Apache | 2.2.8 | CVE-2017-7679 |  HIGH |
| OpenSSH | 4.7p1 | CVE-2008-0166 |  HIGH |
| ISC BIND | 9.4.2 | CVE-2008-1447 |  HIGH |
| Tomcat | 1.1 | CVE-2007-0450 |  HIGH |
| MySQL | 5.0.51a | CVE-2009-2446 |  MEDIUM |

**Analysis:**  
Version detection reveals that every service on Metasploitable 2 runs an outdated version with known critical vulnerabilities. Notably, port 1524 is running a `Metasploitable root shell` (bindshell) — a direct backdoor providing instant root access. UnrealIRCd also contains a backdoor (CVE-2010-2075). This highlights the critical importance of a consistent patch management programme in production environments.

**Risk Level:** `CRITICAL`

---

## Challenge 17 — OS Detection

**Objective:** Use Nmap OS detection to identify the target's operating system through TCP/IP stack fingerprinting.

**Command:**
```bash
nmap -O 192.168.56.104
```

**Actual Output:**
```
Warning: OSScan results may be unreliable because we could not find
at least 1 open and 1 closed port
Device type: VoIP adapter|bridge|general purpose
Running (JUST GUESSING): AT&T embedded (93%),
Oracle Virtualbox (92%), Slirp (92%), QEMU (90%)
OS CPE: cpe:/o:oracle:virtualbox cpe:/a:danny_gasparovski:slirp
Aggressive OS guesses: AT&T BGW210 voice gateway (93%),
Oracle VirtualBox Slirp NAT bridge (92%),
QEMU user mode network gateway (90%)
No exact OS matches for host (test conditions non-ideal).

OS detection performed.
Nmap done: 1 IP address (1 host up) scanned in 9.24 seconds
```

**Findings:**

| Item | Result |
|------|--------|
| OS Guess | AT&T embedded (93%), VirtualBox (92%) |
| Kernel Confirmation | TTL=64 from C5 → Linux confirmed |
| Open Ports | 20+ ports detected |
| Service Info | OS: Unix, Linux; CPE: cpe:/o:linux:linux_kernel |
| Note | Less accurate in VM environment |

**Analysis:**  
OS detection is less accurate in a VM environment because Nmap cannot find clearly closed ports (non-ideal test conditions). However, the service info from `nmap -sV` (Challenge 16) confirms `OS: Unix, Linux; CPE: cpe:/o:linux:linux_kernel`, and TTL=64 from Challenge 5 further confirms Linux. The detection of 20+ open ports indicates a very broad attack surface.

**Risk Level:** `HIGH`

---

## Summary Table

| No. | Challenge | Command | Key Finding | Risk | 
|-----|-----------|---------|-------------|------|
| C1 | NetBIOS Enumeration | `nmblookup -A` | SMB active `<20>`, Hostname: METASPLOITABLE, Domain: WORKGROUP | HIGH |
| C2 | Fast Nmap Scan | `nmap -F` | 18 open ports: FTP, Telnet, rsh, NFS, MySQL, VNC | CRITICAL | ✓ Done |
| C3 | DNS Records | `dig` / `nslookup` | A, AAAA, MX (smtp.google.com), NS, SOA records retrieved | LOW |
| C5 | TTL Fingerprinting | `ping` | TTL=64 → Linux confirmed, 0% packet loss | LOW |
| C7 | SMTP VRFY/EXPN | `nc port 25` | root & nobody confirmed exist, EXPN disabled | MEDIUM |
| C9 | FTP Banner | `nc port 21` | vsFTPd 2.3.4 — CVE-2011-2523 backdoor (CVSS 10.0) | CRITICAL |
| C10 | Anonymous FTP | `ftp` | Anonymous login successful, root directory accessible | HIGH |
| C11 | SMB NSE | `nmap --script` | Samba 3.0.20, 15+ user accounts enumerated | CRITICAL |
| C16 | Version Detection | `nmap -sV` | All services outdated; bindshell on port 1524 found | CRITICAL | 
| C17 | OS Detection | `nmap -O` | Linux confirmed via TTL + service CPE, 20+ ports open | HIGH |

