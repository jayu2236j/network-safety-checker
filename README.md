# Network Safety Checker – USB Security Toolkit  
A complete, portable Linux-based security auditing tool designed to quickly check the safety of a system.  
It analyzes firewall settings, open ports, SSH security, user accounts, dangerous services, permissions, patch levels, and even detects Man-in-the-Middle (MITM) attacks on public Wi-Fi.

This README includes:
- Project overview  
- Full section explanation (1–12)  
- Installation  
- Usage  
- USB use-case  
- Windows/Mac instructions  
- Portfolio/LinkedIn details  

---

# 1. About the Project  
The Network Safety Checker is a **portable security scanner** that runs on any Linux system.  
It gives you:

- A full security audit  
- Clear warnings  
- A security score out of 10  
- ARP-based MITM attack detection  
- Logging for reports  

You can run it:
- In normal Linux  
- In a virtual machine  
- In a Live USB environment  
- From a USB toolkit  

---

# 2. Features (Section Explanations)

## **Section 1 — Firewall Check**
Checks whether `ufw` or `firewalld` is running.
- If inactive → lowers score
- If active → good

## **Section 2 — Open Ports**
Shows the first 15 listening services using:
- `ss -tulpn` or
- `netstat -tulpn`

Useful to spot:
- FTP (21)
- Telnet (23)
- Unknown services

## **Section 3 — SSH Configuration**
Checks:
- Whether root login is allowed
- Whether password authentication is enabled  
Weak SSH settings reduce your score.

## **Section 4 — Empty Password Users**
Reads `/etc/shadow` to find accounts with no password.

## **Section 5 — World-Writable Files in /etc**
Searches for dangerous files that anyone can modify.

## **Section 6 — System Update Check**
Looks for missing updates (APT systems only).  
If many updates are pending → security score decreases.

## **Section 7 — Fail2Ban Status**
Checks if Fail2Ban is installed and active.

## **Section 8 — Dangerous Services**
Scans for old insecure services:
- telnet  
- ftp  
- rlogin  
- rsh

## **Section 9 — Home Directory Permissions**
Ensures the user’s home folder is not world-readable.

## **Section 10 — Kernel Version Check**
Reports current kernel and its update status.

## **Section 11 — Patch Summary**
Simulates an APT upgrade and prints upgrade summary.

## **Section 12 — MITM / ARP Spoofing Detection**
Analyzes the ARP table to see if:
- More than one MAC address is claiming to be the gateway  
This strongly suggests ARP spoofing or a Man-in-the-Middle attack.

This is the “special” feature that improves your project.

---

# 3. Installation (Linux)

### Make scripts executable:
```bash
chmod +x install.sh
chmod +x network_safety_checker.sh
