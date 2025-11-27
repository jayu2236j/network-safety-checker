#!/usr/bin/env python3
import os
import subprocess
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

console = Console()

log_file = "/var/log/network_safety_checker_python.log"
score = 10

# ---------- Logging ----------
def log(msg):
    with open(log_file, "a") as f:
        f.write(msg + "\n")
    console.print(msg)

# ---------- Section Title ----------
def section(title):
    console.print(Panel(title, style="bold blue"))

# ---------- Run Shell Commands ----------
def run(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, text=True).strip()
    except:
        return ""

# ---------- ROOT CHECK ----------
if os.geteuid() != 0:
    console.print("[bold red][ERROR][/bold red] Run as root: sudo python3 script.py")
    exit(1)

log(f"\n====== Network Safety Checker (Python) ======")
log(f"Started: {datetime.now()}")

# ==========================================================
# 1. FIREWALL
# ==========================================================
section("1. Firewall Status")

ufw = run("ufw status 2>/dev/null | head -n1")
firewalld = run("firewall-cmd --state 2>/dev/null")

if ufw:
    if "inactive" in ufw.lower():
        log("[yellow][WARN][/yellow] Firewall (UFW) is inactive.")
        score -= 2
    else:
        log("[green][OK][/green] Firewall (UFW) is active.")
elif firewalld:
    if "running" in firewalld:
        log("[green][OK][/green] firewalld is running.")
    else:
        log("[yellow][WARN][/yellow] firewalld inactive.")
        score -= 2
else:
    log("[yellow][WARN][/yellow] No firewall detected.")
    score -= 2

# ==========================================================
# 2. OPEN PORTS
# ==========================================================
section("2. Open Ports (first 15)")

ports = run("ss -tulpn | head -n 15")
if not ports:
    ports = run("netstat -tulpn | head -n 15")

log(ports if ports else "[red]Unable to list ports[/red]")

# ==========================================================
# 3. SSH CONFIG
# ==========================================================
section("3. SSH Configuration")

ssh_conf = "/etc/ssh/sshd_config"

if os.path.exists(ssh_conf):
    root_login = run("grep -Ei '^\\s*PermitRootLogin' /etc/ssh/sshd_config | awk '{print $2}'")

    if root_login == "yes":
        log("[yellow][WARN][/yellow] SSH root login ENABLED.")
        score -= 2
    else:
        log("[green][OK][/green] Root login disabled.")

    pass_auth = run("grep -Ei '^\\s*PasswordAuthentication' /etc/ssh/sshd_config | awk '{print $2}'")
    if pass_auth == "yes":
        log("[yellow][WARN][/yellow] SSH password auth ENABLED.")
        score -= 1
    else:
        log("[green][OK][/green] SSH password auth disabled.")
else:
    log("[yellow][INFO][/yellow] SSH config not found.")

# ==========================================================
# 4. EMPTY PASSWORD USERS
# ==========================================================
section("4. Empty Password Users")

shadow_data = run("awk -F: '($2 == \"\") {print $1}' /etc/shadow")
if shadow_data:
    log("[red][ALERT][/red] Users with empty passwords:")
    log(shadow_data)
    score -= 3
else:
    log("[green][OK][/green] No empty-password users.")

# ==========================================================
# 5. WORLD-WRITABLE FILES
# ==========================================================
section("5. World-Writable Files in /etc")

ww = run("find /etc -type f -perm -0002 2>/dev/null")
if ww:
    log("[yellow][WARN][/yellow] World-writable files found:")
    log(ww)
    score -= 2
else:
    log("[green][OK][/green] No world-writable files.")

# ==========================================================
# 6. UPDATE CHECK
# ==========================================================
section("6. Update Check")

if run("command -v apt"):
    run("apt update -qq")
    upg = run("apt list --upgradable 2>/dev/null | grep -vc 'Listing'")
    try:
        upg = int(upg)
        if upg > 0:
            log(f"[yellow][WARN][/yellow] {upg} packages can be upgraded.")
            score -= 1
        else:
            log("[green][OK][/green] System fully updated.")
    except:
        log("[yellow][INFO][/yellow] Update check skipped.")

# ==========================================================
# 7. FAIL2BAN
# ==========================================================
section("7. Fail2Ban")

if run("command -v fail2ban-client"):
    if run("systemctl is-active fail2ban") == "active":
        log("[green][OK][/green] Fail2Ban running.")
    else:
        log("[yellow][WARN][/yellow] Fail2Ban installed but not running.")
        score -= 1
else:
    log("[yellow][WARN][/yellow] Fail2Ban not installed.")
    score -= 1

# ==========================================================
# 13. MITM DETECTION
# ==========================================================
section("13. MITM / ARP Spoofing Detection")

gateway = run("ip route | grep default | awk '{print $3}'")

if gateway:
    mac_count = run(f"arp -n | grep {gateway} | awk '{{print $3}}' | wc -l")

    if int(mac_count) > 1:
        log("[red][ALERT][/red] Multiple MAC addresses for gateway! Possible MITM.")
        score -= 3
    else:
        log("[green][OK][/green] No MITM detected.")
else:
    log("[yellow][WARN][/yellow] No gateway found. Skipping ARP check.")

# ==========================================================
# 14. SPEED TEST
# ==========================================================
section("14. Speed Test (Cloudflare)")

if run("command -v curl"):

    # DOWNLOAD
    down_raw = run("curl -o /dev/null -s -w '%{speed_download}' https://speed.cloudflare.com/__down?bytes=50000000")
    try:
        down_mbps = round(float(down_raw) / 125000, 2)
        log(f"[green][OK][/green] Download: {down_mbps} Mbps")
    except:
        log("[yellow][WARN][/yellow] Download test failed.")

    # UPLOAD
    upload_raw = run("dd if=/dev/zero bs=1M count=5 2>/dev/null | curl -o /dev/null -s -w '%{speed_upload}' -X POST --data-binary @- https://speed.cloudflare.com/__up")
    try:
        up_mbps = round(float(upload_raw) / 125000, 2)
        log(f"[green][OK][/green] Upload: {up_mbps} Mbps")
    except:
        log("[yellow][WARN][/yellow] Upload test failed.")
else:
    log("[yellow][WARN][/yellow] curl not installed — skipping speed test.")
    score -= 1

# ==========================================================
# FINAL SCORE
# ==========================================================
section("FINAL SECURITY SCORE")

if score >= 9:
    console.print(f"[bold green]Score: {score}/10 (Secure)[/bold green]")
elif score >= 6:
    console.print(f"[bold yellow]Score: {score}/10 (Moderate Risk)[/bold yellow]")
else:
    console.print(f"[bold red]Score: {score}/10 (High Risk)[/bold red]")

console.print(f"[blue]Log file saved to: {log_file}[/blue]")
