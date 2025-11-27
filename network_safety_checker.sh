#!/usr/bin/env bash
# Network Safety Checker with Colors + Security Score
# Author: Your Name
# Simple security audit script for Linux

# ========== COLORS ==========
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

# SECURITY SCORE (start from 10 and subtract for each issue)
score=10

# ========== ROOT CHECK ==========
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[ERROR]${RESET} Please run this script as root. Try: sudo $0"
  exit 1
fi

echo -e "${BOLD}${BLUE}======================================"
echo "         NETWORK SAFETY CHECKER"
echo "======================================${RESET}"

section() {
  echo -e "\n${BOLD}${BLUE}--- $1 ---${RESET}"
}

# ========== 1. FIREWALL CHECK ==========
section "1. Firewall Status"

if command -v ufw >/dev/null 2>&1; then
    ufw_state=$(ufw status | head -n1)
    echo -e "${BLUE}[INFO]${RESET} ufw detected."

    if echo "$ufw_state" | grep -qi "inactive"; then
        echo -e "${YELLOW}[WARN]${RESET} Firewall is INACTIVE."
        score=$((score - 2))
    else
        echo -e "${GREEN}[OK]${RESET} Firewall appears to be active."
    fi
elif command -v firewall-cmd >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${RESET} firewalld detected."
    if firewall-cmd --state 2>/dev/null | grep -qi "running"; then
        echo -e "${GREEN}[OK]${RESET} firewalld is running."
    else
        echo -e "${YELLOW}[WARN]${RESET} firewalld is installed but not running."
        score=$((score - 2))
    fi
else
    echo -e "${YELLOW}[WARN]${RESET} No common firewall tool (ufw or firewalld) found."
    score=$((score - 2))
fi

# ========== 2. OPEN PORTS ==========
section "2. Open Network Ports"

if command -v ss >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${RESET} Showing first 15 listening ports:"
    ss -tulpn 2>/dev/null | head -n 15
elif command -v netstat >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${RESET} Using netstat to list listening ports (first 15):"
    netstat -tulpn 2>/dev/null | head -n 15
else
    echo -e "${RED}[ERROR]${RESET} Neither 'ss' nor 'netstat' is available to list ports."
fi

echo -e "${BLUE}Tip:${RESET} Look for unexpected services such as Telnet (23), FTP (21), or unused web servers."

# ========== 3. SSH CONFIG ==========
section "3. SSH Configuration"

SSH_CONFIG="/etc/ssh/sshd_config"

if [[ -f $SSH_CONFIG ]]; then
    root_login=$(grep -Ei '^\s*PermitRootLogin' "$SSH_CONFIG" | awk '{print $2}' | tail -n1)

    if [[ "$root_login" == "yes" ]]; then
        echo -e "${YELLOW}[WARN]${RESET} SSH root login is ENABLED (PermitRootLogin yes)."
        score=$((score - 2))
    else
        echo -e "${GREEN}[OK]${RESET} SSH root login is disabled or restricted."
    fi

    pass_auth=$(grep -Ei '^\s*PasswordAuthentication' "$SSH_CONFIG" | awk '{print $2}' | tail -n1)

    if [[ "$pass_auth" == "yes" ]]; then
        echo -e "${YELLOW}[WARN]${RESET} SSH password authentication is ENABLED."
        score=$((score - 1))
    else
        echo -e "${GREEN}[OK]${RESET} SSH password authentication is disabled or not set to yes."
    fi
else
    echo -e "${YELLOW}[INFO]${RESET} SSH server configuration file not found at $SSH_CONFIG. SSH server may not be installed."
fi

# ========== 4. EMPTY PASSWORD USERS ==========
section "4. Users With Empty Passwords"

if [[ -r /etc/shadow ]]; then
    empty_users=$(awk -F: '($2 == "") {print $1}' /etc/shadow)

    if [[ -n "$empty_users" ]]; then
        echo -e "${RED}[ALERT]${RESET} The following users have no password set:"
        echo "$empty_users"
        score=$((score - 3))
    else
        echo -e "${GREEN}[OK]${RESET} No user accounts with empty passwords were found."
    fi
else
    echo -e "${RED}[ERROR]${RESET} Cannot read /etc/shadow. Are you running as root?"
fi

# ========== 5. WORLD-WRITABLE FILES ==========
section "5. World-Writable Files in /etc"

echo -e "${BLUE}[INFO]${RESET} Scanning /etc for world-writable files (this can take a moment)..."
ww_files=$(find /etc -type f -perm -0002 2>/dev/null)

if [[ -n "$ww_files" ]]; then
    echo -e "${YELLOW}[WARN]${RESET} Found world-writable files in /etc:"
    echo "$ww_files"
    score=$((score - 2))
else
    echo -e "${GREEN}[OK]${RESET} No world-writable files in /etc were found."
fi

# ========== 6. UPDATE CHECK ==========
section "6. System Update Check (APT-Based Systems)"

if command -v apt >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${RESET} Checking for available updates..."
    apt update -qq >/dev/null 2>&1
    upgradable_count=$(apt list --upgradable 2>/dev/null | grep -vc "Listing")
    if [[ "$upgradable_count" -gt 0 ]]; then
        echo -e "${YELLOW}[WARN]${RESET} There are $upgradable_count packages that can be upgraded."
        echo "You can update them with: sudo apt upgrade"
        score=$((score - 1))
    else
        echo -e "${GREEN}[OK]${RESET} No pending upgrades detected."
    fi
else
    echo -e "${YELLOW}[INFO]${RESET} apt is not available. Skipping update check."
fi

# ========== FINAL SCORE ==========
echo -e "\n${BOLD}${BLUE}========== SECURITY SCORE ==========${RESET}"

if (( score >= 9 )); then
  echo -e "${GREEN}Your system score: $score / 10 (Secure)${RESET}"
elif (( score >= 6 )); then
  echo -e "${YELLOW}Your system score: $score / 10 (Moderate risk)${RESET}"
else
  echo -e "${RED}Your system score: $score / 10 (High risk)${RESET}"
fi

echo -e "${BLUE}======================================${RESET}"
echo "Review the warnings and alerts above to improve your system security."
echo -e "======================================${RESET}"
