#!/usr/bin/env bash
# Network Safety Checker – Advanced Version
# Simple Linux security audit script for learning purposes.

# ========== COLORS ==========
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
BOLD="\e[1m"
RESET="\e[0m"

# ========== SECURITY SCORE ==========
score=10   # start from 10 and subtract for issues

# ========== ROOT CHECK ==========
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}[ERROR]${RESET} Please run this script as root. Try: sudo $0"
  exit 1
fi

# ========== LOGGING ==========
LOGFILE="/var/log/network_safety_checker.log"
# send all output to both screen and logfile
exec > >(tee -a "$LOGFILE") 2>&1

# ========== ASCII BANNER ==========
echo -e "${BLUE}"
cat << "EOF"
 _   _      _                  _             
| \ | | ___| |__   ___  _ __  | | ___   __ _ 
|  \| |/ _ \ '_ \ / _ \| '_ \ | |/ _ \ / _` |
| |\  |  __/ |_) | (_) | | | || | (_) | (_| |
|_| \_|\___|_.__/ \___/|_| |_||_|\___/ \__,_|

EOF
echo -e "${RESET}"

echo -e "${BOLD}${BLUE}======================================"
echo "           NETWORK SAFETY CHECKER"
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

# ========== 7. FAIL2BAN STATUS ==========
section "7. Fail2Ban Status"

if command -v fail2ban-client >/dev/null 2>&1; then
    if systemctl is-active --quiet fail2ban 2>/dev/null; then
        echo -e "${GREEN}[OK]${RESET} Fail2Ban is installed and running."
    else
        echo -e "${YELLOW}[WARN]${RESET} Fail2Ban is installed but not running."
        score=$((score - 1))
    fi
else
    echo -e "${YELLOW}[WARN]${RESET} Fail2Ban is not installed."
    score=$((score - 1))
fi

# ========== 8. DANGEROUS SERVICES ==========
section "8. Potentially Dangerous Services"

services=(telnet ftp rlogin rsh)

for svc in "${services[@]}"; do
    if systemctl list-unit-files 2>/dev/null | grep -q "^${svc}\."; then
        if systemctl is-enabled --quiet "$svc" 2>/dev/null; then
            echo -e "${YELLOW}[WARN]${RESET} Potentially dangerous service enabled: $svc"
            score=$((score - 2))
        else
            echo -e "${BLUE}[INFO]${RESET} Service $svc exists but is not enabled."
        fi
    fi
done

# ========== 9. HOME DIRECTORY PERMISSIONS ==========
section "9. Home Directory Permission Check"

target_user="${SUDO_USER:-$USER}"
user_home=$(eval echo "~$target_user")

if [[ -d "$user_home" ]]; then
    perms=$(stat -c %a "$user_home" 2>/dev/null)
    echo -e "${BLUE}[INFO]${RESET} Home directory for user $target_user is $user_home with permissions $perms"

    if [[ "$perms" -gt 750 ]]; then
        echo -e "${YELLOW}[WARN]${RESET} Home directory permissions are quite open. Consider using 750 or 700."
        score=$((score - 1))
    else
        echo -e "${GREEN}[OK]${RESET} Home directory permissions look reasonable."
    fi
else
    echo -e "${YELLOW}[INFO]${RESET} Could not determine home directory for user $target_user."
fi

# ========== 10. KERNEL VERSION CHECK ==========
section "10. Kernel Version Check"

if command -v apt >/dev/null 2>&1; then
    current_kernel=$(uname -r)
    echo -e "${BLUE}[INFO]${RESET} Current running kernel: $current_kernel"

    candidate_line=$(apt-cache policy "linux-image-$current_kernel" 2>/dev/null | grep Candidate)
    candidate_version=$(echo "$candidate_line" | awk '{print $2}')

    if [[ -n "$candidate_version" ]]; then
        echo -e "${BLUE}[INFO]${RESET} Package candidate for this kernel: $candidate_version"
    fi

    # This is a simple check; a more advanced tool would compare against all available kernels.
else
    echo -e "${YELLOW}[INFO]${RESET} apt is not available. Skipping kernel package check."
fi

# ========== 11. DETAILED PATCH SUMMARY ==========
section "11. Patch Summary (APT Simulation)"

if command -v apt-get >/dev/null 2>&1; then
    sim_output=$(apt-get -s upgrade 2>/dev/null | awk '/^[0-9]+ upgraded, [0-9]+ newly installed/ {print}')
    if [[ -n "$sim_output" ]]; then
        echo -e "${BLUE}[INFO]${RESET} apt-get -s upgrade summary:"
        echo "$sim_output"
    else
        echo -e "${BLUE}[INFO]${RESET} No upgrade summary available or no upgrades pending."
    fi
else
    echo -e "${YELLOW}[INFO]${RESET} apt-get not available. Skipping patch summary."
fi

# ========== 12. CVE / VULNERABILITY INFO (BASIC STUB) ==========
section "12. Vulnerability Information (Basic)"

if command -v curl >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${RESET} curl is installed. In a full version, this section could"
    echo "download vulnerability data from a security tracker such as:"
    echo "https://security-tracker.debian.org/tracker/data/json"
    echo "and compare it with installed packages."
    echo "For this student project, we only describe the idea instead of running a heavy check."
else
    echo -e "${YELLOW}[WARN]${RESET} curl is not installed, so remote vulnerability checks are not available."
fi

# ========== 13. MITM / ARP Spoofing Detection ==========
section "13. MITM / ARP Spoofing Detection"

# Find default gateway IP (your router)
gateway_ip=$(ip route | grep default | awk '{print $3}')

if [[ -z "$gateway_ip" ]]; then
    echo -e "${YELLOW}[WARN]${RESET} Could not detect a default gateway. You may not be connected to a network."
    echo -e "${YELLOW}[INFO]${RESET} Skipping MITM detection."
else
    echo -e "${BLUE}[INFO]${RESET} Gateway detected at: $gateway_ip"
    echo -e "${BLUE}[INFO]${RESET} Checking ARP table for spoofing attempts..."

    # Count how many MAC addresses claim to be the gateway
    gateway_mac_count=$(arp -n | grep "$gateway_ip" | awk '{print $3}' | wc -l)

    if (( gateway_mac_count > 1 )); then
        echo -e "${RED}[ALERT]${RESET} Multiple devices are responding as your router!"
        echo -e "${RED}[ALERT]${RESET} Possible Wi-Fi MITM (Man-in-the-Middle) attack detected!"
        echo -e "${RED}[ALERT]${RESET} Someone may be intercepting your network traffic."
        score=$((score - 3))
    else
        echo -e "${GREEN}[OK]${RESET} No MITM behavior detected. Your network appears safe."
    fi
fi

# ========== 14. NETWORK SPEED TEST (Download + Upload) ==========
section "14. Network Speed Test"

if command -v curl >/dev/null 2>&1; then
    echo -e "${BLUE}[INFO]${RESET} Running download speed test (Cloudflare)..."

    # ---- DOWNLOAD TEST ----
    download_raw=$(curl -o /dev/null -s -w '%{speed_download}' "https://speed.cloudflare.com/__down?bytes=50000000")
    download_mbps=$(echo "scale=2; $download_raw / 125000" | bc)

    echo -e "${GREEN}[OK]${RESET} Download speed: ${download_mbps} Mbps"

    # ---- UPLOAD TEST ----
    echo -e "${BLUE}[INFO]${RESET} Running upload speed test (Cloudflare)..."

    # We generate 5MB of data and upload it
    upload_raw=$(dd if=/dev/zero bs=1M count=5 2>/dev/null | \
                 curl -o /dev/null -s -w '%{speed_upload}' -X POST \
                 --data-binary @- "https://speed.cloudflare.com/__up")

    upload_mbps=$(echo "scale=2; $upload_raw / 125000" | bc)

    echo -e "${GREEN}[OK]${RESET} Upload speed: ${upload_mbps} Mbps"

else
    echo -e "${YELLOW}[WARN]${RESET} curl not installed — cannot run speed test."
    score=$((score - 1))
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
echo -e "Log file saved to: $LOGFILE"
echo -e "======================================${RESET}"
