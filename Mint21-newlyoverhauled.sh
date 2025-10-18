#!/bin/bash

# --- CyberPatriot Ultimate Linux Mint 21 Hardening Script (v5) ---
#
# This script integrates CIS benchmarks, checklists, and custom security functions
# into a comprehensive, interactive hardening tool with JSON-based progress tracking.
#
# USAGE: sudo ./ultimate_mint_hardener.sh
#

# --- PRE-FLIGHT CHECKS ---
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root. Please use 'sudo ./ultimate_mint_hardener.sh'."
   exit 1
fi

# --- GLOBAL VARIABLES & HELPER FUNCTIONS ---

# Correctly identify the home directory of the user who invoked sudo
SUDO_USER=${SUDO_USER:-$(whoami)}
HOME_DIR=$(getent passwd "$SUDO_USER" | cut -d: -f6)

BACKUP_DIR="/root/cp_backups_$(date +%Y%m%d_%H%M%S)"
PROGRESS_FILE="$HOME_DIR/Desktop/.cp_progress.json"
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info() { echo -e "${YELLOW}[INFO] $1${NC}"; }
success() { echo -e "${GREEN}[SUCCESS] $1${NC}"; }
warn() { echo -e "${RED}[WARNING] $1${NC}"; }

ask_permission() {
    read -p "$(echo -e ${YELLOW}"[PROMPT] ${1} (y/n)? "${NC})" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        info "Skipping."
        return 1
    fi
    return 0
}

pause() {
    read -p "Press [Enter] to continue..."
}

# --- JSON Progress Tracking Functions ---

check_jq() {
    if ! command -v jq &> /dev/null; then
        warn "'jq' is not installed. It is required for progress tracking."
        if ask_permission "Do you want to install 'jq' now?"; then
            info "Installing jq..."
            apt-get update && apt-get install -y jq
            hash -r # Re-hash PATH to find the new command
            if ! command -v jq &> /dev/null; then
                warn "Failed to install jq. Progress tracking will be disabled."
                return 1
            fi
            success "jq installed successfully."
        else
            warn "Progress tracking will be disabled for this session."
            return 1
        fi
    fi
    return 0
}

initialize_progress_file() {
    # Ensure Desktop directory exists
    if [[ ! -d "$HOME_DIR/Desktop" ]]; then
        mkdir -p "$HOME_DIR/Desktop"
        chown "$SUDO_USER:$SUDO_USER" "$HOME_DIR/Desktop"
    fi
    
    # Create a valid JSON file if it doesn't exist or is invalid
    if [[ ! -f "$PROGRESS_FILE" ]] || ! jq -e . "$PROGRESS_FILE" >/dev/null 2>&1; then
        echo "{}" > "$PROGRESS_FILE"
        chown "$SUDO_USER:$SUDO_USER" "$PROGRESS_FILE"
        info "Progress file created on your desktop: .cp_progress.json"
    fi
}

mark_done() {
    if ! $JQ_ENABLED; then return; fi
    local tmp_file
    tmp_file=$(mktemp)
    jq --arg step "$1" '.[$step] = true' "$PROGRESS_FILE" > "$tmp_file" && mv "$tmp_file" "$PROGRESS_FILE"
}

check_done() {
    if ! $JQ_ENABLED; then return; fi
    if jq -e --arg step "$1" '.[$step] == true' "$PROGRESS_FILE" >/dev/null 2>&1; then
        echo -e "${GREEN}(DONE)${NC}"
    fi
}

# --- SCRIPT FUNCTIONS ---

function initial_setup() {
    info "--- 1) Perform Initial Backups of Critical Files ---"
    info "This step creates a timestamped backup of critical configuration files."
    if ! ask_permission "Proceed with file backups?"; then return; fi

    if [[ -d "$BACKUP_DIR" ]]; then
        warn "Backup directory already exists for this session. Skipping."
    else
        mkdir -p "$BACKUP_DIR"
        info "Backing up configurations to $BACKUP_DIR..."
        targets=(/etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/apt/sources.list* /etc/ssh /etc/pam.d /etc/login.defs /etc/sysctl.conf /etc/sysctl.d /etc/lightdm)
        for target in "${targets[@]}"; do cp -R "$target" "$BACKUP_DIR/" 2>/dev/null; done
        success "Critical files backed up."
        mark_done 1
    fi
    pause
}

function update_system() {
    info "--- 2) Update System Repositories and Packages ---"
    info "This section allows you to review software sources and apply all system updates."
    if ! ask_permission "Proceed with system updates?"; then return; fi

    if ask_permission "Interactively review APT sources list?"; then
        info "Review /etc/apt/sources.list and files in /etc/apt/sources.list.d/ for suspicious repositories."
        nano /etc/apt/sources.list
        ls -l /etc/apt/sources.list.d/
        read -p "Enter a file in sources.list.d to edit (or Enter to skip): " source_file
        [[ -f "/etc/apt/sources.list.d/$source_file" ]] && nano "/etc/apt/sources.list.d/$source_file"
    fi
    if ask_permission "Update all system packages now?"; then
        info "Updating package lists... Please review the progress below."
        apt-get update
        info "Upgrading packages..."
        apt-get upgrade -y
        info "Removing unused packages..."
        apt-get autoremove -y
    fi
    success "System update process complete."
    mark_done 2
    pause
}

function user_and_group_management() {
    info "--- 3) User and Group Management (Interactive) ---"
    info "This section helps you audit and correct user accounts and administrator privileges."
    if ! ask_permission "Proceed with user and group management?"; then return; fi

    echo "Current Non-System Users (UID >= 1000):" && awk -F: '($3 >= 1000 && $1 != "nfsnobody") {print $1}' /etc/passwd
    echo -e "\nCurrent Administrators (members of 'sudo' group):" && grep '^sudo:.*$' /etc/group | cut -d: -f4
    
    if ask_permission "Interactively remove unauthorized users?"; then
        for user in $(awk -F: '($3 >= 1000 && $1 != "nfsnobody") {print $1}' /etc/passwd); do
            [[ "$user" == "$(logname)" ]] && info "Skipping current logged-in user: $user" && continue
            ask_permission "  -> Remove user '$user'?" && deluser --remove-home "$user" && success "User '$user' removed."
        done
    fi
    if ask_permission "Interactively manage the 'sudo' administrator group?"; then
        current_admins=$(grep '^sudo:.*$' /etc/group | cut -d: -f4 | tr ',' ' ')
        for admin in $current_admins; do
            [[ "$admin" == "$(logname)" || "$admin" == "root" ]] && continue
            ! ask_permission "  -> Should '$admin' remain an administrator?" && gpasswd -d "$admin" sudo && success "User '$admin' removed from sudo group."
        done
    fi
    if ask_permission "Disable the Guest account?"; then
        mkdir -p /etc/lightdm/lightdm.conf.d/ && echo -e "[Seat:*]\nallow-guest=false" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf
        success "Guest account login disabled."
    fi
    if ask_permission "Lock the root account to prevent direct login?"; then
        passwd -l root > /dev/null 2>&1 && usermod -s /usr/sbin/nologin root
        success "Root account has been locked."
    fi
    success "User and group management complete."
    mark_done 3
    pause
}

function password_policies() {
    info "--- 4) Apply Password & Lockout Policies (PAM & login.defs) ---"
    info "This enforces strong password requirements and account lockout rules."
    if ! ask_permission "Proceed with applying password policies?"; then return; fi
    
    warn "This modifies critical PAM configurations."
    if ask_permission "Install 'libpam-pwquality' for password strength checking?"; then
        info "Installing libpam-pwquality..."
        apt-get install -y libpam-pwquality
    fi
    if ask_permission "Enforce strong password complexity (14 chars, 4 classes, history)?"; then
        sed -i 's/remember=[0-9]*/remember=5/' /etc/pam.d/common-password
        if ! grep -q "remember=" /etc/pam.d/common-password; then sed -i '/pam_unix.so/s/$/ remember=5/' /etc/pam.d/common-password; fi
        if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
            sed -i '/pam_unix.so/i password\trequisite\t\tpam_pwquality.so retry=3 minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1' /etc/pam.d/common-password
        else
            sed -i '/pam_pwquality.so/s/$/ minlen=14 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1/' /etc/pam.d/common-password
        fi
        success "Password complexity and history rules applied."
    fi
    if ask_permission "Set password expiration policies (90-day max, 10-day min)?"; then
        sed -i -E 's/^\s*PASS_MAX_DAYS\s+.*/PASS_MAX_DAYS\t90/' /etc/login.defs
        sed -i -E 's/^\s*PASS_MIN_DAYS\s+.*/PASS_MIN_DAYS\t10/' /etc/login.defs
        sed -i -E 's/^\s*PASS_WARN_AGE\s+.*/PASS_WARN_AGE\t7/' /etc/login.defs
        success "Password expiration policies set."
    fi
    if ask_permission "Enforce account lockout after 5 failed attempts?"; then
        info "Applying modern 'pam_faillock' rules for account lockout."
        # Backup original files before overwriting
        cp /etc/pam.d/common-auth "$BACKUP_DIR/common-auth.bak"
        cp /etc/pam.d/common-account "$BACKUP_DIR/common-account.bak"
        
        # Overwrite common-auth with the correct faillock configuration
        cat > /etc/pam.d/common-auth << EOF
# /etc/pam.d/common-auth - authentication settings overridden by hardening script
auth    required                        pam_faillock.so preauth silent audit deny=5 unlock_time=1800
auth    [success=1 default=ignore]      pam_unix.so nullok
auth    [default=die]                   pam_faillock.so authfail audit deny=5 unlock_time=1800
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
EOF
        # Add the required line to common-account to reset the counter on success
        if ! grep -q "pam_faillock.so" /etc/pam.d/common-account; then
            echo "account required pam_faillock.so" >> /etc/pam.d/common-account
        fi
        success "Account lockout policy applied using pam_faillock."
        info "You can reset a locked account with: sudo faillock --user <username> --reset"
    fi
    success "Password and lockout policy configuration complete."
    mark_done 4
    pause
}


function service_management() {
    info "--- 5) Interactively Disable/Remove Insecure Services ---"
    info "This will check for common insecure services and ask to remove them one by one."
    if ! ask_permission "Proceed with service management?"; then return; fi

    declare -A services_to_check
    services_to_check=(
        ["telnet"]="Unencrypted remote login | Impact: LOW"
        ["samba"]="Windows file sharing | Impact: MEDIUM"
        ["nfs-kernel-server"]="UNIX file sharing | Impact: MEDIUM"
        ["vsftpd"]="Unencrypted file transfer server | Impact: LOW"
        ["apache2"]="Web Server, disable if not needed | Impact: HIGH"
        ["nginx"]="Web Server, disable if not needed | Impact: HIGH"
        ["cups"]="Printing service, unnecessary on servers | Impact: MEDIUM"
        ["avahi-daemon"]="Zero-config networking, often not needed | Impact: MEDIUM"
        ["slapd"]="LDAP Server, disable if not a directory server | Impact: HIGH"
        ["rpcbind"]="Portmapper for NFS, insecure | Impact: MEDIUM"
        ["john"]="John the Ripper, password cracker | Impact: LOW"
        ["hydra"]="Hydra, network login cracker | Impact: LOW"
        ["nmap"]="Nmap, network scanner | Impact: LOW"
        ["wireshark"]="Wireshark, graphical packet sniffer | Impact: LOW"
        ["metasploit-framework"]="Metasploit, pentesting framework | Impact: LOW"
        ["netcat-traditional"]="Netcat, versatile network tool | Impact: LOW"
    )

    for pkg in "${!services_to_check[@]}"; do
        if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
            description=${services_to_check[$pkg]}
            if ask_permission "Purge: $pkg - $description?"; then
                info "Purging $pkg..."
                apt-get purge --autoremove -y "$pkg"
                success "Package '$pkg' purged."
            fi
        fi
    done
    success "Review of insecure services is complete."
    mark_done 5
    pause
}

function service_hardening() {
    info "--- 6) Harden Services (SSH & Apache) ---"
    info "This applies security best practices to installed services."
    if ! ask_permission "Proceed with service hardening?"; then return; fi
    
    # SSH Hardening
    if dpkg-query -W -f='${Status}' "openssh-server" 2>/dev/null | grep -q "install ok installed"; then
        if ask_permission "Apply hardening to SSH configuration?"; then
            sshd_config="/etc/ssh/sshd_config"
            cp "$sshd_config" "$BACKUP_DIR/sshd_config.bak"
            sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' "$sshd_config"
            sed -i -E 's/^#?Protocol.*/Protocol 2/' "$sshd_config"
            sed -i -E 's/^#?LogLevel.*/LogLevel VERBOSE/' "$sshd_config"
            info "Restarting SSH service to apply changes..."
            systemctl restart sshd
            success "SSH server hardened."
        fi
    fi
    
    # Apache Hardening
    if dpkg-query -W -f='${Status}' "apache2" 2>/dev/null | grep -q "install ok installed"; then
        if ask_permission "Apply hardening to Apache configuration?"; then
            echo "ServerSignature Off" > /etc/apache2/conf-available/99-hardening.conf
            echo "ServerTokens Prod" >> /etc/apache2/conf-available/99-hardening.conf
            a2enconf 99-hardening >/dev/null 2>&1
            info "Restarting Apache service to apply changes..."
            systemctl restart apache2
            success "Apache hardened (ServerSignature Off, ServerTokens Prod)."
        fi
    fi
    success "Service hardening section complete."
    mark_done 6
    pause
}

function network_hardening() {
    info "--- 7) Harden Network Settings (UFW & sysctl) ---"
    info "This configures the host firewall and applies secure kernel settings."
    if ! ask_permission "Proceed with network hardening?"; then return; fi

    if ask_permission "Install and enable UFW (Uncomplicated Firewall)?"; then
        info "Installing UFW..."
        apt-get install -y ufw
        ufw reset > /dev/null
        ufw default deny incoming; ufw default allow outgoing; ufw logging on
        [[ $(dpkg-query -W -f='${Status}' "openssh-server" 2>/dev/null) == "install ok installed" ]] && ufw allow ssh && info "UFW rule for SSH added."
        ufw --force enable
        success "UFW enabled with default-deny policy for incoming traffic."
    fi
    if ask_permission "Apply CIS kernel network hardening (sysctl)?"; then
        cat > /etc/sysctl.d/99-cis-hardening.conf << EOF
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.tcp_syncookies=1
EOF
        sysctl --system
        success "CIS kernel network parameters hardened."
    fi
    success "Network hardening complete."
    mark_done 7
    pause
}

function filesystem_hardening() {
    info "--- 8) Harden Filesystem & Permissions (CIS Compliant) ---"
    info "This section applies secure mount options and critical file permissions."
    if ! ask_permission "Proceed with filesystem hardening?"; then return; fi

    if ask_permission "Apply secure mount options for /tmp and /dev/shm?"; then
        if ! grep -q "/tmp" /etc/fstab; then echo "tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec 0 0" >> /etc/fstab; fi
        if ! grep -q "/dev/shm" /etc/fstab; then echo "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec 0 0" >> /etc/fstab; fi
        mount -a
        success "Mount options for /tmp and /dev/shm hardened."
    fi
    if ask_permission "Apply CIS permissions to critical account files?"; then
        chown root:root /etc/passwd && chmod 644 /etc/passwd
        chown root:shadow /etc/shadow && chmod 640 /etc/shadow
        chown root:root /etc/group && chmod 644 /etc/group
        chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow
        success "Permissions set for critical account files."
    fi
    success "Filesystem hardening complete."
    mark_done 8
    pause
}

function audit_and_scan() {
    info "--- 9) Install & Run Security Scans ---"
    info "This installs and runs tools for detecting rootkits, malware, and intrusions."
    if ! ask_permission "Proceed with security scans?"; then return; fi

    if ask_permission "Install security tools (auditd, rkhunter, chkrootkit, clamav, fail2ban)?"; then
        info "Installing tools... Please review the progress below."
        apt-get install -y auditd rkhunter chkrootkit clamav fail2ban
    fi
    if ask_permission "Run Rootkit Hunters (rkhunter & chkrootkit)?"; then
        if command -v rkhunter &> /dev/null; then
            info "Running rkhunter in a new terminal..."
            gnome-terminal -- /bin/bash -c "rkhunter --check --sk | tee $BACKUP_DIR/rkhunter.log; echo; read -p 'Scan complete. Press Enter to close.'"
            info "Summarizing rkhunter results (full log in backup dir):"
            grep "Warning:" "$BACKUP_DIR/rkhunter.log" || success "No warnings found in rkhunter log."
        else
            warn "rkhunter not found. Please install it first."
        fi
        if command -v chkrootkit &> /dev/null; then
            info "Running chkrootkit in a new terminal..."
            gnome-terminal -- /bin/bash -c "chkrootkit | tee $BACKUP_DIR/chkrootkit.log; echo; read -p 'Scan complete. Press Enter to close.'"
            info "Summarizing chkrootkit results (full log in backup dir):"
            grep "INFECTED" "$BACKUP_DIR/chkrootkit.log" || success "No infections found by chkrootkit."
        else
            warn "chkrootkit not found. Please install it first."
        fi
    fi
    if ask_permission "Run ClamAV Antivirus scan on /home?"; then
        if command -v clamscan &> /dev/null; then
            info "Updating ClamAV definitions..."
            freshclam
            info "Running ClamAV scan in a new terminal..."
            gnome-terminal -- /bin/bash -c "clamscan -r -i /home | tee $BACKUP_DIR/clamscan.log; echo; read -p 'Scan complete. Press Enter to close.'"
            info "Summarizing ClamAV results (full log in backup dir):"
            grep "FOUND" "$BACKUP_DIR/clamscan.log" || success "No threats found by ClamAV."
        else
            warn "ClamAV not found. Please install it first."
        fi
    fi
    if ask_permission "Enable and configure Fail2Ban for SSH?"; then
        if command -v fail2ban-client &> /dev/null; then
            echo -e "[sshd]\nenabled = true\nport = ssh\nmaxretry = 3\nbantime = 1h" > /etc/fail2ban/jail.local
            info "Starting and enabling Fail2Ban..."
            systemctl enable --now fail2ban
            success "Fail2Ban enabled for SSH."
        else
            warn "Fail2Ban not found. Please install it first."
        fi
    fi
    success "Security scanning section complete."
    mark_done 9
    pause
}

function media_file_scanner() {
    info "--- 10) Find & Interactively Delete Media Files ---"
    info "This will scan home directories for media files and ask to delete them individually."
    if ! ask_permission "Proceed with media file scan?"; then return; fi

    mapfile -t media_files < <(find /home -type f -not -path '*/\.*' \( -iname "*.mp3" -o -iname "*.mov" -o -iname "*.mp4" -o -iname "*.avi" -o -iname "*.wav" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.png" -o -iname "*.gif" \))

    if [ ${#media_files[@]} -eq 0 ]; then
        success "No unauthorized media files found."
    else
        warn "Found ${#media_files[@]} media file(s)."
        if ask_permission "Do you want to review and delete these files one-by-one?"; then
            for file in "${media_files[@]}"; do
                if ask_permission "  -> Delete '$file'?"; then
                    rm -f "$file"
                    success "Deleted."
                fi
            done
        fi
    fi
    success "Media file scan complete."
    mark_done 10
    pause
}

function cleanup_and_exit() {
    warn "--- 99) End Image Prerequisites & Clean Up ---"
    warn "This action is irreversible. It will PERMANENTLY delete:"
    warn "  - The progress tracking file ($PROGRESS_FILE)"
    warn "  - The entire backup directory ($BACKUP_DIR)"
    if ask_permission "Are you absolutely sure you want to clean up and exit?"; then
        rm -f "$PROGRESS_FILE"
        rm -rf "$BACKUP_DIR"
        success "Cleanup complete. Exiting."
        exit 0
    fi
}

# --- MAIN MENU & SCRIPT LOGIC ---

function main_menu() {
    clear
    cat << EOF
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
           '\\\'    '\\\\\\\'
           '|'            '/'        Ultimate Linux Mint 21 Hardening Script
           '| \\\'         '/'
           '|   |'        '/'        CyberPatriot National-Tier Tool
           '\\\'         '/'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 --- Initial Setup & Updates ---
  1) Perform Initial Backups of Critical Files        $(check_done 1)
  2) Update System Repositories and Packages        $(check_done 2)

 --- User Accounts & Policies ---
  3) User and Group Management (Interactive)        $(check_done 3)
  4) Apply Password & Lockout Policies (PAM)        $(check_done 4)

 --- Software & Services ---
  5) Interactively Disable/Remove Insecure Services   $(check_done 5)
  6) Harden Services (SSH & Apache)                 $(check_done 6)

 --- System & Filesystem Hardening ---
  7) Harden Network Settings (UFW & sysctl)         $(check_done 7)
  8) Harden Filesystem & Permissions (CIS Compliant)  $(check_done 8)

 --- Auditing and Scanning ---
  9) Install & Run Security Scans (Rootkit, AV)     $(check_done 9)
  10) Find & Interactively Delete Media Files         $(check_done 10)
  11) Find Potential Python Backdoors                 $(check_done 11)

 --- Utilities ---
  12) Install X2Go Service (Remote Desktop)
  98) Full Automatic Hardening (Runs steps 2-11)
  99) End Image Prerequisites & Clean Up
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
EOF
}

# --- SCRIPT START ---

JQ_ENABLED=true
check_jq || JQ_ENABLED=false
if $JQ_ENABLED; then
    initialize_progress_file
fi

# Main loop
while true; do
    main_menu
    read -p "Please choose an option: " choice
    case $choice in
        1) initial_setup ;;
        2) update_system ;;
        3) user_and_group_management ;;
        4) password_policies ;;
        5) service_management ;;
        6) service_hardening ;;
        7) network_hardening ;;
        8) filesystem_hardening ;;
        9) audit_and_scan ;;
        10) media_file_scanner ;;
        11)
            info "--- 11) Find Potential Python Backdoors ---"
            info "This scans for Python scripts using modules commonly found in backdoors."
            if ! ask_permission "Proceed with Python backdoor scan?"; then continue; fi
            find / -type f -iname "*.py" -exec grep -l -E "import socket|os.system|subprocess.run" {} + > "$BACKUP_DIR/python_backdoors.txt"
            if [ -s "$BACKUP_DIR/python_backdoors.txt" ]; then
                warn "Potential Python backdoors found! See list below and in '$BACKUP_DIR/python_backdoors.txt'."
                cat "$BACKUP_DIR/python_backdoors.txt"
            else
                success "No potential Python backdoors found."
            fi
            mark_done 11
            pause
            ;;
        12)
            info "--- 12) Install X2Go Service ---"
            info "This installs a secure remote desktop server."
            if ask_permission "Install and start the X2Go service?"; then
                info "Installing X2Go server..."
                apt-get install -y x2goserver
                info "Starting and enabling X2Go..."
                systemctl enable --now x2goserver
            fi
            pause
            ;;
        98)
            info "--- 98) Starting Full Automatic Hardening ---"
            info "This will run all major hardening steps sequentially. You will be prompted at each step."
            if ! ask_permission "Begin the full hardening process?"; then continue; fi
            update_system; user_and_group_management; password_policies; service_management; service_hardening; network_hardening; filesystem_hardening; audit_and_scan; media_file_scanner;
            info "Full hardening process complete."
            pause
            ;;
        99) cleanup_and_exit ;;
        *)
            warn "Invalid option. Please try again."
            pause
            ;;
    esac
done