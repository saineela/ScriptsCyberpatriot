#!/bin/bash
echo "Sai Neela's Cyberpatriot Script"
echo "Cybersecurity is my dream"
echo "UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU "
echo "Script Starting......"

# Function to ask for confirmation
confirm() {
    read -p "$1 [y/n]: " choice
    case "$choice" in 
        y|Y ) return 0;;
        n|N ) return 1;;
        * ) echo "Invalid input"; return 1;;
    esac
}

# Function to scan for suspicious MP3 or media files
scan_for_media_files() {
    echo "Checking for MP3 or media files..."

    # Find all MP3 files and display details with full paths
    find / -type f -iname "*.mp3" -exec ls -l {} \; > mp3_files_found.txt

    # Check if any MP3 files were found
    if [ -s mp3_files_found.txt ]; then
        echo "Suspicious MP3 files found:"
        cat mp3_files_found.txt

        if confirm "Do you want to delete these MP3 files?"; then
            # Delete found MP3 files
            while read -r file; do
                sudo rm -f "$file"
                echo "Deleted: $file"
            done < mp3_files_found.txt
        else
            echo "MP3 files were not deleted."
        fi
    else
        echo "No MP3 files found."
    fi
}

# Disable SSH Root Login
disable_ssh_root_login() {
    if confirm "Do you want to disable SSH root login for added security?"; then
        echo "Disabling SSH root login..."
        sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo sed -i 's/PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sudo systemctl restart sshd
        echo "SSH root login has been disabled."
    else
        echo "Skipping SSH root login disabling."
    fi
}

# Setup Fail2Ban
setup_fail2ban() {
    if confirm "Do you want to install and set up Fail2Ban?"; then
        echo "Installing and configuring Fail2Ban..."
        sudo apt-get install -y fail2ban

        # Enable and start Fail2Ban service
        sudo systemctl enable fail2ban
        sudo systemctl start fail2ban

        # Custom Fail2Ban configuration for SSH
        sudo tee /etc/fail2ban/jail.local > /dev/null <<EOF
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 10m
EOF

        echo "Fail2Ban installed and configured."
    else
        echo "Skipping Fail2Ban installation."
    fi
}

# Check for Backdoors
check_for_backdoors() {
    if confirm "Do you want to check for backdoors with chkrootkit and rkhunter?"; then
        echo "Installing and running chkrootkit and rkhunter..."
        sudo apt-get install -y chkrootkit rkhunter
        sudo chkrootkit
        sudo rkhunter --update && sudo rkhunter --check
    else
        echo "Skipping backdoor check."
    fi
}

# Install and Enable UFW (Uncomplicated Firewall)
setup_ufw() {
    if confirm "Would you like to install and enable the UFW firewall?"; then
        echo "Installing and enabling UFW firewall..."
        sudo apt-get install -y ufw
        sudo ufw enable
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
    else
        echo "Skipping UFW firewall installation and enablement."
    fi
}

# Change Password Policy in /etc/login.defs
setup_password_policy() {
    if confirm "Would you like to set password policies for maximum and minimum days and warning age?"; then
        echo "Setting password policies in /etc/login.defs..."
        sudo sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/' /etc/login.defs
        sudo sed -i 's/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/' /etc/login.defs
        sudo sed -i 's/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
    else
        echo "Skipping password policy configuration."
    fi
}

# Install and Enable Auditing
setup_auditd() {
    if confirm "Would you like to install and enable auditd for system auditing?"; then
        echo "Installing and enabling auditd..."
        sudo apt-get install -y auditd
        sudo auditctl -e 1
    else
        echo "Skipping auditd installation and enablement."
    fi
}

# Check for Unusual Administrators in the Sudo Group
check_sudo_group() {
    if confirm "Would you like to check for unusual administrators in the sudo group?"; then
        echo "Checking for unusual administrators in the sudo group..."
        sudo mawk -F: '$1 == "sudo"' /etc/group
    else
        echo "Skipping check for unusual administrators."
    fi
}

# Check for Users with UID Greater than 999 (Non-System Accounts)
check_non_system_users() {
    if confirm "Would you like to check for non-system users with UID greater than 999?"; then
        echo "Checking for non-system users..."
        sudo mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd
    else
        echo "Skipping check for non-system users."
    fi
}

# Check for Accounts with Empty Passwords
check_empty_passwords() {
    if confirm "Would you like to check for accounts with empty passwords?"; then
        echo "Checking for accounts with empty passwords..."
        sudo mawk -F: '$2 == ""' /etc/passwd
    else
        echo "Skipping check for accounts with empty passwords."
    fi
}

# Check for Non-root UID 0 Accounts
check_non_root_uid_0() {
    if confirm "Would you like to check for non-root accounts with UID 0?"; then
        echo "Checking for non-root accounts with UID 0..."
        sudo mawk -F: '$3 == 0 && $1 != "root"' /etc/passwd
    else
        echo "Skipping check for non-root accounts with UID 0."
    fi
}

# Main script execution

# Update and Upgrade System (In the background with only essential info shown)
if confirm "Would you like to update and upgrade the system?"; then
    echo "Updating and upgrading the system..."

    # Run update and upgrade in the background and suppress unnecessary output
    sudo apt-get update -y > /dev/null 2>&1 &
    sudo apt-get upgrade -y > /dev/null 2>&1 &
    sudo apt-get dist-upgrade -y > /dev/null 2>&1 &
    
    echo "System is being updated and upgraded in the background. Please wait..."
    wait  # Wait for all processes to complete
else
    echo "Skipping system update and upgrade."
fi

# Start by scanning for MP3 files
scan_for_media_files

# Run Fail2Ban setup
setup_fail2ban

# Check for Backdoors
check_for_backdoors

# Disable SSH Root Login
disable_ssh_root_login

# Setup UFW Firewall
setup_ufw

# Setup password policies
setup_password_policy

# Setup Auditing
setup_auditd

# Check for unusual sudo users
check_sudo_group

# Check for non-system users
check_non_system_users

# Check for accounts with empty passwords
check_empty_passwords

# Check for non-root UID 0 accounts
check_non_root_uid_0

# Function to check for ClamAV Installation and Update Definitions
check_clamav() {
    if ! command -v clamscan &> /dev/null; then
        echo "ClamAV is not installed. Installing ClamAV..."
        sudo apt-get install -y clamav clamav-daemon
        sudo freshclam   # Update ClamAV definitions
    else
        echo "ClamAV is already installed. Updating virus definitions..."
        sudo freshclam   # Update ClamAV definitions if it's already installed
    fi
}

# Function to scan files with ClamAV
scan_with_clamav() {
    echo "Scanning $1 with ClamAV..."
    clamscan "$1"
}

# Function to scan installed programs with ClamAV
scan_installed_programs_with_clamav() {
    echo "Scanning installed programs with ClamAV..."

    # List installed programs
    installed_programs=$(dpkg-query -f '${binary:Package}\n' -W)

    for program in $installed_programs; do
        # Get the program binary location
        program_path=$(which "$program")
        
        # Scan the program with ClamAV
        scan_with_clamav "$program_path"
    done
}

# Run ClamAV scan at the end of the script
check_clamav  # Ensure ClamAV is installed and up-to-date

# Scan installed programs with ClamAV
scan_installed_programs_with_clamav

# Final message
echo "Script execution completed."
