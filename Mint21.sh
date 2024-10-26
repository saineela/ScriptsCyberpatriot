#!/bin/bash

# Function to prompt the user for Fail2Ban setup
setup_fail2ban() {
    echo "Do you want to install and set up Fail2Ban? (yes/no)"
    read -r user_input
    if [[ "$user_input" == "yes" ]]; then
        echo "Installing Fail2Ban..."
        sudo apt-get install -y fail2ban
        
        # Configure Fail2Ban to monitor SSH
        echo "Configuring Fail2Ban for SSH..."
        sudo systemctl enable fail2ban
        sudo systemctl start fail2ban
        
        # Create a custom jail.local configuration
        {
            echo "[sshd]"
            echo "enabled = true"
            echo "port = ssh"
            echo "filter = sshd"
            echo "logpath = /var/log/auth.log"
            echo "maxretry = 5"
            echo "bantime = 10m"
        } | sudo tee /etc/fail2ban/jail.local > /dev/null

        echo "Fail2Ban installed and configured."
    else
        echo "Skipping Fail2Ban installation."
    fi
}

# Function to prompt the user to check for backdoors
check_for_backdoors() {
    echo "Do you want to check for backdoors using chkrootkit and rkhunter? (yes/no)"
    read -r user_input
    if [[ "$user_input" == "yes" ]]; then
        echo "Installing chkrootkit and rkhunter..."
        sudo apt-get install -y chkrootkit rkhunter

        echo "Running chkrootkit..."
        sudo chkrootkit
        
        echo "Updating rkhunter..."
        sudo rkhunter --update
        
        echo "Running rkhunter check..."
        sudo rkhunter --check
    else
        echo "Skipping backdoor check."
    fi
}

# Install updates
echo "Installing updates..."
sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y

# Prompt for Fail2Ban installation
setup_fail2ban

# Enable Uncomplicated Firewall (UFW)
echo "Enabling and configuring UFW..."
sudo apt-get install -y ufw
sudo ufw enable

# No root login on sshd
echo "Configuring SSH settings to disable root login..."
if grep -qF 'PermitRootLogin' /etc/ssh/sshd_config; then
    sudo sed -i 's/^.*PermitRootLogin.*$/PermitRootLogin no/' /etc/ssh/sshd_config
else
    echo 'PermitRootLogin no' | sudo tee -a /etc/ssh/sshd_config
fi

# Lock the root user
echo "Locking the root user..."
sudo passwd -l root

# Configure password expiration policies
echo "Configuring password expiration policies..."
sudo sed -i 's/PASS_MAX_DAYS.*$/PASS_MAX_DAYS 90/;s/PASS_MIN_DAYS.*$/PASS_MIN_DAYS 10/;s/PASS_WARN_AGE.*$/PASS_WARN_AGE 7/' /etc/login.defs
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' | sudo tee -a /etc/pam.d/common-auth

# Install libpam-cracklib for password policies
echo "Installing PAM cracklib..."
sudo apt-get install -y libpam-cracklib

# Update PAM settings for password complexity
echo "Updating PAM settings for password complexity..."
sudo sed -i 's/\(pam_unix\.so.*\)$/\1 remember=5 minlen=8/' /etc/pam.d/common-password
sudo sed -i 's/\(pam_cracklib\.so.*\)$/\1 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' /etc/pam.d/common-password

# Install and enable auditd
echo "Installing and enabling auditd..."
sudo apt-get install -y auditd
sudo auditctl -e 1

# Remove samba packages if installed
echo "Removing samba packages..."
sudo apt-get remove -y samba*

# Remove prohibited software
echo "Removing prohibited software..."
prohibited_packages=(nmap zenmap apache2 nginx lighttpd wireshark tcpdump netcat-traditional nikto ophcrack)

for pkg in "${prohibited_packages[@]}"; do
    if dpkg -s "$pkg" &> /dev/null; then
        echo "Removing $pkg..."
        sudo apt-get remove --purge -y "$pkg"
        echo "$pkg removed."
    else
        echo "$pkg not installed."
    fi
done

# List non-work-related music and video files
echo "Finding non-work-related media files (music and video)..."
find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" \) -exec echo "Found media file: {}" \;

# Find and list potentially unwanted "hacking tools" packages
echo "Finding downloaded 'hacking tools' packages..."
find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) -exec echo "Found downloaded package: {}" \;

# Secure SSH settings
echo "Configuring additional SSH settings..."
# Additional SSH security settings
sudo sed -i 's/^.*ChallengeResponseAuthentication.*$/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*PasswordAuthentication.*$/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*UsePAM.*$/UsePAM no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/' /etc/ssh/sshd_config

echo "Restarting SSH service..."
sudo systemctl restart sshd
echo "SSH service restarted with secure settings."

# Prompt for backdoor check
check_for_backdoors

echo "All tasks completed."
