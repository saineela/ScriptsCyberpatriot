#!/bin/bash

# Update and Upgrade System
echo "Updating and upgrading system..."
sudo apt-get update && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y

# Function: Fail2Ban Setup
setup_fail2ban() {
    read -rp "Do you want to install and set up Fail2Ban? (yes/no) " user_input
    if [[ "$user_input" == "yes" ]]; then
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

# Function: Check for Backdoors
check_for_backdoors() {
    read -rp "Do you want to check for backdoors with chkrootkit and rkhunter? (yes/no) " user_input
    if [[ "$user_input" == "yes" ]]; then
        echo "Installing and running chkrootkit and rkhunter..."
        sudo apt-get install -y chkrootkit rkhunter
        sudo chkrootkit
        sudo rkhunter --update && sudo rkhunter --check
    else
        echo "Skipping backdoor check."
    fi
}

# Install and Enable UFW
echo "Enabling and configuring UFW..."
sudo apt-get install -y ufw
sudo ufw enable

# Configure SSH Security
echo "Configuring SSH security settings..."
sudo sed -i '/^PermitRootLogin/s/.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo passwd -l root

# Set Password Expiration Policies
echo "Configuring password expiration policies..."
sudo sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS 90/; s/PASS_MIN_DAYS.*/PASS_MIN_DAYS 10/; s/PASS_WARN_AGE.*/PASS_WARN_AGE 7/' /etc/login.defs
echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' | sudo tee -a /etc/pam.d/common-auth

# Install and Enable auditd
echo "Installing and enabling auditd for logging..."
sudo apt-get install -y auditd
sudo systemctl enable auditd && sudo systemctl start auditd

# Remove Samba and Other Prohibited Software
echo "Removing prohibited software..."
sudo apt-get remove -y samba*
for pkg in nmap zenmap apache2 nginx lighttpd wireshark tcpdump netcat-traditional nikto ophcrack; do
    if dpkg -s "$pkg" &> /dev/null; then
        echo "Removing $pkg..."
        sudo apt-get remove --purge -y "$pkg"
    else
        echo "$pkg is not installed."
    fi
done

# List Non-Work-Related Media Files
echo "Searching for non-work-related media files..."
find /home/ -type f \( -name "*.mp3" -o -name "*.mp4" \) -exec echo "Found media file: {}" \;

# List Downloaded "Hacking Tools" Packages
echo "Searching for downloaded 'hacking tools' packages..."
find /home/ -type f \( -name "*.tar.gz" -o -name "*.tgz" -o -name "*.zip" -o -name "*.deb" \) -exec echo "Found package: {}" \;

# Additional SSH Security Settings
echo "Configuring additional SSH security settings..."
sudo sed -i 's/^.*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/^.*PermitEmptyPasswords.*/PermitEmptyPasswords no/' /etc/ssh/sshd_config

# Restart SSH Service
echo "Restarting SSH service to apply security settings..."
sudo systemctl restart sshd

# Run Fail2Ban and Backdoor Checks
setup_fail2ban
check_for_backdoors

echo "All security tasks completed successfully."
