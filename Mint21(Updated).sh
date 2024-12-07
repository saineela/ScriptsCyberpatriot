#!/bin/bash
echo "Sai Neela's Cyberpatriot Script"
echo "Cybersecurity is my dream"
echo "UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU UwU "
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

# Function to check and disable OpenSSH
check_openssh() {
    if dpkg -l | grep -qw "openssh"; then
        if confirm "OpenSSH is present. Do you want to disable OpenSSH?"; then
            sudo systemctl disable ssh
            sudo systemctl stop ssh
            echo "OpenSSH has been disabled."
        else
            echo "OpenSSH remains enabled."
        fi
    else
        echo "OpenSSH is not installed."
    fi
}

# Prohibited software removal
remove_prohibited_software() {
    prohibited_programs=("hydra")
    for program in "${prohibited_programs[@]}"; do
        if dpkg -l | grep -qw "$program"; then
            sudo apt-get remove -y "$program"
            echo "$program has been removed."
        else
            echo "$program not found on the system."
        fi
    done
}

# Check and remove prohibited MP3 files
remove_prohibited_mp3s() {
    find / -name "*.mp3" -type f | while read -r mp3; do
        if confirm "Prohibited MP3 file found: $mp3. Do you want to remove it?"; then
            rm "$mp3"
            echo "$mp3 has been removed."
        fi
    done
}

# Search for Python backdoors
check_python_backdoors() {
    echo "Scanning for Python backdoors..."
    python_files=$(find / -name "*.py" -type f 2>/dev/null)
    if [[ -z "$python_files" ]]; then
        echo "No Python files found."
        return
    fi

    echo "Analyzing Python files..."
    suspicious_files=()
    for file in $python_files; do
        if grep -qE "(os\.system|subprocess\.|eval\(|exec\()" "$file"; then
            suspicious_files+=("$file")
        fi
    done

    if [[ ${#suspicious_files[@]} -gt 0 ]]; then
        echo "Potential Python backdoors detected:"
        for file in "${suspicious_files[@]}"; do
            echo "$file"
        done
        if confirm "Do you want to delete these suspicious Python files?"; then
            for file in "${suspicious_files[@]}"; do
                rm "$file"
                echo "$file has been removed."
            done
        else
            echo "Suspicious Python files were not deleted."
        fi
    else
        echo "No Python backdoors detected."
    fi
}

# Apache configurations
configure_apache() {
    if dpkg -l | grep -qw "apache2"; then
        if confirm "Apache is installed. Do you want to disable the server signature?"; then
            sudo sed -i 's/^ServerSignature On/ServerSignature Off/' /etc/apache2/conf-available/security.conf
            echo "Apache server signature disabled."
        fi
        if confirm "Do you want to set Apache server tokens to minimal?"; then
            sudo sed -i 's/^ServerTokens OS/ServerTokens Prod/' /etc/apache2/conf-available/security.conf
            echo "Apache server tokens set to least."
        fi
        sudo systemctl restart apache2
    else
        echo "Apache is not installed."
    fi
}

# Password policies
set_password_policies() {
    echo "Configuring password policies..."
    sudo sed -i '/^PASS_MIN_DAYS/s/[0-9]\+/1/' /etc/login.defs
    sudo sed -i '/^PASS_MAX_DAYS/s/[0-9]\+/90/' /etc/login.defs
    sudo sed -i '/^PASS_WARN_AGE/s/[0-9]\+/7/' /etc/login.defs
    echo "Password policies configured."
}

# IPv4 TCP SYN cookies
enable_tcp_syn_cookies() {
    echo "Enabling TCP SYN cookies..."
    sudo sysctl -w net.ipv4.tcp_syncookies=1
    echo "TCP SYN cookies enabled."
}

# Insecure permissions on shadow file
fix_shadow_permissions() {
    echo "Fixing insecure permissions on the shadow file..."
    sudo chmod 600 /etc/shadow
    echo "Permissions for the shadow file fixed."
}

# Main execution
set_password_policies
enable_tcp_syn_cookies
fix_shadow_permissions
check_openssh
remove_prohibited_software
remove_prohibited_mp3s
check_python_backdoors
configure_apache

echo "Script execution completed."
