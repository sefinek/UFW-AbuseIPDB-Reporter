#!/bin/bash

###
# https://github.com/sefinek/UFW-AbuseIPDB-Reporter
##

VERSION="1.1.2"
DATE="20.12.2024"
REPO="https://github.com/sefinek/UFW-AbuseIPDB-Reporter"

cat << "EOF"
     _      _                            ___   ____    ____    ____
    / \    | |__    _   _   ___    ___  |_ _| |  _ \  |  _ \  | __ )
   / _ \   | '_ \  | | | | / __|  / _ \  | |  | |_) | | | | | |  _ \
  / ___ \  | |_) | | |_| | \__ \ |  __/  | |  |  __/  | |_| | | |_) |
 /_/   \_\_|_.__/ _ \__,_| |___/  \___| |___| |_|     |____/  |____/

         (_)_ __ | |_ ___  __ _ _ __ __ _| |_(_) ___  _ __
         | | '_ \| __/ _ \/ _` | '__/ _` | __| |/ _ \| '_ \
         | | | | | ||  __/ (_| | | | (_| | |_| | (_) | | | |
         |_|_| |_|\__\___|\__, |_|  \__,_|\__|_|\___/|_| |_|
                          |___/

EOF

cat <<EOF
     >> Made by sefinek.net || Version: $VERSION [$DATE] <<

This installer will configure UFW-AbuseIPDB-Reporter, a tool that analyzes
UFW firewall logs and reports IP addresses to AbuseIPDB. Remember to perform
updates periodically. You can join my Discord server to receive notifications
about the latest changes and more: https://discord.gg/53DBjTuzgZ
================================================================================

EOF

# Function to download a file using either curl or wget
download_file() {
    local url="$1"
    local output="$2"
    local user_agent="UFW-AbuseIPDB-Reporter/$VERSION (+$REPO)"

    if command -v curl >/dev/null 2>&1; then
        echo "INFO: Using 'curl' to download the file..."
        sudo curl -A "$user_agent" -o "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        echo "INFO: 'curl' is not installed. Using 'wget' to download the file..."
        sudo wget --header="User-Agent: $user_agent" -O "$output" "$url"
    else
        echo "FAIL: Neither 'curl' nor 'wget' is installed! Please install one of these packages and try running the script again."
        exit 1
    fi
}

# Ask
ask_user() {
    local question="$1"
    local response

    while true; do
        read -rp "$ $question [Yes/no]: " response
        case "${response,,}" in
            yes|y) return 0;;
            no|n) return 1;;
            *) echo "Invalid input. Please answer 'yes' or 'no'."
               echo;;
        esac
    done
}

# ========================= CHECK FOR MISSING PACKAGES =========================
required_packages=(ufw jq openssl)
missing_packages=()

for pkg in "${required_packages[@]}"; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        missing_packages+=("$pkg")
    fi
done

if [ ${#missing_packages[@]} -gt 0 ]; then
    echo "WARN: The following packages are not installed: ${missing_packages[*]}"
    if ! ask_user "Do you want to install them now?"; then
        echo "FAIL: Missing dependencies packages. Installation cannot proceed without them."
        exit 1
    fi

    echo "INFO: Installing missing dependencies: ${missing_packages[*]}"
    if ! sudo apt-get update && sudo apt-get install -y "${missing_packages[@]}"; then
        echo "FAIL: Failed to install the required dependencies. Aborting installation!"
        exit 1
    fi

    echo -e "INFO: All required dependencies have been successfully installed.\n"
else
    echo "INFO: Dependencies are already installed on this machine."
fi


# =========================== Check if the service already exists ===========================
if systemctl list-unit-files | grep -q '^abuseipdb-ufw.service'; then
    echo "WARN: abuseipdb-ufw.service is already installed! If you plan to update or reinstall, choose 'Yes'."
    if ask_user "Do you want to remove the existing service?"; then
      sudo systemctl stop abuseipdb-ufw.service
      sudo systemctl disable abuseipdb-ufw.service
      sudo rm /etc/systemd/system/abuseipdb-ufw.service
      sudo systemctl daemon-reload
    else
        echo -e "INFO: Existing service will not be removed\n"
    fi
fi


# =========================== Prepare installation directory ===========================
install_dir="/usr/local/bin/UFW-AbuseIPDB-Reporter"
script_path="$install_dir/reporter.sh"
if [ -d "$install_dir" ]; then
    echo "INFO: Directory $install_dir already exists. Removing it..."
    if ! sudo rm -rf "$install_dir"; then
        echo "FAIL: Something went wrong. Failed to remove existing directory $install_dir."
        exit 1
    fi
fi

echo "INFO: Creating installation directory at $install_dir..."
if ! sudo mkdir -p "$install_dir"; then
    echo "FAIL: Something went wrong. Failed to create installation directory."
    exit 1
fi
echo


# =========================== Prepare reporter.sh script ===========================
GITHUB_URL="https://raw.githubusercontent.com/sefinek/UFW-AbuseIPDB-Reporter/main/reporter.sh"
echo "INFO: Downloading reporter.sh from $GITHUB_URL..."
if ! download_file "$GITHUB_URL" "$script_path"; then
    echo "FAIL: Something went wrong while downloading the file from GitHub servers! Maybe try running this script as sudo?"
    exit 1
fi
echo "INFO: Saved reporter.sh at location $script_path"

if ! sudo chmod +x "$script_path"; then
    echo "FAIL: Failed to make reporter.sh executable."
    exit 1
fi
echo -e "INFO: reporter.sh has been made executable.\n"


# =========================== AbuseIPDB API token ===========================
max_attempts=4
valid_token=false
for ((attempts = 0; attempts < max_attempts; attempts++)); do
    read -rsp "$ Please enter your AbuseIPDB API token: " api_key
    echo

    if [[ "$api_key" =~ ^[a-f0-9]{80}$ ]]; then
        valid_token=true
        break
    fi

    attempts_left=$((max_attempts - attempts - 1))
    if (( attempts_left > 0 )); then
        echo "WARN: Invalid API token format. Please enter an 80-character hexadecimal string. You have $attempts_left/$max_attempts attempts left."
    fi
done

if [[ "$valid_token" != true ]]; then
    echo "FAIL: Maximum number of attempts reached. Installation aborted!"
    exit 1
fi

# Encode the API token
token_file="$install_dir/.abuseipdb_token"
echo "INFO: Encoding data (file $token_file)..."
if ! echo -n "$api_key" | openssl enc -base64 | sudo tee "$token_file" >/dev/null; then
    echo "FAIL: Something went wrong. Failed to encode API token."
    exit 1
fi

# Update the ENCODED_API_KEY_FILE variable in reporter.sh by replacing the existing definition
echo "INFO: Updating ENCODED_API_KEY_FILE variable in reporter.sh..."
if ! sudo sed -i "s|^ENCODED_API_KEY_FILE=.*|ENCODED_API_KEY_FILE=\"$token_file\"|" "$script_path"; then
    echo "FAIL: Failed to update ENCODED_API_KEY_FILE in reporter.sh."
    exit 1
fi

echo "INFO: Setting permissions (chmod 644) for /var/log/ufw.log..."
sudo chmod 644 /var/log/ufw.log
echo


# =========================== abuseipdb-ufw.service ===========================
if ask_user "Would you like to add reporter.sh as a service and start it?"; then
    service_file="/etc/systemd/system/abuseipdb-ufw.service"
    echo "INFO: Setting up reporter.sh as a service"
    if ! sudo bash -c "cat > $service_file" <<-EOF
[Unit]
Description=UFW AbuseIPDB Reporter
After=network.target
Documentation=$REPO

[Service]
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ExecStart=$script_path
Restart=always
User=$(logname)
WorkingDirectory=$install_dir
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    then
        echo "FAIL: Failed to create service file. Please check your permissions!"
        exit 1
    fi

    sudo systemctl daemon-reload

    if sudo systemctl enable abuseipdb-ufw.service && sudo systemctl start abuseipdb-ufw.service; then
        echo "INFO: Attempting to start the abuseipdb-ufw.service..."
    else
        echo "FAIL: Failed to enable or start the abuseipdb-ufw.service. Please check the system logs for details."
        exit 1
    fi

    echo "INFO: Waiting 8 seconds to verify the script's stability..."
    sleep 8

    if sudo systemctl is-active --quiet abuseipdb-ufw.service; then
        echo "INFO: abuseipdb-ufw.service is running!"
        sudo systemctl status abuseipdb-ufw.service --no-pager
    else
        echo "FAIL: abuseipdb-ufw.service failed to start."
        sudo systemctl status abuseipdb-ufw.service --no-pager
        exit 1
    fi
else
    echo -e "INFO: reporter.sh will not be added as a service. Running the script directly... Press ^C to stop.\n"
    if "$script_path"; then
        echo "INFO: reporter.sh executed successfully."
    else
        echo "FAIL: Failed to execute reporter.sh!"
        exit 1
    fi
fi
echo

# Prompt to add the service to autostart
if ask_user "Do you want to add abuseipdb-ufw.service to autostart?"; then
    if sudo systemctl enable abuseipdb-ufw.service; then
        echo "INFO: Great! abuseipdb-ufw.service has been added to autostart. Installation finished!"
        echo "INFO: Run 'journalctl -u abuseipdb-ufw.service -f' to view more logs."
    else
        echo "FAIL: Failed to add abuseipdb-ufw.service to autostart!"
        exit 1
    fi
else
    echo "INFO: abuseipdb-ufw.service will not be added to autostart. Installation finished!"
fi
