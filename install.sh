#!/usr/bin/env bash

##################################################################
#    Copyright 2024-2025 (c) by Sefinek All rights reserved.     #
#                    https://sefinek.net                         #
##################################################################

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

                 >> Made by sefinek.net || Last update: 10.02.2025 <<

This installer will configure UFW-AbuseIPDB-Reporter, a tool that analyzes UFW logs and
reports to AbuseIPDB the IP addresses that have violated firewall rules. Join my Discord
server to stay updated on the latest changes and more: https://discord.gg/53DBjTuzgZ
============================================================================================

EOF

# Function to prompt for a Yes/no answer
yes_no_prompt() {
    local prompt="$1"
    while true; do
        read -r -p "$prompt [Yes/no]: " answer
        case $answer in
            [Yy]*|[Yy]es ) return 0 ;;  # Return 0 for Yes
            [Nn]*|[Nn]o ) return 1 ;;   # Return 1 for No
            * ) echo "❌ Invalid input. Please answer Yes/no or Y/n." ;;
        esac
    done
}

# Function to check and install missing dependencies
check_dependencies() {
    local dependencies=(curl node git)
    local missing=()

    for dependency in "${dependencies[@]}"; do
        if ! command -v "$dependency" &> /dev/null; then
            missing+=("$dependency")
        else
            echo "✅ $dependency is installed ($(command -v "$dependency"))"
            if $dependency --version &> /dev/null; then
                $dependency --version
            else
                echo "ℹ️ Version information for $dependency is unavailable"
            fi
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "🚨 Missing dependencies: ${missing[*]}"
        for dep in "${missing[@]}"; do
            if yes_no_prompt "📦 Do you want to install $dep?"; then
                case $dep in
                    curl ) sudo apt-get install -y curl ;;
                    node ) curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh && sudo bash nodesource_setup.sh && sudo apt-get install -y nodejs && rm -f nodesource_setup.sh ;;
                    git ) sudo add-apt-repository ppa:git-core/ppa && sudo apt-get update && sudo apt-get -y install git ;;
                esac
            else
                echo "❌ Cannot proceed without $dep. Exiting..."
                exit 1
            fi
        done
    else
        echo "✅ All dependencies are installed"
    fi
}

# Check dependencies before proceeding
check_dependencies

# Function to validate AbuseIPDB API key
validate_token() {
    local api_key=$1
    local api_url="https://api.abuseipdb.com/api/v2/check?ipAddress=1.1.1.1"
    local response

    if command -v curl &>/dev/null; then
        response=$(curl -s -o /dev/null -w "%{http_code}" -H "Key: $api_key" "$api_url")
    elif command -v wget &>/dev/null; then
        response=$(wget --quiet --server-response --header="Key: $api_key" --output-document=/dev/null "$api_url" 2>&1 | awk '/HTTP\/1\.[01] [0-9]{3}/ {print $2}' | tail -n1)
    else
        echo "🚨 Neither curl nor wget is installed. Please install one of them to proceed."
        exit 1
    fi

    if [[ $response -eq 200 ]]; then
        echo "✅ Yay! Token is valid."
        return 0
    else
        echo "❌ Invalid token! Please try again."
        return 1
    fi
}

# Check for UFW log file
if [[ ! -f /var/log/ufw.log ]]; then
    read -r -p "🔍 /var/log/ufw.log not found. Please enter the path to your log file: " ufw_log_path
    if [[ -f $ufw_log_path ]]; then
        echo "✅ Log file found at $ufw_log_path"
    else
        echo "❌ Provided log file path does not exist. Exiting..."
        exit 1
    fi
else
    ufw_log_path="/var/log/ufw.log"
    echo "✅ /var/log/ufw.log exists"
fi

# Prompt for AbuseIPDB API token
while true; do
    read -r -p "🔑 Please enter your AbuseIPDB API token: " api_token
    if validate_token "$api_token"; then
        break
    fi
    continue
done

# Prompt for server ID
while true; do
    read -r -p "🖥️ Enter the server ID (e.g., homeserver1). Leave blank if you do not wish to provide one: " server_id
    if [[ -z $server_id ]]; then
        server_id=null
        break
    elif [[ $server_id =~ ^[A-Za-z0-9]{1,16}$ ]]; then
        break
    else
        echo "❌ It must be 1-16 characters long, contain only letters and numbers, and have no spaces or special characters."
    fi
done

# Prompt for system update and upgrade
if yes_no_prompt "🛠️ Do you want the script to run apt update and apt upgrade for you?"; then
    echo "🔧 Updating and upgrading the system..."
    sudo apt-get update && sudo apt-get upgrade
fi

# Clone repository & set permissions
if [ ! -d "/opt" ]; then
    mkdir -p /opt
    echo "📂 '/opt' has been created"
else
    echo "✅ '/opt' directory already exists"
fi

cd /opt || { echo "❌ Failed to change directory to '/opt'. Exiting..."; exit 1; }

if [ ! -d "UFW-AbuseIPDB-Reporter" ]; then
    echo "📥 Cloning the UFW-AbuseIPDB-Reporter repository..."
    sudo git clone https://github.com/sefinek/UFW-AbuseIPDB-Reporter.git --recurse-submodules || { echo "❌ Failed to clone the repository. Exiting..."; exit 1; }
else
    echo "✨ The UFW-AbuseIPDB-Reporter repository already exists"
fi

sudo chown "$USER":"$USER" /opt/UFW-AbuseIPDB-Reporter -R

echo "📥 Pulling latest changes..."
cd UFW-AbuseIPDB-Reporter || { echo "❌ Failed to change directory to 'UFW-AbuseIPDB-Reporter'. Exiting..."; exit 1; }
git pull || { echo "❌ Failed to pull the latest changes. Exiting..."; exit 1; }

# Install npm dependencies
echo "📦 Installing npm dependencies..."
npm install -silent

# Copy configuration file
if [ -e config.js ]; then
  echo "✅ config.js already exists"
else
  echo "📑 Copying config.default.js to config.js..."
  cp config.default.js config.js
fi

# Update config.js with API token, Server ID, and UFW log path
config_file="config.js"
if [[ -f $config_file ]]; then
    echo "🔧 Updating $PWD/$config_file..."
    sed -i "s|UFW_LOG_FILE: .*|UFW_LOG_FILE: '$ufw_log_path',|" $config_file
    sed -i "s|SERVER_ID: .*|SERVER_ID: '$server_id',|" $config_file
    sed -i "s|ABUSEIPDB_API_KEY: .*|ABUSEIPDB_API_KEY: '$api_token',|" $config_file
else
    echo "❌ $config_file not found. Make sure the repository was cloned and initialized correctly."
    exit 1
fi

# Create logs directory
echo "📂 Creating /var/log/ufw-abuseipdb directory..."
sudo mkdir -p /var/log/ufw-abuseipdb
sudo chown "$USER":"$USER" /var/log/ufw-abuseipdb -R

# Change permissions for UFW log file
echo "🔒 Changing permissions for $ufw_log_path..."
sudo chmod 644 "$ufw_log_path"

# Install pm2
echo "📦 Installing PM2..."
sudo npm install pm2 -g -silent


# Configure PM2
echo "⚙️ Adding PM2 to autostart..."
startup_command=$(pm2 startup | grep "sudo env PATH" | sed 's/^[^s]*sudo/sudo/')

if [ -n "$startup_command" ]; then
    echo "⚙️ Executing: $startup_command"
    eval "$startup_command" &>/dev/null || {
        echo "❌ Failed to execute the startup command!"
    }
else
    echo "❌ Failed to find the command generated by pm2 startup! PM2 was not added to autostart."
fi

echo "⚙️ Running a script with PM2 and saving the current state of all processes managed by it..."
pm2 start --silent
pm2 save --silent


# Final
echo "🌌 Checking PM2 status..."
pm2 status

echo -e "\n🎉 Installation and configuration completed! Use the 'pm2 logs' command to monitor logs in real time."

echo -e "\n====================================== Summary ======================================"
echo "🖥️ Server ID     : ${server_id:-null}"
echo "🔑 API Key       : $api_token"
echo "📂 Script        : $PWD"
echo "⚙️ Config File   : $PWD/config.js"

echo -e "\n====================================== Support ======================================"
echo "📩 Email         : contact@sefinek.net"
echo "🔵 Discord       : https://discord.gg/RVH8UXgmzs"
echo "😺 GitHub Issues : https://github.com/sefinek/UFW-AbuseIPDB-Reporter/issues"
