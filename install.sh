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

This installer will configure UFW-AbuseIPDB-Reporter, a tool that analyzes UFW logs and
reports to AbuseIPDB the IP addresses that have violated firewall rules. Join my Discord
server to stay updated on the latest changes and more: https://discord.gg/53DBjTuzgZ

📩 Author        : Sefinek <contact@sefinek.net> (https://sefinek.net)
🔵 Discord       : https://discord.gg/RVH8UXgmzs
😺 GitHub Issues : https://github.com/sefinek/UFW-AbuseIPDB-Reporter/issues
📦 Last update   : 20.12.2025
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
    local dependencies=("$@")
    local missing=()

    # Helper: install dependency
    install_dep() {
        local dep=$1
        case $dep in
            node)
                curl -fsSL https://deb.nodesource.com/setup_24.x -o nodesource_setup.sh
                sudo bash nodesource_setup.sh
                sudo apt-get install -y nodejs
                rm -f nodesource_setup.sh
                ;;
            git)
                check_dependencies software-properties-common
                sudo add-apt-repository -y ppa:git-core/ppa
                sudo apt-get update
                sudo apt-get install -y git
                ;;
            *)
                sudo apt-get install -y "$dep"
                ;;
        esac
    }

    for dependency in "${dependencies[@]}"; do
        if ! command -v "$dependency" &> /dev/null; then
            missing+=("$dependency")
        else
            echo "✅ $dependency is installed ($(command -v "$dependency"))"
            if "$dependency" --version &> /dev/null; then
                "$dependency" --version | head -n 1
            else
                echo "      Version information for $dependency is unavailable"
            fi
        fi
    done

    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "🚨 Found missing dependencies: ${missing[*]}"
        for dep in "${missing[@]}"; do
            if yes_no_prompt "📦 Do you want to install $dep?"; then
                install_dep "$dep" || { echo "❌ Installation failed for $dep. Exiting..."; exit 1; }
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
check_dependencies curl node git

# Function to extract value from config.js
extract_config_value() {
    local key=$1
    local config_file="${2:-config.js}"

    if [[ ! -f $config_file ]]; then
        echo ""
        return
    fi

    local value
    value=$(grep -oP "^\s*${key}:\s*\K.*?(?=,\s*(//|$))" "$config_file" | sed "s/^['\"]//;s/['\"]$//" | sed 's/[[:space:]]*$//')
    [[ $value == "null" ]] && value=""
    echo "$value"
}

# Function to ask for configuration with validation
ask_config() {
    local prompt=$1
    local default=$2
    local validation_type=${3:-""}
    local result

    while true; do
        read -e -i "$default" -r -p "$prompt" result
        result="${result:-$default}"

        case $validation_type in
            bool)
                if [[ $result =~ ^(true|false)$ ]]; then
                    echo "$result"
                    return 0
                else
                    echo "❌ Must be 'true' or 'false'"
                fi
                ;;
            number)
                if [[ $result =~ ^[0-9]+\.?[0-9]*$ ]]; then
                    echo "$result"
                    return 0
                else
                    echo "❌ Must be a valid number"
                fi
                ;;
            url)
                if [[ -z $result ]] || [[ $result =~ ^https?:// ]]; then
                    echo "$result"
                    return 0
                else
                    echo "❌ Must be a valid URL starting with http:// or https://"
                fi
                ;;
            cron)
                if [[ $result =~ ^[0-9*,/-]+\ [0-9*,/-]+\ [0-9*,/-]+\ [0-9*,/-]+\ [0-9*,/-]+$ ]]; then
                    echo "$result"
                    return 0
                else
                    echo "❌ Invalid cron format. Expected: 'minute hour day month weekday'"
                fi
                ;;
            static_dynamic)
                if [[ $result =~ ^(static|dynamic)$ ]]; then
                    echo "$result"
                    return 0
                else
                    echo "❌ Must be 'static' or 'dynamic'"
                fi
                ;;
            *)
                echo "$result"
                return 0
                ;;
        esac
    done
}

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
        echo "✅ API token validated successfully."
        return 0
    else
        echo "❌ Invalid token. Please try again."
        return 1
    fi
}

# Prepare UFW
echo "🔧 Preparing UFW..."
UFW_STATUS=$(LANG=C sudo ufw status verbose)
if ! grep -q "^Status: active" <<< "$UFW_STATUS"; then
    echo "❌ UFW appears to be inactive. Do you want to enable it?"
    if yes_no_prompt "🔧 Would you like to enable UFW now?"; then
        sudo ufw enable
        echo "✅ UFW has been successfully enabled"
        UFW_STATUS=$(LANG=C sudo ufw status verbose)
    else
        echo "❌ UFW is required to proceed. Exiting..."
        exit 1
    fi
fi

if ! grep -q "^Logging: on (" <<< "$UFW_STATUS"; then
    echo "🔧 Enabling UFW logging (low)..."
    sudo ufw logging low

    echo "⏳ Waiting a moment for the ufw.log file to be created..."
    sleep 5
else
    echo "✅ UFW logging is already enabled"
fi

# Prompt for system update and upgrade
if yes_no_prompt "🛠️ Do you want the script to run apt update and apt upgrade for you?"; then
    echo "🔧 Updating and upgrading the system..."
    sudo apt-get update && sudo apt-get upgrade
fi

# Clone repository & set permissions
echo "📂 Ensuring /opt directory exists..."
mkdir -p /opt
cd /opt || { echo "❌ Failed to change directory to '/opt'. Exiting..."; exit 1; }

# Migrate from old directory name if exists
if [ -d "UFW-AbuseIPDB-Reporter" ] && [ ! -d "ufw-abuseipdb-reporter" ]; then
    echo "📦 Migrating from old directory name (UFW-AbuseIPDB-Reporter → ufw-abuseipdb-reporter)..."

    # Stop UFW-AbuseIPDB reporter process if running
    if command -v pm2 &>/dev/null; then
        if pm2 list | grep -q "ufw-abuseipdb"; then
            echo "⏸️ Stopping ufw-abuseipdb process..."
            pm2 stop ufw-abuseipdb &>/dev/null || true
            pm2 delete ufw-abuseipdb &>/dev/null || true
        fi
    fi

    sudo mv UFW-AbuseIPDB-Reporter ufw-abuseipdb-reporter
    echo "✅ Migration completed"
fi

if [ ! -d "ufw-abuseipdb-reporter" ]; then
    echo "📥 Cloning the repository..."
    sudo git clone --recurse-submodules https://github.com/sefinek/UFW-AbuseIPDB-Reporter.git ufw-abuseipdb-reporter || { echo "❌ Failed to clone the repository. Exiting..."; exit 1; }
else
    echo "✅ The repository already exists"
fi

sudo chown "$USER":"$USER" /opt/ufw-abuseipdb-reporter -R

echo "📥 Pulling latest changes..."
cd ufw-abuseipdb-reporter || { echo "❌ Failed to change directory to 'ufw-abuseipdb-reporter'. Exiting..."; exit 1; }
git pull || { echo "❌ Failed to pull the latest changes. Exiting..."; exit 1; }

# Install npm dependencies
echo "📦 Installing npm dependencies..."
npm install --omit=dev -silent

# Copy configuration file
if [ -e config.js ]; then
  echo "✅ config.js already exists"
else
  echo "📑 Copying config.default.js to config.js..."
  cp config.default.js config.js
fi

# Check for UFW log file
existing_log_path=$(extract_config_value "UFW_LOG_FILE")
default_log_path="${existing_log_path:-/var/log/ufw.log}"

if [[ -f $default_log_path ]]; then
    echo "✅ $default_log_path exists"
    ufw_log_path="$default_log_path"
else
    while true; do
        read -e -i "$default_log_path" -r -p "> 🔍 Please enter the path to your UFW log file: " ufw_log_path

        if [[ -f $ufw_log_path ]]; then
            echo "✅ Log file found at $ufw_log_path"
            break
        else
            echo "❌ Provided log file path does not exist. Please try again."
        fi
    done
fi

echo -e "\n==============================================================================================\n"

# Prompt for API token
existing_api_token=$(extract_config_value "ABUSEIPDB_API_KEY")

while true; do
    read -e -i "$existing_api_token" -r -p "> 🔑 Please enter your AbuseIPDB API token: " api_token

    if [[ -z $api_token ]]; then
        echo "❌ API token cannot be empty. Please try again."
        continue
    fi

    if validate_token "$api_token"; then
        break
    fi
done

# Prompt for server ID
echo ""
echo "     Server ID identifies this machine in AbuseIPDB reports and Discord notifications."
echo "     Examples: 'homeserver1', 'vps-de-01', 'production'. Leave blank if not needed."
existing_server_id=$(extract_config_value "SERVER_ID")

while true; do
    read -e -i "$existing_server_id" -r -p "> 🖥️ Enter the server ID (1-16 characters, or leave blank): " server_id

    if [[ -z $server_id ]]; then
        server_id=null
        break
    elif [[ $server_id =~ ^[A-Za-z0-9]{1,16}$ ]]; then
        server_id="'$server_id'"
        break
    else
        echo "❌ Must be 1-16 characters long, only letters and numbers (a-z, A-Z, 0-9)."
    fi
done

# Extended logs
echo -e "\n     Extended logs show additional debugging information in console output."
existing_extended_logs=$(extract_config_value "EXTENDED_LOGS")
extended_logs=$(ask_config "> 📊 Enable extended logs? (true/false): " "${existing_extended_logs:-false}" "bool")

# Cache file path
echo -e "\n     Cache file stores reported IPs to prevent duplicate reports within cooldown period."
existing_cache_file=$(extract_config_value "CACHE_FILE")
cache_file=$(ask_config "> 💾 Cache file path: " "${existing_cache_file:-./tmp/ufw-abuseipdb-reporter.cache}" "")

# IP assignment type
echo -e "\n     IP assignment: 'dynamic' if your ISP changes your IP periodically, 'static' if it never changes."
echo "     Most home/small business connections are 'dynamic'. VPS/dedicated servers are usually 'static'."
existing_ip_assignment=$(extract_config_value "IP_ASSIGNMENT")
ip_assignment=$(ask_config "> 🌐 IP assignment type (static/dynamic): " "${existing_ip_assignment:-dynamic}" "static_dynamic")

# IP refresh schedule (only if dynamic)
if [[ $ip_assignment == "dynamic" ]]; then
    echo -e "\n     How often to check your public IP to avoid accidentally reporting your own IP (cron format)."
    echo "     Default '0 */6 * * *' = every 6 hours. Format: minute hour day month weekday"
    existing_ip_refresh=$(extract_config_value "IP_REFRESH_SCHEDULE")
    ip_refresh_schedule=$(ask_config "> ⏰ IP refresh schedule (cron): " "${existing_ip_refresh:-0 */6 * * *}" "cron")
else
    ip_refresh_schedule="0 */6 * * *"
fi

# IPv6 support
echo -e "\n     Enable if your server has a public IPv6 address assigned by your ISP."
echo "     Check with: ip -6 addr | grep 'scope global'"
existing_ipv6=$(extract_config_value "IPv6_SUPPORT")
ipv6_support=$(ask_config "> 🔢 Enable IPv6 support? (true/false): " "${existing_ipv6:-false}" "bool")

# IP report cooldown
echo -e "\n     Minimum time (in hours) before reporting the same IP again."
echo "     Recommended: 12 hours. Minimum: 0.25 (15 minutes) due to AbuseIPDB rate limits."
existing_cooldown=$(extract_config_value "IP_REPORT_COOLDOWN")
default_cooldown_hours="12"
if [[ -n $existing_cooldown ]]; then
    default_cooldown_hours=$(awk "BEGIN {printf \"%.2f\", $existing_cooldown / 3600000}")
fi

while true; do
    cooldown_hours=$(ask_config "> ⏱️ IP report cooldown (hours): " "$default_cooldown_hours" "number")
    # Check if >= 0.25 (15 minutes)
    if awk "BEGIN {exit !($cooldown_hours >= 0.25)}"; then
        break
    else
        echo "❌ Minimum cooldown is 0.25 hours (15 minutes)"
    fi
done

ip_report_cooldown=$(awk "BEGIN {printf \"%.0f\", $cooldown_hours * 3600000}")

# Auto-update
echo -e "\n     Automatically update script via 'git pull' on schedule. May cause issues with breaking changes."
existing_auto_update=$(extract_config_value "AUTO_UPDATE_ENABLED")
auto_update_enabled=$(ask_config "> 🔄 Enable automatic updates? (true/false): " "${existing_auto_update:-false}" "bool")

# Auto-update schedule (only if enabled)
if [[ $auto_update_enabled == "true" ]]; then
    echo -e "\n     When to check for updates (cron format)."
    echo "     Default '0 14,16,20 * * *' = daily at 14:00, 16:00, 20:00"
    existing_update_schedule=$(extract_config_value "AUTO_UPDATE_SCHEDULE")
    auto_update_schedule=$(ask_config "> 📅 Auto-update schedule (cron): " "${existing_update_schedule:-0 14,16,20 * * *}" "cron")
else
    auto_update_schedule="0 14,16,20 * * *"
fi

# Discord webhook
echo -e "\n     Receive Discord notifications about important events, daily summaries of blocked IPs, and errors."
existing_discord_enabled=$(extract_config_value "DISCORD_WEBHOOK_ENABLED")
discord_enabled=$(ask_config "> 💬 Enable Discord webhooks? (true/false): " "${existing_discord_enabled:-false}" "bool")

# Discord webhook URL (only if enabled)
if [[ $discord_enabled == "true" ]]; then
    echo -e "\n     Edit Channel → Integrations → Create Webhook → Click on created webhook → Copy Webhook URL"
    discord_url=$(ask_config "> 🔗 Discord webhook URL: " "$(extract_config_value "DISCORD_WEBHOOK_URL")" "url")

    echo -e "\n     Username shown in Discord messages. 'SERVER_ID' will use your server ID value."
    existing_discord_username=$(extract_config_value "DISCORD_WEBHOOK_USERNAME")
    discord_username=$(ask_config "> 👤 Discord webhook username: " "${existing_discord_username:-SERVER_ID}" "")
    [[ -z $discord_username ]] && discord_username="SERVER_ID"

    echo -e "\n     Your Discord user ID to receive @mentions when critical issues occur."
    echo "     User Settings → Advanced → Developer Mode"
    echo "     Esc → Right-click on your profile → Copy User ID. Leave blank to skip."
    discord_user_id=$(ask_config "> 🆔 Discord user ID (optional): " "$(extract_config_value "DISCORD_USER_ID")" "")
else
    discord_url=""
    discord_username="SERVER_ID"
    discord_user_id=""
fi

echo -e "\n==============================================================================================\n"

# Update config.js with all parameters
if [[ ! -f config.js ]]; then
    echo "❌ config.js not found. Installation may have failed."
    exit 1
fi

echo "🔧 Updating $PWD/config.js..."
sed -i \
    -e "s|UFW_LOG_FILE: .*|UFW_LOG_FILE: '$ufw_log_path',|" \
    -e "s|SERVER_ID: .*|SERVER_ID: $server_id,|" \
    -e "s|EXTENDED_LOGS: .*|EXTENDED_LOGS: $extended_logs,|" \
    -e "s|CACHE_FILE: .*|CACHE_FILE: '$cache_file',|" \
    -e "s|IP_ASSIGNMENT: .*|IP_ASSIGNMENT: '$ip_assignment',|" \
    -e "s|IP_REFRESH_SCHEDULE: .*|IP_REFRESH_SCHEDULE: '$ip_refresh_schedule',|" \
    -e "s|IPv6_SUPPORT: .*|IPv6_SUPPORT: $ipv6_support,|" \
    -e "s|ABUSEIPDB_API_KEY: .*|ABUSEIPDB_API_KEY: '$api_token',|" \
    -e "s|IP_REPORT_COOLDOWN: .*|IP_REPORT_COOLDOWN: $ip_report_cooldown,|" \
    -e "s|AUTO_UPDATE_ENABLED: .*|AUTO_UPDATE_ENABLED: $auto_update_enabled,|" \
    -e "s|AUTO_UPDATE_SCHEDULE: .*|AUTO_UPDATE_SCHEDULE: '$auto_update_schedule',|" \
    -e "s|DISCORD_WEBHOOK_ENABLED: .*|DISCORD_WEBHOOK_ENABLED: $discord_enabled,|" \
    -e "s|DISCORD_WEBHOOK_URL: .*|DISCORD_WEBHOOK_URL: '$discord_url',|" \
    -e "s|DISCORD_WEBHOOK_USERNAME: .*|DISCORD_WEBHOOK_USERNAME: '$discord_username',|" \
    -e "s|DISCORD_USER_ID: .*|DISCORD_USER_ID: '$discord_user_id',|" \
    config.js

# Create directories & set permissions
echo "📂 Creating directories and setting permissions..."
sudo mkdir -p /var/log/ufw-abuseipdb
sudo chown -R "$USER":"$USER" /var/log/ufw-abuseipdb

# Change permissions for UFW log file
if [[ -f $ufw_log_path ]]; then
    echo "🔒 Changing permissions for $ufw_log_path..."
    sudo chown syslog:"$USER" "$ufw_log_path"
    sudo chmod 640 "$ufw_log_path"
else
    echo "⚠️  Warning: UFW log file not found at $ufw_log_path. Permissions not changed."
fi

# Install PM2
echo "📦 Installing PM2..."
sudo npm install pm2@latest -g --silent

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

echo "⚙️ Starting the application with PM2..."
pm2 start --silent
pm2 save --silent

# Final
echo "🌌 Checking PM2 status..."
pm2 status

echo -e "\n🎉 Installation and configuration completed! Use the 'pm2 logs' command to monitor logs in real time."
echo -e "⚙️ More settings can be found in the file: $PWD/config.js"
echo -e "   After editing the configuration file, restart the process: pm2 restart ufw-abuseipdb"

echo -e "\n====================================== Summary ======================================"
echo "🖥️ Server ID          : ${server_id//\'/}"
if [[ ${#api_token} -gt 16 ]]; then
    echo "🔑 API Key            : ${api_token:0:8}...${api_token: -4}"
else
    echo "🔑 API Key            : ${api_token:0:4}...${api_token: -4}"
fi
echo "📂 UFW Log File       : $ufw_log_path"
echo "💾 Cache File         : $cache_file"
echo "🌐 IP Assignment      : $ip_assignment"
echo "🔢 IPv6 Support       : $ipv6_support"
echo "⏱️ Report Cooldown    : $cooldown_hours hours"
echo "🔄 Auto-Updates       : $auto_update_enabled"
echo "💬 Discord Webhooks   : $discord_enabled"
echo "📂 Script Directory   : $PWD"
