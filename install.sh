#!/usr/bin/env bash

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
                    curl ) apt-get install -y curl ;;
                    node ) curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh && bash nodesource_setup.sh && apt-get install -y nodejs && rm -f nodesource_setup.sh ;;
                    git ) add-apt-repository ppa:git-core/ppa && apt-get update && apt-get -y install git ;;
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
    local api_url="https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8"
    local response

    if command -v curl &>/dev/null; then
        response=$(curl -s -o /dev/null -w "%{http_code}" -H "Key: $api_key" "$api_url")
    elif command -v wget &>/dev/null; then
        response=$(wget --quiet --server-response --header="Key: $api_key" --output-document=/dev/null "$api_url" 2>&1 | awk '/HTTP\/1\.[01] [0-9]{3}/ {print $2}' | tail -n1)
    else
        echo "❌ Neither curl nor wget is installed. Please install one of them to proceed."
        exit 1
    fi

    if [[ $response -eq 200 ]]; then
        echo "✅ Yay! Token is valid."
        return 0
    else
        echo "🚨 Invalid token or an error occurred! Please try again."
        exit 1
    fi
}

# Check for UFW log file
if [[ ! -f /var/log/ufw.log ]]; then
    read -r -p "🔍 /var/log/ufw.log not found. Please enter the path to your log file: " ufw_log_path
    if [[ -f $ufw_log_path ]]; then
        echo "✅ Log file found at $ufw_log_path."
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
    read -r -p "🖥️ Enter the server ID. Leave blank if you do not wish to provide one (e.g., homeserver1): " server_id
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
    apt-get update > /dev/null 2>&1 && apt-get upgrade
else
    echo "⏩ Skipping system update and upgrade..."
fi

# Clone repository
if [ -d "/home" ]; then
    mkdir -p /home/new_directory
    echo "📂 '/home/new_directory' has been created"
else
    echo "❌ '/home' directory does not exist. Exiting..."
    exit 1
fi

cd /home || { echo "❌ Failed to change directory to '/home'. Exiting..."; exit 1; }

if [ ! -d "UFW-AbuseIPDB-Reporter" ]; then
    echo "📥 Cloning the UFW-AbuseIPDB-Reporter repository..."
    git clone https://github.com/sefinek/UFW-AbuseIPDB-Reporter.git --branch node.js || { echo "❌ Failed to clone the repository. Exiting..."; exit 1; }
else
    echo "✨ The UFW-AbuseIPDB-Reporter repository already exists!"
fi

echo "📥 Pulling latest changes..."
cd UFW-AbuseIPDB-Reporter || { echo "❌ Failed to change directory to 'UFW-AbuseIPDB-Reporter'. Exiting..."; exit 1; }
git pull || { echo "❌ Failed to pull the latest changes. Exiting..."; exit 1; }

# Install npm dependencies
echo "📦 Installing npm dependencies..."
npm install --silent

# Copy configuration file
echo "📑 Copying default.config.js to config.js..."
cp default.config.js config.js

# Update config.js with API token, Server ID, and UFW log path
config_file="config.js"
if [[ -f $config_file ]]; then
    echo "🔧 Updating $PWD/$config_file..."
    sed -i "s|UFW_FILE: .*|UFW_FILE: '$ufw_log_path',|" $config_file
    sed -i "s|SERVER_ID: .*|SERVER_ID: '$server_id',|" $config_file
    sed -i "s|ABUSEIPDB_API_KEY: .*|ABUSEIPDB_API_KEY: '$api_token',|" $config_file
else
    echo "❌ $config_file not found. Make sure the repository was cloned and initialized correctly."
    exit 1
fi

# Change permissions for UFW log file
echo "🔒 Changing permissions for $ufw_log_path..."
chmod 644 "$ufw_log_path"

# Uninstall corepack
echo "🗑️ Uninstalling corepack..."
npm uninstall corepack -g --silent

# Install pm2
echo "📦 Installing PM2..."
npm install pm2 -g --silent

# Create logs directory
echo "📂 Creating /var/log/ufw-abuseipdb directory..."
mkdir -p /var/log/ufw-abuseipdb
chown "$USER":"$USER" /var/log/ufw-abuseipdb -R

# Configure pm2
echo "⚙️ Configuring PM2..."
pm2 start
pm2 startup

# Execute the command generated by pm2 startup
echo "🔧 Complete pm2 startup configuration:"
sudo env PATH="$PATH":/usr/bin /usr/lib/node_modules/pm2/bin/pm2 startup systemd -u "$USER" --hp /home/"$USER"

pm2 save


# Final
echo -e "\n\n🌌 Checking PM2 status..."
pm2 status

echo -e "\n🎉 Installation and configuration completed!"

echo -e "\n====================================== Summary ======================================"
echo "🔑 API Token     : $api_token"
echo "🖥️ Server ID     : ${server_id:-null}"
echo "📂 Script        : $PWD"
echo "⚙️ Config File   : $PWD/config.js"

echo -e "\n====================================== Support ======================================"
echo "📩 Email         : contact@sefinek.net"
echo "🔵 Discord       : https://discord.gg/RVH8UXgmzs"
echo "😺 GitHub Issues : https://github.com/sefinek/UFW-AbuseIPDB-Reporter/issues"
