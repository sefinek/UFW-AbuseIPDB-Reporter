# 🛡️ UFW AbuseIPDB Reporter
A utility designed to analyze UFW logs and report IP addresses blocked by the firewall to the [AbuseIPDB](https://www.abuseipdb.com) database.  
To prevent excessive reporting of the same IP address within a short period, the tool uses a temporary cache file to track previously reported IP addresses.

⭐ If you like this repository or find it useful, I'd greatly appreciate it if you could give it a star. Many thanks!  
Also, check this out: [sefinek/Cloudflare-WAF-To-AbuseIPDB](https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)

> [!IMPORTANT]
> - If you'd like to make changes to any files in this repository, please start by creating a [public fork](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/fork).
> - According to AbuseIPDB's policy, [UDP traffic should not be reported](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/discussions/2)!


## 📋 Requirements
1. [Node.js + npm](https://github.com/sefinek/UFW-AbuseIPDB-Reporter?tab=readme-ov-file#nodejs-installation)
2. [PM2](https://www.npmjs.com/package/pm2) (`npm i pm2 -g`)
3. [Git](https://github.com/sefinek/UFW-AbuseIPDB-Reporter?tab=readme-ov-file#git-installation)
4. Linux


## ✅ Features
1. **Easy Configuration** – The [`config.js`](config.default.js) file allows for quick and simple customization.
2. **Simple Installer** – Enables fast and seamless integration deployment.
3. **Bulk Reporting Support** – If the script encounters a rate limit, it will start buffering collected IPs and send a bulk report.
4. **Self-IP Protection (IPv4 & IPv6)** – The script will never report IP addresses belonging to you or your server, even if you're using a dynamic IP address.
5. **Local IP Filtering** – Local IP addresses will never be reported.
6. **Discord Webhooks Integration**:
   - Critical notifications
   - Script error alerts
   - Daily summaries of reported IPs
7. **Automatic Updates** – The script regularly fetches and applies the latest updates. You can [disable this](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/blob/main/config.default.js#L14) if you prefer.


## 📥 Installation (Ubuntu & Debian)

### Automatic (easy & fast & recommenced)
#### Via curl
```bash
bash <(curl -fsS https://raw.githubusercontent.com/sefinek/UFW-AbuseIPDB-Reporter/main/install.sh)
```

#### Via wget
```bash
bash <(wget -qO- https://raw.githubusercontent.com/sefinek/UFW-AbuseIPDB-Reporter/main/install.sh)
```

### Manually
#### Node.js installation
```bash
sudo apt install -y curl
curl -fsSL https://deb.nodesource.com/setup_22.x -o nodesource_setup.sh
sudo -E bash nodesource_setup.sh && sudo apt install -y nodejs
```

#### Git installation
```bash
sudo add-apt-repository ppa:git-core/ppa
sudo apt update && sudo apt -y install git 
```

#### Commands
```bash
sudo apt update && apt upgrade
cd ~
git clone https://github.com/sefinek/UFW-AbuseIPDB-Reporter.git --recurse-submodules && cd UFW-AbuseIPDB-Reporter
npm install
cp config.default.js config.js
sudo chmod 644 /var/log/ufw.log
node .
^C
npm install pm2 -g
sudo mkdir -p /var/log/ufw-abuseipdb
sudo chown -R "$USER":"$USER" /var/log/ufw-abuseipdb
sudo mkdir -p /var/cache/sefinek
sudo chown -R "$USER":"$USER" /var/cache/sefinek
pm2 start
pm2 startup
[Paste the command generated by pm2 startup]
pm2 save
```


## 🖥️ Usage
After a successful installation, the script will run continuously in the background, monitoring UFW logs and automatically reporting IP addresses.

Servers are constantly scanned by bots, usually looking for security vulnerabilities and similar weaknesses.
So don't be surprised if the number of reports sent to AbuseIPDB exceeds a thousand the next day.

### 🔍 Checking logs
```bash
pm2 logs ufw-abuseipdb
```

### 📄 Example reports
#### 1️⃣
```text
Blocked by UFW on homeserver1 [80/tcp]
Source port: 23639
TTL: 247
Packet length: 40
TOS: 0x00

This report was generated by:
https://github.com/sefinek/UFW-AbuseIPDB-Reporter
```

#### 2️⃣
```text
Blocked by UFW on homeserver1 [30049/tcp]. Generated by: https://github.com/sefinek/UFW-AbuseIPDB-Reporter
```


## 🤝 Development
If you want to contribute to the development of this project, feel free to create a new [Pull request](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/pulls). I will definitely appreciate it!


## 🔑 [GPL-3.0 License](LICENSE)
Copyright 2024-2025 © by [Sefinek](https://sefinek.net). All rights reserved.