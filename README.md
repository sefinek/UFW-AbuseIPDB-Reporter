# 🛡️ UFW AbuseIPDB Reporter
A utility designed to analyze UFW firewall logs and report malicious IP addresses to the [AbuseIPDB](https://www.abuseipdb.com) database.  
To prevent redundant reporting of the same IP address within a short period, the tool uses a temporary cache file to track previously reported IPs.

This project was previously written in Bash, but it has been rewritten in [Node.js](https://nodejs.org). All my integration tools are currently written in Node, hence the change.
If you were using the old version, [uninstall it](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/tree/node.js?tab=readme-ov-file#%EF%B8%8F-remove-the-old-version) as it will no longer be supported.

If you like this repository or find it useful, I would greatly appreciate it if you could give it a star ⭐. Thanks a lot!  
See also this: [sefinek/Cloudflare-WAF-To-AbuseIPDB](https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)

> [!IMPORTANT]
> If you'd like to make changes to any files in this repository, please start by creating a [public fork](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/fork).


## 📋 Requirements
1. [Node.js + npm](https://nodejs.org)
2. [PM2](https://www.npmjs.com/package/pm2)
3. [Git](https://git-scm.com)


## 📥 Installation
```bash
sudo apt update && sudo apt upgrade
cd ~
git clone https://github.com/sefinek/UFW-AbuseIPDB-Reporter.git
cd UFW-AbuseIPDB-Reporter
npm install
cp default.config.js config.js
sudo chmod 644 /var/log/ufw.log
node .
^C
npm uninstall corepack -g
npm install pm2 -g
sudo mkdir /var/log/ufw-abuseipdb
sudo chown $USER:$USER /var/log/ufw-abuseipdb -R
pm2 start
pm2 startup
[Paste the command generated by pm2 startup]
pm2 save
```

## 🗑️ Remove the old version
```bash
sudo systemctl stop abuseipdb-ufw.service
sudo systemctl disable abuseipdb-ufw.service
sudo rm /etc/systemd/system/abuseipdb-ufw.service
sudo systemctl daemon-reload
sudo rm -r /usr/local/bin/UFW-AbuseIPDB-Reporter
```


## 🖥️ Usage
After successful installation, the script will run continuously in the background, monitoring UFW logs and automatically reporting malicious IP addresses.
The tool requires no additional user action after installation. However, it's worth occasionally checking its operation and updating the script regularly (by running the installation command).

Servers open to the world are constantly scanned by bots, usually looking for vulnerabilities or other security gaps.
So don't be surprised if the next day, the number of reports to AbuseIPDB exceeds a thousand.

### 🔍 Checking logs
```bash
pm2 logs ufw-abuseipdb
```

### 📄 Example reports
#### 1️⃣
```text
Blocked by UFW on vserver1 [80/tcp]
Source port: 23639
TTL: 247
Packet length: 40
TOS: 0x00

This report was generated by:
https://github.com/sefinek/UFW-AbuseIPDB-Reporter
```

#### 2️⃣
```text
Blocked by UFW on vserver1 [30049/tcp]. Generated by: https://github.com/sefinek/UFW-AbuseIPDB-Reporter
```


## 🤝 Development
If you want to contribute to the development of this project, feel free to create a new [Pull request](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/pulls). I will definitely appreciate it!


## 🔑 GPL-3.0 License
Copyright 2024 © by [Sefinek](https://sefinek.net). All rights reserved. See the [LICENSE](LICENSE) file for more information.