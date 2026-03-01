# 🛡️ UFW AbuseIPDB Reporter
[![Version](https://img.shields.io/github/package-json/v/sefinek/UFW-AbuseIPDB-Reporter?label=version)](https://github.com/sefinek/UFW-AbuseIPDB-Reporter)
[![License: GPL v3](https://img.shields.io/github/license/sefinek/UFW-AbuseIPDB-Reporter)](https://www.gnu.org/licenses/gpl-3.0)
[![Node.js](https://img.shields.io/badge/node-%3E%3D20.0.0-339933?logo=node.js&logoColor=white)](https://nodejs.org)
[![Last Commit](https://img.shields.io/github/last-commit/sefinek/UFW-AbuseIPDB-Reporter?label=last%20commit)](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/commits)
[![Stars](https://img.shields.io/github/stars/sefinek/UFW-AbuseIPDB-Reporter)](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/stargazers)

An integration tool designed to analyze UFW logs and report IP addresses blocked by the firewall to the [AbuseIPDB](https://www.abuseipdb.com) database.
To prevent excessive reporting of the same IP address within a short time period, the tool uses a temporary cache file to track previously reported IP addresses.

⭐ If you like this repository or find it useful, I'd greatly appreciate it if you could give it a star. Many thanks!  
Also, check this out: [sefinek/Cloudflare-WAF-To-AbuseIPDB](https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)

> [!IMPORTANT]
> - If you'd like to make changes to any files in this repository, please start by creating a [public fork](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/fork).
> - According to AbuseIPDB's policy, [UDP traffic should not be reported](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/discussions/2)!


## 📋 Requirements
- [Node.js + npm](https://gist.github.com/sefinek/fb50041a5f456321d58104bbf3f6e649)
- [PM2](https://www.npmjs.com/package/pm2) (`npm i -g pm2`)
- [Git](https://gist.github.com/sefinek/1de50073ffbbae82fc901506304f0ada)
- Linux (Ubuntu or Debian)


## ✅ Features
1. **Easy Configuration** – The [`config.js`](config.default.js) file allows for quick and simple configuration.
2. **Simple Installer** – Enables fast and seamless integration deployment.
3. **Self-IP Protection (IPv4 & IPv6)** – The script will never report IP addresses belonging to you or your server, even if you're using a dynamic IP address.
4. **IP Filtering** – Local and special-purpose IP addresses will never be reported.
5. **IP Whitelist** – Maintain a `whitelist.txt` file with IP addresses that should never be reported (e.g., your home IP when running on a VPS).
6. **UDP Traffic Filtering** – UDP traffic is automatically skipped in accordance with [AbuseIPDB's policy](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/discussions/2).
7. **Report Cooldown** – Prevents duplicate reports of the same IP within a configurable time window (default: 12 hours).
8. **Bulk Reporting Support** – If the script encounters a rate limit, it will start buffering collected IPs and send a bulk report.
9. **Discord Webhooks Integration**:
   - Critical notifications
   - Script error alerts
   - Daily summaries of reported IPs
10. **Automatic Updates** – The script regularly fetches and applies the latest updates. You can disable this feature if you'd prefer.


## 📥 Installation (Ubuntu & Debian)

### Automatic (easy & fast & recommended)
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
See https://gist.github.com/sefinek/fb50041a5f456321d58104bbf3f6e649.

#### Git installation
See https://gist.github.com/sefinek/1de50073ffbbae82fc901506304f0ada.

#### Commands
```bash
sudo apt update && sudo apt upgrade
cd ~
git clone --recurse-submodules https://github.com/sefinek/UFW-AbuseIPDB-Reporter.git ufw-abuseipdb
cd ufw-abuseipdb
npm install --omit=dev
cp config.default.js config.js
sudo chown syslog:"$USER" "$ufw_log_path"
sudo chmod 640 "$ufw_log_path"
npm install -g pm2@latest
sudo mkdir -p /var/log/ufw-abuseipdb
sudo chown -R "$USER":"$USER" /var/log/ufw-abuseipdb
pm2 start
eval "$(pm2 startup | grep sudo)"
pm2 save
```


## 🖥️ Usage
After a successful installation, the script will run continuously in the background, monitoring UFW logs and automatically reporting IP addresses.

Servers are constantly scanned by bots, usually looking for security vulnerabilities and similar weaknesses.
So don't be surprised if the number of reports sent to AbuseIPDB exceeds a thousand the next day.

### 🔍 Check logs
```bash
pm2 logs ufw-abuseipdb
```

### 📄 Example reports
```text
Blocked by UFW on NY01 [8096/tcp] | SPT: 52458 | TTL: 243 | LEN: 40 | TOS: 0x08 • Reported by: github.com/sefinek/UFW-AbuseIPDB-Reporter
```

```text
Blocked by UFW on PL02 [64505/tcp] | SPT: 34017 | TTL: 43 | LEN: 44 | TOS: 0x00 • Reported by: github.com/sefinek/UFW-AbuseIPDB-Reporter
```


## 🤝 Development
If you want to contribute to the development of this project, feel free to create a new [Pull request](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/pulls). I will definitely appreciate it!


## 🔑 [GPL-3.0 License](LICENSE)
Copyright © 2024-2026 [Sefinek](https://sefinek.net)