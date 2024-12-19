# 🛡️ UFW AbuseIPDB Reporter
A utility designed to analyze UFW firewall logs and report malicious IP addresses to the [AbuseIPDB](https://www.abuseipdb.com) database.  
To prevent redundant reporting of the same IP address within a short period, the tool uses a temporary cache file to track previously reported IPs.

If you like this repository or find it useful, I would greatly appreciate it if you could give it a star ⭐. Thanks a lot!  
See also this: [sefinek/Cloudflare-WAF-To-AbuseIPDB](https://github.com/sefinek/Cloudflare-WAF-To-AbuseIPDB)

> [!IMPORTANT]
> If you'd like to make changes to any files in this repository, please start by creating a [public fork](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/fork).


## 📋 Requirements
- **Operating System:** Linux with UFW firewall installed and configured.
- **AbuseIPDB Account:** An account on the AbuseIPDB service [with a valid API token](https://www.abuseipdb.com/account/api). The API token is required.
- **Installed packages:**
  - `wget` or `curl`: One of these tools is required to download the [installation script](install.sh) from the GitHub repository and to send requests to the AbuseIPDB API.
  - `jq`: A tool for processing and parsing JSON data returned by the AbuseIPDB API.
  - `openssl`: Used to encode and decode the API token to secure authentication data.
  - `tail`, `awk`, `grep`, `sed`: Standard Unix tools used for text processing and log analysis.


## 🧪 Tested operating systems
- **Ubuntu Server:** 20.04 & 22.04

*If the distribution you're using to run this tool isn't listed here but works correctly, please create a new [Issue](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/issues) or submit a [Pull request](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/pulls).*


## 📥 Installation
### curl
```bash
bash <(curl -s https://raw.githubusercontent.com/sefinek/UFW-AbuseIPDB-Reporter/main/install.sh)
```

### wget
```bash
bash <(wget -qO- https://raw.githubusercontent.com/sefinek/UFW-AbuseIPDB-Reporter/main/install.sh)
```

The installation script will automatically download and configure the tool on your machine. During the installation process, you will be prompted to provide an [AbuseIPDB API token](https://www.abuseipdb.com/account/api).


## 🖥️ Usage
After successful installation, the script will run continuously in the background, monitoring UFW logs and automatically reporting malicious IP addresses.
The tool requires no additional user action after installation. However, it's worth occasionally checking its operation and updating the script regularly (by running the installation command).

Servers open to the world are constantly scanned by bots, usually looking for vulnerabilities or other security gaps.
So don't be surprised if the next day, the number of reports to AbuseIPDB exceeds a thousand.

### 🔍 Checking service status
```bash
sudo systemctl status abuseipdb-ufw.service
```

To see the current logs generated by the process, use the command:
```bash
journalctl -u abuseipdb-ufw.service -f
```

### 📄 Example report
```
Blocked by UFW (TCP on 80)
Source port: 28586
TTL: 116
Packet length: 48
TOS: 0x08

This report (for 46.174.191.31) was generated by:
https://github.com/sefinek/UFW-AbuseIPDB-Reporter
```


## 🤝 Development
If you want to contribute to the development of this project, feel free to create a new [Pull request](https://github.com/sefinek/UFW-AbuseIPDB-Reporter/pulls). I will definitely appreciate it!


## 🔑 GPL-3.0 License
Copyright 2024 © by [Sefinek](https://sefinek.net). All rights reserved. See the [LICENSE](LICENSE) file for more information.