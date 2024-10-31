# 🛡️ UFW AbuseIPDB Reporter
A tool that analyzes UFW firewall logs and reports malicious IP addresses to the [AbuseIPDB](https://www.abuseipdb.com) database.

> [!IMPORTANT]
> If you'd like to make changes to any files in this repository, please start by creating a public fork.

<div align="center">
  [<a href="README.md">English</a>]
  [<a href="README_PL.md">Polish</a>]
</div>

- [⚙️ How does it work in detail?](#how-it-works)
- [📋 Requirements](#requirements)
  - [🛠️ Installing required packages](#installing-required-packages)
    - [🌍 Perform repository and software updates](#perform-repository-and-software-updates)
    - [🌌 Install required dependencies](#install-required-dependencies)
  - [🧪 Tested operating systems](#tested-operating-systems)
- [📥 Installation](#installation)
- [🖥️ Usage](#usage)
  - [🔍 Checking service status](#checking-service-status)
  - [📄 Example report](#example-report)
- [🤝 Development](#development)
- [🔑 MIT License](#license)

See also this: [sefinek24/Node-Cloudflare-WAF-AbuseIPDB](https://github.com/sefinek24/Node-Cloudflare-WAF-AbuseIPDB)

> If you like this repository or find it useful, I would greatly appreciate it if you could give it a star ⭐. Thanks a lot!

## ⚙️ How does it work in detail?<div id="how-it-works"></div>
1. **Monitoring UFW logs:** The tool continuously monitors logs generated by the UFW firewall, looking for unauthorized access attempts or other suspicious activities.
2. **Analyzing the reported address:** After identifying a suspicious IP address, the script checks if the address has already been reported.
3. **Reporting IP to AbuseIPDB:** If the IP meets the criteria, the address is reported to the AbuseIPDB database with information about the protocol, source port, destination port, etc.
4. **Cache of reported IPs:** The tool stores a list of reported IPs in a temporary file to prevent multiple reports of the same IP address in a short period.

## 📋 Requirements<div id="requirements"></div>
- **Operating System:** Linux with UFW firewall installed and configured.
- **AbuseIPDB Account:** An account on the AbuseIPDB service [with a valid API token](https://www.abuseipdb.com/account/api). The API token is required.
- **Installed packages:**
  - `wget` or `curl`: One of these tools is required to download the [installation script](install.sh) from the GitHub repository and to send requests to the AbuseIPDB API.
  - `jq`: A tool for processing and parsing JSON data returned by the AbuseIPDB API.
  - `openssl`: Used to encode and decode the API token to secure authentication data.
  - `tail`, `awk`, `grep`, `sed`: Standard Unix tools used for text processing and log analysis.
- **Internet connection:** Hm, I think it's obvious, right?


### 🛠️ Installing required packages<div id="installing-required-packages"></div>
#### 🌍 Perform repository and software updates (highly recommended)<div id="perform-repository-and-software-updates"></div>
```bash
sudo apt update && sudo apt upgrade -y
```

#### 🌌 Install required dependencies<div id="install-required-dependencies"></div>
```bash
sudo apt install -y curl jq openssl ufw
```

### 🧪 Tested operating systems<div id="tested-operating-systems"></div>
- Ubuntu Server 20.04/22.04

If the distribution you're using to run the tool isn't listed here and the script works correctly, please create a new [Issue](https://github.com/sefinek24/UFW-AbuseIPDB-Reporter/issues). I'll add its name to the list.


## 📥 Installation<div id="installation"></div>
To install this tool, run the following command in the terminal (`sudo` is required):
```bash
sudo bash -c "$(curl -s https://raw.githubusercontent.com/sefinek24/UFW-AbuseIPDB-Reporter/main/install.sh)"
```

The installation script will automatically download and configure the tool on your server. During installation, you will be asked to provide an [AbuseIPDB API token](https://www.abuseipdb.com/account/api).


## 🖥️ Usage<div id="usage"></div>
After successful installation, the script will run continuously in the background, monitoring UFW logs and automatically reporting malicious IP addresses.
The tool requires no additional user action after installation. However, it's worth occasionally checking its operation and updating the script regularly (by running the installation command).

Servers open to the world are constantly scanned by bots, usually looking for vulnerabilities or other security gaps.
So don't be surprised if the next day, the number of reports to AbuseIPDB exceeds a thousand.

### 🔍 Checking service status<div id="checking-service-status"></div>
If the tool was installed as a system service, you can check its status using the following command:
```bash
sudo systemctl status abuseipdb-ufw.service
```

To see the current logs generated by the process, use the command:
```bash
journalctl -u abuseipdb-ufw.service -f
```

### 📄 Example report<div id="example-report"></div>
```
Blocked by UFW (TCP on port 848).
Source port: 42764
TTL: 236
Packet length: 40
TOS: 0x00
Timestamp: 2024-08-20 09:06:48 [Europe/Warsaw]

This report (for 83.222.190.122) was generated by:
https://github.com/sefinek24/UFW-AbuseIPDB-Reporter
```


## 🤝 Development<div id="development"></div>
If you want to contribute to the development of this project, feel free to create a new [Pull request](https://github.com/sefinek24/UFW-AbuseIPDB-Reporter/pulls). I will definitely appreciate it!

## 🔑 GPL-3.0 License<div id="license"></div>
Copyright 2024 © by [Sefinek](https://sefinek.net). All rights reserved. See the [LICENSE](LICENSE) file for more information.