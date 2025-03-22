exports.MAIN = {
	// My Server
	UFW_LOG_FILE: '/var/log/ufw.log',
	CACHE_FILE: '/tmp/ufw-abuseipdb-reporter.cache',
	SERVER_ID: null, // The server name that will be visible in the reports (e.g., 'homeserver1'). If you don't want to define it, leave the value as null.
	IP_REFRESH_SCHEDULE: '0 */6 * * *', // CRON: How often should the script check the IP address assigned by the ISP to prevent accidental self-reporting? Default: every 6 hours
	IPv6_SUPPORT: true, // Specifies whether the device has been assigned an IPv6 address.

	// Reporting
	ABUSEIPDB_API_KEY: '', // Secret API key for AbuseIPDB.
	IP_REPORT_COOLDOWN: 12 * 60 * 60 * 1000, // The minimum time (12 hours) that must pass before reporting the same IP address again.

	// Automatic Updates
	AUTO_UPDATE_ENABLED: true, // Do you want the script to automatically update to the latest version using 'git pull'? (true = enabled, false = disabled)
	AUTO_UPDATE_SCHEDULE: '0 18 * * *', // CRON: Schedule for automatic script updates. Default: every day at 18:00

	// Discord Webhooks
	DISCORD_WEBHOOKS_ENABLED: false, // Should the script send webhooks? They will contain error reports, daily summaries related to reports, etc.
	DISCORD_WEBHOOKS_URL: '', // Webhook URL.
};


/**
 * Generates a report submission to AbuseIPDB.
 * @returns {string} A formatted string report.
 */
exports.REPORT_COMMENT = ({ date, srcIp, dstIp, proto, spt, dpt, In, Out, mac, len, ttl, id, tos, prec, res, window, urgp, syn }, fullLog, serverName) =>
	`Blocked by UFW ${serverName ? `on ${serverName} ` : ''}[${dpt || 'N/A'}/${proto?.toLowerCase() || 'N/A'}]
Source port: ${spt || 'N/A'}
TTL: ${ttl || 'N/A'}
Packet length: ${len || 'N/A'}
TOS: ${tos || 'N/A'}

This report was generated by:
https://github.com/sefinek/UFW-AbuseIPDB-Reporter`; // Please do not delete this URL. I would be very grateful, thank you! 💙

// Alternative version:
// exports.REPORT_COMMENT = ({ date, In, Out, srcIp, dstIp, res, tos, prec, ttl, id, proto, spt, dpt, len, urgp, mac, window, syn }, fullLog, serverName) =>
// 	`Blocked by UFW ${serverName ? `on ${serverName} ` : ''}[${dpt}/${proto?.toLowerCase()}]. Generated by: https://github.com/sefinek/UFW-AbuseIPDB-Reporter`;


// See: https://www.abuseipdb.com/categories
const categories = {
	TCP: {
		22: '14,22,18', // Port Scan | SSH | Brute-Force
		80: '14,21', // Port Scan | Web App Attack
		443: '14,21', // Port Scan | Web App Attack
		8080: '14,21', // Port Scan | Web App Attack
		25: '14,11', // Port Scan | Email Spam
		21: '14,5,18', // Port Scan | FTP Brute-Force | Brute-Force
		53: '14,1,2', // Port Scan | DNS Compromise | DNS Poisoning
		23: '14,15,18', // Port Scan | Hacking | Brute-Force
		3389: '14,15,18', // Port Scan | Hacking | Brute-Force
		3306: '14,16', // Port Scan | SQL Injection
		6666: '14,8', // Port Scan | Fraud VoIP
		6667: '14,8', // Port Scan | Fraud VoIP
		6668: '14,8', // Port Scan | Fraud VoIP
		6669: '14,8', // Port Scan | Fraud VoIP
		9999: '14,6', // Port Scan | Ping of Death
	},
	UDP: {},
};

exports.DETERMINE_CATEGORIES = ({ proto, dpt }) => categories[proto]?.[dpt] || '14'; // Default: Port Scan