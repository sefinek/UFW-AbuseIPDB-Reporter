exports.MAIN = {
	// Server
	UFW_FILE: '/var/log/ufw.log',
	CACHE_FILE: '/tmp/ufw-abuseipdb-reporter.cache',
	SERVER_ID: null, // The server name that will be visible in the reports. If you don't want to define it, leave the value as null.

	// Reporting
	ABUSEIPDB_API_KEY: '',
	REPORT_INTERVAL: 12 * 60 * 60 * 1000, // 12h

	// Project
	GITHUB_REPO: 'https://github.com/sefinek/UFW-AbuseIPDB-Reporter', // If you are using a fork, provide the link to the forked repository here.
};

/**
 * Generates a report submission to AbuseIPDB.
 * @param {Object} logData
 * @param {string|null} logData.timestamp
 * @param {string|null} logData.In
 * @param {string|null} logData.Out
 * @param {string|null} logData.srcIp
 * @param {string|null} logData.dstIp
 * @param {string|null} logData.res
 * @param {string|null} logData.tos
 * @param {string|null} logData.prec
 * @param {string|null} logData.ttl
 * @param {string|null} logData.id
 * @param {string|null} logData.proto
 * @param {string|null} logData.spt
 * @param {string|null} logData.dpt
 * @param {string|null} logData.len
 * @param {string|null} logData.urgp
 * @param {string|null} logData.mac
 * @param {string|null} logData.window
 * @param {boolean} logData.syn
 * @param {string|null} fullLog
 * @param {string|null} serverName
 * @returns {string} A formatted string report.
 */
exports.REPORT_COMMENT = ({ timestamp, In, Out, srcIp, dstIp, res, tos, prec, ttl, id, proto, spt, dpt, len, urgp, mac, window, syn }, fullLog, serverName) => {
	return `Blocked by UFW ${serverName ? `on ${serverName} ` : ''}[${dpt}/${proto?.toLowerCase()}]
Source port: ${spt || 'N/A'}
TTL: ${ttl || 'N/A'}
Packet length: ${len || 'N/A'}
TOS: ${tos || 'N/A'}

This report was generated by:
https://github.com/sefinek/UFW-AbuseIPDB-Reporter`; // Please do not remove this URL; I would be very grateful! Thank you. 💙
};

// See: https://www.abuseipdb.com/categories
exports.DETERMINE_CATEGORIES = (proto, dpt) => {
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
		UDP: {
			53: '14,1,2', // Port Scan | DNS Compromise | DNS Poisoning
			123: '14,17', // Port Scan | Spoofing
		},
	};

	return categories[proto]?.[dpt] || '14'; // Port Scan
};