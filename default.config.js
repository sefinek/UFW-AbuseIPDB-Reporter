exports.MAIN = {
	LOG_FILE: 'D:\\test\\ufw.log',
	CACHE_FILE: 'D:\\test\\ufw-abuseipdb-reporter.cache',

	ABUSEIPDB_API_KEY: '',
	GITHUB_REPO: 'https://github.com/sefinek/UFW-AbuseIPDB-Reporter',

	REPORT_INTERVAL: 43200,
};

exports.REPORT_COMMENT = (timestamp, srcIp, dstIp, proto, spt, dpt, ttl, len, tos) => {
	return `Blocked by UFW (${proto} on ${dpt})
Source port: ${spt}
TTL: ${ttl || 'N/A'}
Packet length: ${len || 'N/A'}
TOS: ${tos || 'N/A'}

This report (for ${srcIp}) was generated by:
https://github.com/sefinek/UFW-AbuseIPDB-Reporter`; // Please do not remove the URL to the repository of this script. I would be really grateful. 💙
};