//
//   Copyright 2024-2025 (c) by Sefinek All rights reserved.
//                     https://sefinek.net
//

const fs = require('node:fs');
const chokidar = require('chokidar');
const parseTimestamp = require('./scripts/utils/parseTimestamp.js');
const { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const log = require('./scripts/utils/log.js');
const axios = require('./scripts/services/axios.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const discordWebhooks = require('./scripts/services/discord.js');
const config = require('./config.js');
const { version } = require('./package.json');
const { UFW_LOG_FILE, ABUSEIPDB_API_KEY, SERVER_ID, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

let fileOffset = 0;

const reportToAbuseIPDb = async (logData, categories, comment) => {
	try {
		const { data: res } = await axios.post('https://api.abuseipdb.com/api/v2/report', new URLSearchParams({
			ip: logData.srcIp,
			categories,
			comment,
		}), { headers: { 'Key': ABUSEIPDB_API_KEY } });

		log(0, `Reported ${logData.srcIp} [${logData.dpt}/${logData.proto}]; ID: ${logData.id}; Categories: ${categories}; Abuse: ${res.data.abuseConfidenceScore}%`);
		return true;
	} catch (err) {
		log(2, `Failed to report ${logData.srcIp} [${logData.dpt}/${logData.proto}]; ID: ${logData.id}; ${err.message}\n${JSON.stringify(err.response.data?.errors || err.response.data)}`);
		return false;
	}
};

const toNumber = (str, regex) => {
	const parsed = str.match(regex)?.[1];
	return parsed ? Number(parsed) : parsed;
};

const processLogLine = async (line, test = false) => {
	if (!line.includes('[UFW BLOCK]')) return log(0, `Ignoring invalid line: ${line}`);

	const logData = {
		date: parseTimestamp(line), // Log timestamp
		srcIp: line.match(/SRC=([\d.]+)/)?.[1] || null, // Source IP address
		dstIp: line.match(/DST=([\d.]+)/)?.[1] || null, // Destination IP address
		proto: line.match(/PROTO=(\S+)/)?.[1] || null, // Protocol (TCP, UDP, etc.)
		spt: toNumber(line, /SPT=(\d+)/), // Source port
		dpt: toNumber(line, /DPT=(\d+)/), // Destination port
		in: line.match(/IN=(\w+)/)?.[1] || null, // Input interface
		out: line.match(/OUT=(\w+)/)?.[1] || null, // Output interface
		mac: line.match(/MAC=([\w:]+)/)?.[1] || null, // MAC address
		len: toNumber(line, /LEN=(\d+)/), // Packet length
		ttl: toNumber(line, /TTL=(\d+)/), // Time to live
		id: toNumber(line, /ID=(\d+)/), // Packet ID
		tos: line.match(/TOS=(\S+)/)?.[1] || null, // Type of service
		prec: line.match(/PREC=(\S+)/)?.[1] || null, // Precedence
		res: line.match(/RES=(\S+)/)?.[1] || null, // Reserved bits
		window: toNumber(line, /WINDOW=(\d+)/), // TCP Window size
		urgp: toNumber(line, /URGP=(\d+)/), // Urgent pointer
		ack: !!line.includes('ACK'), // ACK flag
		syn: !!line.includes('SYN'), // SYN flag
	};

	const { srcIp, proto, dpt } = logData;
	if (!srcIp) {
		return log(2, `Missing SRC in the log line: ${line}`);
	}

	const ips = getServerIPs();
	if (!Array.isArray(ips)) {
		return log(2, 'For some reason, \'ips\' is not an array');
	}

	if (ips.includes(srcIp)) {
		return log(0, `Ignoring own IP address! PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt} ID=${logData.id}`);
	}

	// Report MUST NOT be of an attack where the source address is likely spoofed i.e. SYN floods and UDP floods.
	// TCP connections can only be reported if they complete the three-way handshake. UDP connections cannot be reported.
	// Read more: https://www.abuseipdb.com/reporting-policy
	if (proto === 'UDP') {
		return log(0, `Skipping UDP traffic: SRC=${srcIp} DPT=${dpt}`);
	}

	// Testing
	if (test) return logData;

	if (isIPReportedRecently(srcIp)) {
		const lastReportedTime = reportedIPs.get(srcIp);
		const elapsedTime = Math.floor(Date.now() / 1000 - lastReportedTime);

		const days = Math.floor(elapsedTime / 86400);
		const hours = Math.floor((elapsedTime % 86400) / 3600);
		const minutes = Math.floor((elapsedTime % 3600) / 60);
		const seconds = elapsedTime % 60;

		const timeAgo = [
			days && `${days}d`,
			hours && `${hours}h`,
			minutes && `${minutes}m`,
			(seconds || !days && !hours && !minutes) && `${seconds}s`,
		].filter(Boolean).join(' ');

		log(0, `${srcIp} was last reported on ${new Date(lastReportedTime * 1000).toLocaleString()} (${timeAgo} ago)`);
		return;
	}

	const categories = config.DETERMINE_CATEGORIES(logData);
	const comment = config.REPORT_COMMENT(logData, line, SERVER_ID);

	if (await reportToAbuseIPDb(logData, categories, comment)) {
		markIPAsReported(srcIp);
		saveReportedIPs();
	}
};

(async () => {
	log(0, `Version ${version} - https://github.com/sefinek/UFW-AbuseIPDB-Reporter`);

	loadReportedIPs();

	log(0, 'Trying to fetch your IPv4 and IPv6 address from api.sefinek.net...');
	await refreshServerIPs();
	log(0, `Fetched ${getServerIPs()?.length} of your IP addresses. If any of them accidentally appear in the UFW logs, they will be ignored.`);

	if (!fs.existsSync(UFW_LOG_FILE)) {
		log(2, `Log file ${UFW_LOG_FILE} does not exist`);
		return;
	}

	fileOffset = fs.statSync(UFW_LOG_FILE).size;

	chokidar.watch(UFW_LOG_FILE, { persistent: true, ignoreInitial: true })
		.on('change', path => {
			const stats = fs.statSync(path);
			if (stats.size < fileOffset) {
				fileOffset = 0;
				log(1, 'The file has been truncated, and the offset has been reset');
			}

			fs.createReadStream(path, { start: fileOffset, encoding: 'utf8' }).on('data', chunk => {
				chunk.split('\n').filter(line => line.trim()).forEach(processLogLine);
			}).on('end', () => {
				fileOffset = stats.size;
			});
		});

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') await require('./scripts/services/updates.js')();
	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./scripts/services/summaries.js')();

	// Final
	if (SERVER_ID !== 'development') {
		await discordWebhooks(0, `[UFW-AbuseIPDB-Reporter](https://github.com/sefinek/UFW-AbuseIPDB-Reporter) has been successfully launched on the device \`${SERVER_ID}\`.`);
	}

	log(0, `Ready! Now monitoring: ${UFW_LOG_FILE}`);
	process.send && process.send('ready');
})();

module.exports = processLogLine;