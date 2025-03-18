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
const serverAddress = require('./scripts/services/fetchServerIP.js');
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

const processLogLine = async line => {
	if (!line.includes('[UFW BLOCK]')) return log(0, `Ignoring invalid line: ${line}`);

	const logData = {
		timestamp: parseTimestamp(line), // Log timestamp
		srcIp: line.match(/SRC=([\d.]+)/)?.[1] || null, // Source IP address
		dstIp: line.match(/DST=([\d.]+)/)?.[1] || null, // Destination IP address
		proto: line.match(/PROTO=(\S+)/)?.[1] || null, // Protocol (TCP, UDP, ICMP, etc.)
		spt: line.match(/SPT=(\d+)/)?.[1] || null, // Source port
		dpt: line.match(/DPT=(\d+)/)?.[1] || null, // Destination port
		in: line.match(/IN=(\w+)/)?.[1] || null, // Input interface
		out: line.match(/OUT=(\w+)/)?.[1] || null, // Output interface
		mac: line.match(/MAC=([\w:]+)/)?.[1] || null, // MAC address
		len: line.match(/LEN=(\d+)/)?.[1] || null, // Packet length
		ttl: line.match(/TTL=(\d+)/)?.[1] || null, // Time to live
		id: line.match(/ID=(\d+)/)?.[1] || null, // Packet ID
		tos: line.match(/TOS=(\S+)/)?.[1] || null, // Type of service
		prec: line.match(/PREC=(\S+)/)?.[1] || null, // Precedence
		res: line.match(/RES=(\S+)/)?.[1] || null, // Reserved bits
		window: line.match(/WINDOW=(\d+)/)?.[1] || null, // TCP Window size
		urgp: line.match(/URGP=(\d+)/)?.[1] || null, // Urgent pointer
		ack: !!line.includes('ACK'), // ACK flag
		syn: !!line.includes('SYN'), // SYN flag
	};

	const { srcIp, proto, dpt } = logData;
	if (!srcIp) {
		return log(1, `Missing SRC in log line: ${line}`);
	}

	if (serverAddress().includes(srcIp)) {
		return log(0, `Ignoring own IP address: ${srcIp}`);
	}

	const ips = serverAddress();
	if (!Array.isArray(ips)) {
		return log(1, 'For some reason, \'ips\' is not an array');
	}

	if (ips.includes(srcIp)) {
		return log(0, `Ignoring own IP address: ${srcIp}`);
	}

	// Report MUST NOT be of an attack where the source address is likely spoofed i.e. SYN floods and UDP floods.
	// TCP connections can only be reported if they complete the three-way handshake. UDP connections cannot be reported.
	// More: https://www.abuseipdb.com/reporting-policy
	if (proto === 'UDP') {
		return log(0, `Skipping UDP traffic: SRC=${srcIp} DPT=${dpt}`);
	}

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
	log(0, `v${version} (https://github.com/sefinek/UFW-AbuseIPDB-Reporter)`);

	loadReportedIPs();

	if (!fs.existsSync(UFW_LOG_FILE)) {
		log(2, `Log file ${UFW_LOG_FILE} does not exist.`);
		return;
	}

	fileOffset = fs.statSync(UFW_LOG_FILE).size;

	chokidar.watch(UFW_LOG_FILE, { persistent: true, ignoreInitial: true })
		.on('change', path => {
			const stats = fs.statSync(path);
			if (stats.size < fileOffset) {
				fileOffset = 0;
				log(1, 'The file has been truncated, and the offset has been reset.');
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
	log(0, '=====================================================================');

	process.send && process.send('ready');
})();