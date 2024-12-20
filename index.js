const fs = require('node:fs');
const chokidar = require('chokidar');
const isLocalIP = require('./utils/isLocalIP.js');
const { reportedIps, loadReportedIps, saveReportedIps, isIpReportedRecently, markIpAsReported } = require('./utils/cache.js');
const log = require('./utils/log.js');
const axios = require('./services/axios.js');
const config = require('./config.js');
const { version } = require('./package.json');
const { LOG_FILE, ABUSEIPDB_API_KEY, SERVER_IDENTIFIER } = config.MAIN;

let fileOffset = 0;

const reportToAbuseIpDb = async (ip, categories, comment) => {
	try {
		const { data } = await axios.post('https://api.abuseipdb.com/api/v2/report', new URLSearchParams({ ip, categories, comment }), {
			headers: { 'Key': ABUSEIPDB_API_KEY },
		});

		log(0, `Successfully reported IP ${ip} (abuse: ${data.data.abuseConfidenceScore}%)`);
		return true;
	} catch (err) {
		log(2, `${err.message}\n${JSON.stringify(err.response.data)}`);
		return false;
	}
};

const processLogLine = async line => {
	if (!line.includes('[UFW BLOCK]')) return log(1, `Ignoring line: ${line}`);

	const match = {
		timestamp: line.match(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:\d{2})?/)?.[0] || null,
		srcIp: line.match(/SRC=([\d.]+)/)?.[1] || null,
		dstIp: line.match(/DST=([\d.]+)/)?.[1] || null,
		proto: line.match(/PROTO=(\S+)/)?.[1] || null,
		spt: line.match(/SPT=(\d+)/)?.[1] || null,
		dpt: line.match(/DPT=(\d+)/)?.[1] || null,
		ttl: line.match(/TTL=(\d+)/)?.[1] || null,
		len: line.match(/LEN=(\d+)/)?.[1] || null,
		tos: line.match(/TOS=(\S+)/)?.[1] || null,
	};

	const { srcIp, proto, dpt } = match;
	if (!srcIp) {
		log(1, `Missing SRC in log line: ${line}`);
		return;
	}

	if (isLocalIP(srcIp)) {
		log(0, `Ignoring local/private IP: ${srcIp}`);
		return;
	}

	// Report MUST NOT be of an attack where the source address is likely spoofed i.e. SYN floods and UDP floods.
	// TCP connections can only be reported if they complete the three-way handshake. UDP connections cannot be reported.
	// More: https://www.abuseipdb.com/reporting-policy
	if (proto === 'UDP') {
		log(0, `Skipping UDP traffic: SRC=${srcIp} DPT=${dpt}"`);
		return;
	}

	if (isIpReportedRecently(srcIp)) {
		const lastReportedTime = reportedIps.get(srcIp);
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

		log(0, `IP ${srcIp} was last reported on ${new Date(lastReportedTime * 1000).toLocaleString()} (${timeAgo} ago)`);
		return;
	}

	const categories = config.DETERMINE_CATEGORIES(proto, dpt);
	const comment = config.REPORT_COMMENT(match.timestamp, srcIp, match.dstIp, proto, match.spt, dpt, match.ttl, match.len, match.tos, SERVER_IDENTIFIER);

	log(0, `Reporting IP ${srcIp} (${proto} ${dpt}) with categories: ${categories}`);

	if (await reportToAbuseIpDb(srcIp, categories, comment)) {
		markIpAsReported(srcIp);
		saveReportedIps();
	}
};

const startMonitoring = () => {
	loadReportedIps();

	if (!fs.existsSync(LOG_FILE)) {
		log(2, `Log file ${LOG_FILE} does not exist.`);
		return;
	}

	fileOffset = fs.statSync(LOG_FILE).size;

	chokidar.watch(LOG_FILE, { persistent: true, ignoreInitial: true })
		.on('change', path => {
			const stats = fs.statSync(path);
			if (stats.size < fileOffset) {
				log(1, 'File truncated. Resetting offset...');
				fileOffset = 0;
			}

			fs.createReadStream(path, { start: fileOffset, encoding: 'utf8' }).on('data', chunk => {
				chunk.split('\n').filter(line => line.trim()).forEach(processLogLine);
			}).on('end', () => {
				fileOffset = stats.size;
			});
		});

	log(0, `==================== Version ${version} ====================`);
	log(0, `Ready! Now monitoring: ${LOG_FILE}`);
};

startMonitoring();