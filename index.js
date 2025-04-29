//   Copyright 2024-2025 (c) by Sefinek All rights reserved.
//                     https://sefinek.net

const fs = require('node:fs');
const chokidar = require('chokidar');
const { parseUfwLog } = require('ufw-log-parser');
const axios = require('./scripts/services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { name, version, authorEmailWebsite, repoFullUrl } = require('./scripts/repo.js');
const sendWebhook = require('./scripts/services/discordWebhooks.js');
const isLocalIP = require('./scripts/isLocalIP.js');
const log = require('./scripts/log.js');
const config = require('./config.js');
const { UFW_LOG_FILE, ABUSEIPDB_API_KEY, SERVER_ID, EXTENDED_LOGS, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = config.MAIN;

const ABUSE_STATE = { isLimited: false, isBuffering: false, sentBulk: false };
const RATE_LIMIT_LOG_INTERVAL = 10 * 60 * 1000;
const BUFFER_STATS_INTERVAL = 5 * 60 * 1000;

const nextRateLimitReset = () => {
	const now = new Date();
	return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1, 0, 1));
};

let LAST_RATELIMIT_LOG = 0, LAST_STATS_LOG = 0, RATELIMIT_RESET = nextRateLimitReset(), fileOffset = 0;

const checkRateLimit = async () => {
	const now = Date.now();
	if (now - LAST_STATS_LOG >= BUFFER_STATS_INTERVAL && BULK_REPORT_BUFFER.size > 0) LAST_STATS_LOG = now;

	if (ABUSE_STATE.isLimited) {
		if (now >= RATELIMIT_RESET.getTime()) {
			ABUSE_STATE.isLimited = false;
			ABUSE_STATE.isBuffering = false;
			if (!ABUSE_STATE.sentBulk && BULK_REPORT_BUFFER.size > 0) await sendBulkReport();
			RATELIMIT_RESET = nextRateLimitReset();
			ABUSE_STATE.sentBulk = false;
			log(`Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`, 1);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			log(`Rate limit is still active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`, 1);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async ({ srcIp, dpt = 'N/A', proto = 'N/A', id, timestamp }, categories, comment) => {
	if (!srcIp) return log('Missing source IP (srcIp)', 3);

	if (getServerIPs().includes(srcIp)) return;
	if (isIPReportedRecently(srcIp)) return;

	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;
		BULK_REPORT_BUFFER.set(srcIp, { categories, timestamp, comment });
		saveBufferToFile();
		log(`Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`, 1);
		return;
	}

	try {
		const { data: res } = await axios.post('/report', new URLSearchParams({
			ip: srcIp,
			categories,
			comment,
		}), { headers: { 'Key': ABUSEIPDB_API_KEY } });

		log(`Reported ${srcIp} [${dpt}/${proto}]; ID: ${id}; Categories: ${categories}; Abuse: ${res.data.abuseConfidenceScore}%`, 1);
		return true;
	} catch (err) {
		const status = err.response?.status ?? 'unknown';
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				log(`Daily AbuseIPDB limit reached. Buffering reports until ${RATELIMIT_RESET.toISOString()}`);
			}

			if (!BULK_REPORT_BUFFER.has(srcIp)) {
				BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
				saveBufferToFile();
				log(`Queued ${srcIp} for bulk report due to rate limit`, 1);
			}
		} else {
			log(`Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`, status === 429 ? 0 : 3);
		}
	}
};

const processLogLine = async (line, test = false) => {
	if (!line.includes('[UFW BLOCK]')) return log(`Ignoring invalid line: ${line}`, 2);

	const data = parseUfwLog(line);
	const { srcIp, proto, dpt } = data;
	if (!srcIp) return log(`Missing SRC in the log line: ${line}`, 3);

	const ips = getServerIPs();
	if (!Array.isArray(ips)) return log(`For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`, 3, true);

	if (ips.includes(srcIp)) return log(`Ignoring own IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt} ID=${data.id}`, 2, true);
	if (isLocalIP(srcIp)) return log(`Ignoring local IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt} ID=${data.id}`, 2, true);
	if (proto === 'UDP') {
		if (EXTENDED_LOGS) log(`Skipping UDP traffic: SRC=${srcIp} DPT=${dpt} ID=${data.id}`);
		return;
	}

	if (test) return data;

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
			(seconds || (!days && !hours && !minutes)) && `${seconds}s`,
		].filter(Boolean).join(' ');

		if (EXTENDED_LOGS) log(`${srcIp} was last reported on ${new Date(lastReportedTime * 1000).toLocaleString()} (${timeAgo} ago)`);
		return;
	}

	const categories = config.DETERMINE_CATEGORIES(data);
	const comment = config.REPORT_COMMENT(data, line);

	if (await reportIp(data, categories, comment)) {
		markIPAsReported(srcIp);
		saveReportedIPs();
	}
};

(async () => {
	log(`${repoFullUrl} - v${version} | Author: ${authorEmailWebsite}`);

	loadReportedIPs();
	loadBufferFromFile();

	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		log(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	log('Trying to fetch your IPv4 and IPv6 address from api.sefinek.net...');
	await refreshServerIPs();
	log(`Fetched ${getServerIPs()?.length} of your IP addresses. If any of them accidentally appear in the UFW logs, they will be ignored.`, 1);

	if (!fs.existsSync(UFW_LOG_FILE)) {
		log(`Log file ${UFW_LOG_FILE} does not exist`, 3);
		return;
	}

	fileOffset = fs.statSync(UFW_LOG_FILE).size;

	chokidar.watch(UFW_LOG_FILE, { persistent: true, ignoreInitial: true })
		.on('change', path => {
			const stats = fs.statSync(path);
			if (stats.size < fileOffset) {
				fileOffset = 0;
				log('The file has been truncated, and the offset has been reset');
			}

			fs.createReadStream(path, { start: fileOffset, encoding: 'utf8' }).on('data', chunk => {
				chunk.split('\n').filter(line => line.trim()).forEach(processLogLine);
			}).on('end', () => {
				fileOffset = stats.size;
			});
		});

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js')();
	} else {
		await require('./scripts/services/version.js')();
	}

	// Summaries
	if (DISCORD_WEBHOOKS_ENABLED && DISCORD_WEBHOOKS_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await sendWebhook(`[${name}](${repoFullUrl}) has been successfully started on the device \`${SERVER_ID}\`.`, 0x59D267);
	log(`Ready! Now monitoring: ${UFW_LOG_FILE}`, 1);
	process.send && process.send('ready');
})();

module.exports = processLogLine;