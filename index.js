//   Copyright 2024-2025 © by Sefinek. All Rights Reserved.
//                     https://sefinek.net

const fs = require('node:fs');
const chokidar = require('chokidar');
const { parseUfwLog } = require('ufw-log-parser');
const banner = require('./scripts/banners/ufw.js');
const { axiosService } = require('./scripts/services/axios.js');
const { saveBufferToFile, loadBufferFromFile, sendBulkReport, BULK_REPORT_BUFFER } = require('./scripts/services/bulk.js');
const { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported } = require('./scripts/services/cache.js');
const ABUSE_STATE = require('./scripts/services/state.js');
const { refreshServerIPs, getServerIPs } = require('./scripts/services/ipFetcher.js');
const { repoSlug, repoUrl } = require('./scripts/repo.js');
const isSpecialPurposeIP = require('./scripts/isSpecialPurposeIP.js');
const logger = require('./scripts/logger.js');
const config = require('./config.js');
const { UFW_LOG_FILE, SERVER_ID, EXTENDED_LOGS, AUTO_UPDATE_ENABLED, AUTO_UPDATE_SCHEDULE, DISCORD_WEBHOOK_ENABLED, DISCORD_WEBHOOK_URL } = config.MAIN;
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
			logger.success(`Rate limit reset. Next reset scheduled at ${RATELIMIT_RESET.toISOString()}`);
		} else if (now - LAST_RATELIMIT_LOG >= RATE_LIMIT_LOG_INTERVAL) {
			const minutesLeft = Math.ceil((RATELIMIT_RESET.getTime() - now) / 60000);
			logger.success(`Rate limit is still active. Collected ${BULK_REPORT_BUFFER.size} IPs. Waiting for reset in ${minutesLeft} minute(s) (${RATELIMIT_RESET.toISOString()})`);
			LAST_RATELIMIT_LOG = now;
		}
	}
};

const reportIp = async ({ srcIp, dpt = 'N/A', proto = 'N/A', timestamp }, categories, comment) => {
	if (!srcIp) return logger.error('Missing source IP (srcIp)', { ping: true });

	await checkRateLimit();

	if (ABUSE_STATE.isBuffering) {
		if (BULK_REPORT_BUFFER.has(srcIp)) return;
		BULK_REPORT_BUFFER.set(srcIp, { categories, timestamp, comment });
		await saveBufferToFile();
		logger.success(`Queued ${srcIp} for bulk report (collected ${BULK_REPORT_BUFFER.size} IPs)`);
		return;
	}

	try {
		const { data: res } = await axiosService.post('/report', {
			ip: srcIp,
			categories,
			comment,
		});

		logger.success(`Reported ${srcIp} [${dpt}/${proto}]; Categories: ${categories}; Abuse: ${res.data.abuseConfidenceScore}%`);
		return true;
	} catch (err) {
		const status = err.response?.status;
		if (status === 429 && JSON.stringify(err.response?.data || {}).includes('Daily rate limit')) {
			if (!ABUSE_STATE.isLimited) {
				ABUSE_STATE.isLimited = true;
				ABUSE_STATE.isBuffering = true;
				ABUSE_STATE.sentBulk = false;
				LAST_RATELIMIT_LOG = Date.now();
				RATELIMIT_RESET = nextRateLimitReset();
				logger.info(`Daily API request limit for specified endpoint reached. Reports will be buffered until \`${RATELIMIT_RESET.toLocaleString()}\`. Bulk report will be sent the following day.`, { discord: true });
			}

			if (!BULK_REPORT_BUFFER.has(srcIp)) {
				BULK_REPORT_BUFFER.set(srcIp, { timestamp, categories, comment });
				await saveBufferToFile();
				logger.success(`Queued ${srcIp} for bulk report due to rate limit`);
			}
		} else {
			const failureMsg = `Failed to report ${srcIp} [${dpt}/${proto}]; ${err.response?.data?.errors ? JSON.stringify(err.response.data.errors) : err.message}`;
			status === 429 ? logger.info(failureMsg) : logger.error(failureMsg);
		}
	}
};

const processLogLine = async (line, test = false) => {
	if (!line.includes('[UFW BLOCK]')) return logger.warn(`Ignoring invalid line: ${line}`);

	const data = parseUfwLog(line);
	const { srcIp, proto, dpt } = data;
	if (!srcIp) return logger.error(`Missing SRC in the log line: ${line}`, { ping: true });

	// Check IP
	const ips = getServerIPs();
	if (!Array.isArray(ips)) return logger.error(`For some reason, 'ips' from 'getServerIPs()' is not an array. Received: ${ips}`, { ping: true });

	if (ips.includes(srcIp)) {
		if (EXTENDED_LOGS) logger.info(`Ignoring own IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt} ID=${data.id}`);
		return;
	}

	if (isSpecialPurposeIP(srcIp)) {
		if (EXTENDED_LOGS) logger.info(`Ignoring local IP address: PROTO=${proto?.toLowerCase()} SRC=${srcIp} DPT=${dpt} ID=${data.id}`);
		return;
	}

	if (proto === 'UDP') {
		if (EXTENDED_LOGS) logger.info(`Skipping UDP traffic: SRC=${srcIp} DPT=${dpt} ID=${data.id}`);
		return;
	}

	if (test) return data;

	// Report
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

		if (EXTENDED_LOGS) logger.info(`${srcIp} was last reported on ${new Date(lastReportedTime * 1000).toLocaleString()} (${timeAgo} ago)`);
		return;
	}

	const categories = config.DETERMINE_CATEGORIES(data);
	const comment = config.REPORT_COMMENT(data, line);

	if (await reportIp(data, categories, comment)) {
		markIPAsReported(srcIp);
		await saveReportedIPs();
	}
};

(async () => {
	banner();

	// Auto updates
	if (AUTO_UPDATE_ENABLED && AUTO_UPDATE_SCHEDULE && SERVER_ID !== 'development') {
		await require('./scripts/services/updates.js')();
	} else {
		await require('./scripts/services/version.js');
	}

	// Fetch IPs
	await refreshServerIPs();

	// Load cache
	await loadReportedIPs();

	// Bulk
	await loadBufferFromFile();
	if (BULK_REPORT_BUFFER.size > 0 && !ABUSE_STATE.isLimited) {
		logger.info(`Found ${BULK_REPORT_BUFFER.size} IPs in buffer after restart. Sending bulk report...`);
		await sendBulkReport();
	}

	// Check UFW_LOG_FILE
	if (!fs.existsSync(UFW_LOG_FILE)) {
		logger.error(`Log file ${UFW_LOG_FILE} does not exist`, { ping: true });
		return;
	}

	// Watch
	let incompleteLine = '';
	let processing = Promise.resolve();

	fileOffset = fs.statSync(UFW_LOG_FILE).size;
	chokidar.watch(UFW_LOG_FILE, { persistent: true, ignoreInitial: true })
		.on('change', filePath => {
			const stats = fs.statSync(filePath);
			if (stats.size < fileOffset) {
				incompleteLine = '';
				fileOffset = 0;
				logger.info('The file has been truncated, and the offset has been reset');
			}

			const start = fileOffset;
			fileOffset = stats.size;

			processing = processing.then(async () => {
				let data = '';
				try {
					await new Promise((resolve, reject) => {
						fs.createReadStream(filePath, { start, encoding: 'utf8' })
							.on('data', chunk => { data += chunk; })
							.on('end', resolve)
							.on('error', reject);
					});
				} catch (err) {
					logger.error(`Failed to read log chunk: ${err.message}`);
					return;
				}

				const text = incompleteLine + data;
				const lines = text.split('\n');
				incompleteLine = lines.pop();

				for (const line of lines) {
					if (!line.trim()) continue;
					try {
						await processLogLine(line);
					} catch (err) {
						logger.error(`Failed to process log line: ${err.message}`);
					}
				}
			});
		});

	// Summaries
	if (DISCORD_WEBHOOK_ENABLED && DISCORD_WEBHOOK_URL) await require('./scripts/services/summaries.js')();

	// Ready
	await logger.webhook(`[${repoSlug}](${repoUrl}) was successfully started!`, 0x59D267);
	logger.success(`Ready! Now monitoring: ${UFW_LOG_FILE}`);
	process.send?.('ready');
})();

const gracefulShutdown = async signal => {
	logger.info(`Received ${signal}, flushing pending writes...`);
	try {
		await saveBufferToFile();
		await saveReportedIPs();
	} catch (err) {
		logger.error(`Error during shutdown flush: ${err.message}`);
	}
	process.exit(0);
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

module.exports = processLogLine;

// test1