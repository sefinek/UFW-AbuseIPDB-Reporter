const { existsSync, readFileSync, writeFileSync } = require('node:fs');
const { CACHE_FILE, IP_REPORT_COOLDOWN } = require('../config.js').MAIN;
const log = require('../utils/log.js');

const reportedIPs = new Map();

const loadReportedIPs = () => {
	if (existsSync(CACHE_FILE)) {
		readFileSync(CACHE_FILE, 'utf8')
			.split('\n')
			.forEach(line => {
				const [ip, time] = line.split(' ');
				if (ip && time) reportedIPs.set(ip, Number(time));
			});
		log(0, `Loaded ${reportedIPs.size} IPs from ${CACHE_FILE}`);
	} else {
		log(0, `${CACHE_FILE} does not exist. No data to load.`);
	}
};

const saveReportedIPs = () => writeFileSync(CACHE_FILE, Array.from(reportedIPs).map(([ip, time]) => `${ip} ${time}`).join('\n'), 'utf8');

const isIPReportedRecently = ip => {
	const reportedTime = reportedIPs.get(ip);
	return reportedTime && (Date.now() / 1000 - reportedTime < IP_REPORT_COOLDOWN / 1000);
};

const markIPAsReported = ip => reportedIPs.set(ip, Math.floor(Date.now() / 1000));

module.exports = { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported };