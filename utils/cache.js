const fs = require('node:fs');
const { CACHE_FILE, REPORT_INTERVAL } = require('../config.js').MAIN;
const log = require('./log.js');

const reportedIPs = new Map();

const loadReportedIPs = () => {
	if (fs.existsSync(CACHE_FILE)) {
		fs.readFileSync(CACHE_FILE, 'utf8')
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

const saveReportedIPs = () => fs.writeFileSync(CACHE_FILE, Array.from(reportedIPs).map(([ip, time]) => `${ip} ${time}`).join('\n'), 'utf8');

const isIPReportedRecently = ip => {
	const reportedTime = reportedIPs.get(ip);
	return reportedTime && (Date.now() / 1000 - reportedTime < REPORT_INTERVAL / 1000);
};

const markIPAsReported = ip => reportedIPs.set(ip, Math.floor(Date.now() / 1000));

module.exports = { reportedIPs, loadReportedIPs, saveReportedIPs, isIPReportedRecently, markIPAsReported };