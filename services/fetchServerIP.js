const { networkInterfaces } = require('node:os');
const axios = require('./axios.js');
const isLocalIP = require('../utils/isLocalIP.js');
const { IP_REFRESH_INTERVAL } = require('../config.js').MAIN;

const ipAddrList = new Set();

const fetchIPv4Address = async () => {
	try {
		const { data } = await axios.get('https://api.sefinek.net/api/v2/ip');
		if (data?.success && data?.message) ipAddrList.add(data.message);
	} catch (err) {
		console.warn('Error fetching IPv4 address:', err.message);
	}
};

const fetchIPv6Address = () => {
	try {
		Object.values(networkInterfaces()).flat().forEach(({ address, internal }) => {
			if (!internal && address && !isLocalIP(address)) ipAddrList.add(address);
		});
	} catch (err) {
		console.warn('Error fetching IPv6 address:', err.message);
	}
};

const fetchServerIPs = async () => {
	ipAddrList.clear();
	await fetchIPv4Address();
	fetchIPv6Address();
};

(async () => {
	await fetchServerIPs();
	setInterval(fetchServerIPs, IP_REFRESH_INTERVAL);

	// console.debug(ipAddrList);
})();

module.exports = () => Array.from(ipAddrList);