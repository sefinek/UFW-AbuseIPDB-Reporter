const os = require('node:os');
const axios = require('./axios.js');
const isLocalIP = require('../utils/isLocalIP.js');
const { MAIN } = require('../config.js');

const ipAddressList = new Set();

const fetchIPv4Address = async () => {
	try {
		const { data } = await axios.get('https://api.sefinek.net/api/v2/ip');
		if (data?.success && data?.message) ipAddressList.add(data.message);
	} catch (err) {
		console.warn('Error fetching IPv4 address:', err.message);
	}
};

const fetchIPv6Address = () => {
	const networkInterfaces = os.networkInterfaces();

	Object.values(networkInterfaces).forEach(interfaces => {
		interfaces.forEach(details => {
			const ip = details.address;
			if (!details.internal && ip && !isLocalIP(ip)) {
				ipAddressList.add(ip);
			}
		});
	});
};

const fetchIPAddress = async () => {
	ipAddressList.clear();
	await fetchIPv4Address();
	fetchIPv6Address();
};

(async () => {
	await fetchIPAddress();
	setInterval(fetchIPAddress, MAIN.REFRESHING_IP_ADDRESS);

	// console.debug(ipAddressList);
})();

module.exports = () => Array.from(ipAddressList);