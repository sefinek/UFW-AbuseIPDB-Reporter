const os = require('node:os');
const axios = require('./axios.js');
const isLocalIP = require('./isLocalIP.js');

let ipAddressList = [];

const fetchIPv4Address = async () => {
	try {
		const { data } = await axios.get('https://api.sefinek.net/api/v2/ip');
		if (data?.success && data?.message) ipAddressList.push(data.message);
	} catch (err) {
		console.warn('Error fetching IPv4 address:', err.message);
	}
};

const fetchIPv6Address = () => {
	const networkInterfaces = os.networkInterfaces();

	for (const interfaces of Object.values(networkInterfaces)) {
		for (const details of interfaces) {
			const ip = details.address;
			if (!details.internal && ip && !isLocalIP(ip)) ipAddressList.push(ip);
		}
	}
};

const fetchIPAddress = async () => {
	ipAddressList = [];
	await fetchIPv4Address();
	fetchIPv6Address();
};

(async () => {
	await fetchIPAddress();
	setInterval(fetchIPAddress, 25 * 1000);
})();

module.exports = () => [...ipAddressList];