const axios = require('./axios.js');

let address = null;

const fetchIPAddress = async () => {
	if (address) return;

	try {
		const { data } = await axios.get('https://api.sefinek.net/api/v2/ip');
		if (data?.success && data?.message) {
			address = data.message;
		} else {
			setTimeout(fetchIPAddress, 20 * 1000);
		}
	} catch {
		setTimeout(fetchIPAddress, 25 * 1000);
	}
};

(async () => fetchIPAddress())();

module.exports = () => address;