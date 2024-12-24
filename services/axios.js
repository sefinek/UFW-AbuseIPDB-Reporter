const axios = require('axios');
const { version } = require('../package.json');
const { main } = require('../config.js');

axios.defaults.headers.common = {
	'User-Agent': `Mozilla/5.0 (compatible; UFW-AbuseIPDB-Reporter/${version}; +${main.GITHUB_REPO})`,
	'Accept': 'application/json',
	'Cache-Control': 'no-cache',
	'Connection': 'keep-alive',
};

axios.defaults.timeout = 30000;

module.exports = axios;