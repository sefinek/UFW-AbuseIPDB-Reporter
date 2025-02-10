const discordWebhooks = require('../services/discord.js');

const levels = {
	0: { method: 'log', label: '[INFO]' },
	1: { method: 'warn', label: '[WARN]' },
	2: { method: 'error', label: '[FAIL]' },
};

module.exports = (level, msg) => {
	const { method, label } = levels[level] || { method: 'log', label: '[N/A]' };
	console[method](`${label} ${msg}`);

	if (level >= 1) discordWebhooks(level, msg).catch(console.error);
};