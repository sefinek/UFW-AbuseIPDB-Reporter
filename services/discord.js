const axios = require('axios');
const log = require('../utils/log.js');
const { SERVER_ID, DISCORD_WEBHOOKS_ENABLED, DISCORD_WEBHOOKS_URL } = require('../config.js').MAIN;

const TYPES = {
	0: { type: 'SUCCESS', emoji: '\\✅', color: 0x60D06D },
	1: { type: 'WARN', emoji: '\\⚠️', color: 0xFFB02E },
	2: { type: 'ERROR', emoji: '\\❌', color: 0xF92F60 },
	3: { type: 'FAIL', emoji: '\\🔴', color: 0xF8312F },
	4: { type: 'INFO', emoji: '\\📄', color: 0xF2EEF8 },
	5: { type: 'DEBUG', emoji: '\\🛠️', color: 0xB4ACBC },
	6: { type: 'CRITICAL', emoji: '\\🔴', color: 0xF8312F },
	7: { type: 'NOTICE', emoji: '\\📝', color: 0xF3EEF8 },
};

module.exports = async (id, description) => {
	if (!DISCORD_WEBHOOKS_ENABLED || !DISCORD_WEBHOOKS_URL) return;

	const logType = TYPES[id];
	if (!logType) return log(1, 'Invalid log type ID provided!');

	const config = {
		method: 'POST',
		url: DISCORD_WEBHOOKS_URL,
		headers: { 'Content-Type': 'application/json' },
		data: {
			embeds: [{
				title: `${logType.emoji} ${SERVER_ID}: ${logType.type} [ID ${id}]`,
				description,
				color: logType.color,
				footer: {
					text: `Date: ${new Date().toLocaleString()} | sefinek/UFW-AbuseIPDB-Reporter`,
				},
				timestamp: new Date().toISOString(),
			}],
		},
	};

	try {
		const res = await axios(config);
		if (res.status !== 204) log(1, 'Failed to deliver Discord Webhook');
	} catch (err) {
		log(2, `Failed to send Discord Webhook! ${err.stack}`);
	}
};