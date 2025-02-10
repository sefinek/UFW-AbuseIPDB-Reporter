const { exec } = require('node:child_process');
const ecosystem = require('../ecosystem.config.js');
const discordWebhooks = require('./discord.js');
const log = require('../utils/log.js');

const executeCmd = cmd =>
	new Promise((resolve, reject) => {
		exec(cmd, (err, stdout, stderr) => {
			if (err || stderr) reject(err || stderr);
			else resolve(stdout);
		});
	});

module.exports = async () => {
	const process = ecosystem.apps[0].name;
	await discordWebhooks(4, `Restarting the ${process} process...`);

	try {
		console.log(await executeCmd('npm install --omit=dev'));
		console.log(await executeCmd(`pm2 restart ${process}`));
	} catch (err) {
		log(2, err);
	}
};