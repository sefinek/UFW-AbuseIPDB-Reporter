const { AUTO_UPDATE_SCHEDULE } = require('../config.js').MAIN;

const simpleGit = require('simple-git');
const { CronJob } = require('cron');
const restartApp = require('./reloadApp.js');
const log = require('../utils/log.js');
const discordWebhooks = require('./discord.js');

const git = simpleGit();

const pull = async () => {
	await discordWebhooks(4, 'Updating the local repository in progress `(git pull)`...');
	log(0, '$ git pull');

	try {
		const { summary } = await git.pull();
		log(0, `Changes: ${summary.changes}; Deletions: ${summary.insertions}; Insertions: ${summary.insertions}`);
		await discordWebhooks(4, `**Changes:** ${summary.changes}; **Deletions:** ${summary.insertions}; **Insertions:** ${summary.insertions}`);
	} catch (err) {
		log(2, err);
	}
};

const pullAndRestart = async () => {
	try {
		await pull();
		await restartApp();
	} catch (err) {
		log(2, err);
	}
};

// https://crontab.guru
new CronJob(AUTO_UPDATE_SCHEDULE, pullAndRestart, null, true, 'UTC');

module.exports = pull;