const { AUTO_UPDATE_SCHEDULE } = require('../config.js').MAIN;

const simpleGit = require('simple-git');
const { CronJob } = require('cron');
const restartApp = require('./reloadApp.js');
const log = require('../utils/log.js');

const git = simpleGit();

const pull = async () => {
	log(0, '$ git pull');

	const { summary } = await git.pull();
	log(0, `Changes: ${summary.changes}; Deletions: ${summary.insertions}; Insertions: ${summary.insertions};`);
};

const pullAndRestart = async () => {
	try {
		await pull();
		await restartApp();
	} catch (err) {
		log(2, err.message);
	}
};

// https://crontab.guru
new CronJob(AUTO_UPDATE_SCHEDULE || '0 18 * * *', pullAndRestart, null, true, 'UTC'); // At 18:00

module.exports = { pull };