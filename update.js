const { SERVER_ID, AUTO_UPDATE_SCHEDULE, AUTO_UPDATE_ENABLED } = require('./config.js').MAIN;

if (AUTO_UPDATE_ENABLED) {
	const simpleGit = require('simple-git');
	const { CronJob } = require('cron');
	const restartApp = require('./services/reloadApp.js');
	const log = require('./utils/log.js');

	const git = simpleGit();

	const updateScript = async () => {
		log(0, 'The script is being updated...');

		try {
			const { summary } = await git.pull();
			log(0, `Changes: ${summary.changes}; Deletions: ${summary.insertions}; Insertions: ${summary.insertions};`);

			if (SERVER_ID !== 'development') await restartApp();
		} catch (err) {
			log(2, err.message);
		}
	};

	// https://crontab.guru
	new CronJob(AUTO_UPDATE_SCHEDULE || '0 18 * * *', updateScript, null, true, 'UTC'); // At 18:00

	if (SERVER_ID === 'development') (async () => updateScript())();
}