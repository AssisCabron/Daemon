
import { exec } from 'child_process';
import util from 'util';
import fs from 'fs';
import path from 'path';
import winston from 'winston';

const execAsync = util.promisify(exec);
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.simple(),
    transports: [new winston.transports.Console()],
});

export class AutoUpdater {
    private isUpdateInProgress = false;

    public async checkForUpdates(): Promise<boolean> {
        try {
            // Check if .git exists and configure if needed
            if (!fs.existsSync(path.join(process.cwd(), '.git'))) {
                logger.warn('AutoUpdater: Not a git repository. Attempting to initialize...');
                try {
                    await execAsync('git init');
                    await execAsync('git remote add origin https://github.com/AssisCabron/Daemon');
                    await execAsync('git fetch');
                    try {
                        await execAsync('git checkout main');
                        await execAsync('git branch --set-upstream-to=origin/main main');
                    } catch (e) {
                         logger.warn('AutoUpdater: Could not checkout main branch automatically.');
                    }
                    logger.info('AutoUpdater: Git repository initialized successfully.');
                } catch (e: any) {
                    logger.error(`AutoUpdater: Failed to initialize git repository: ${e.message}`);
                    return false;
                }
            } else {
                // Ensure remote is correct
                try {
                    await execAsync('git remote set-url origin https://github.com/AssisCabron/Daemon');
                } catch (e) {
                    // ignore
                }
            }

            // Fetch latest
            await execAsync('git fetch');
            
            // Check status
            const { stdout } = await execAsync('git status -uno');
            if (stdout.includes('Your branch is behind')) {
                logger.info('AutoUpdater: Update available!');
                return true;
            } else {
                logger.info('AutoUpdater: No updates found.');
                return false;
            }
        } catch (err: any) {
            logger.error(`AutoUpdater Check Failed: ${err.message}`);
            return false;
        }
    }

    public async update(): Promise<void> {
        if (this.isUpdateInProgress) return;
        this.isUpdateInProgress = true;

        try {
            logger.info('AutoUpdater: Starting update process...');
            
            // Pull changes
            await execAsync('git pull');
            
            // Install dependencies
            logger.info('AutoUpdater: Installing dependencies...');
            await execAsync('npm install');

            // Build (if needed, but we are running ts-node-dev for now)
            // await execAsync('npm run build');

            logger.info('AutoUpdater: Update complete! Restarting process...');
            
            // Exit - process manager (PM2/Docker/Systemd) should restart us
            process.exit(0); 

        } catch (err: any) {
            logger.error(`AutoUpdater Failed: ${err.message}`);
            this.isUpdateInProgress = false;
        }
    }
    
    public startService() {
        // Check every 5 seconds
        setInterval(() => {
            this.checkForUpdates().then(hasUpdate => {
                if (hasUpdate) {
                    this.update();
                }
            });
        }, 5000);
        
        // Also check on start
        this.checkForUpdates().then(hasUpdate => {
            if (hasUpdate) {
                this.update();
            }
        });
    }
}

export const autoUpdater = new AutoUpdater();
