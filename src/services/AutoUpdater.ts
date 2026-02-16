
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

    // In a real scenario, this would check a remote endpoint.
    // For now, we will simulate the check or assume a git repo is available.
    public async checkForUpdates(): Promise<boolean> {
        try {
            logger.info('Checking for updates via Git...');
            
            // Check if .git exists
            if (!fs.existsSync(path.join(process.cwd(), '.git'))) {
                logger.warn('AutoUpdater: Not a git repository. Skipping update check.');
                return false;
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
