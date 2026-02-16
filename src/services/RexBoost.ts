import Dockerode from 'dockerode';
import winston from 'winston';
import fs from 'fs';
import path from 'path';
import { prisma } from '../lib/prisma';

const docker = new Dockerode();
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [new winston.transports.Console()],
});

export class RexBoost {
    /**
     * Turbo Mode: Adjusts CPU shares/priority for a container.
     * Higher shares = more CPU time when the node is under load.
     */
    public static async setTurboMode(serverId: string, enabled: boolean) {
        try {
            // Persist the preference in the database first
            const server = await prisma.server.update({
                where: { id: serverId },
                data: { turboMode: enabled }
            });

            const containerName = `rexhost-${serverId}`;
            const container = docker.getContainer(containerName);
            const cpuWeight = enabled ? 2000 : 1000;

            try {
                const inspect = await container.inspect();
                if (inspect.State.Running) {
                    await container.update({
                        CpuShares: cpuWeight
                    });
                    logger.info(`[RexBoost] LIVE UPDATE: Applied CpuShares=${cpuWeight} to ${server.name}. Verify with: docker inspect rexhost-${serverId} --format='{{.HostConfig.CpuShares}}'`);
                }
            } catch (dockerErr) {
                // If container doesn't exist or is stopped, we skip the live update.
                // It will be applied during the next start sequence.
                logger.info(`[RexBoost] PREFERENCE SAVED: Turbo Mode ${enabled ? 'ON' : 'OFF'} for ${server.name}. Will apply CpuShares=${cpuWeight} on next startup.`);
            }

            return true;
        } catch (err: any) {
            logger.error(`RexBoost Turbo error: ${err.message}`);
            return false;
        }
    }

    /**
     * Java Flag Manager: Returns optimized flags for Minecraft servers.
     * Uses Aikar's recommended flags based on allocated memory.
     */
    public static getOptimizedJavaFlags(memoryMb: number): string {
        // Aikar's Flags (Modern/Simplified)
        let flags = '-XX:+UseG1GC -XX:+ParallelRefProcEnabled -XX:MaxGCPauseMillis=200 -XX:+UnlockExperimentalVMOptions -XX:+DisableExplicitGC -XX:+AlwaysPreTouch -XX:G1NewSizePercent=30 -XX:G1MaxNewSizePercent=40 -XX:G1HeapRegionSize=8M -XX:G1ReservePercent=20 -XX:G1HeapWastePercent=5 -XX:G1MixedGCCountTarget=4 -XX:InitiatingHeapOccupancyPercent=15 -XX:G1MixedGCLiveThresholdPercent=90 -XX:G1RSetUpdatingPauseTimePercent=5 -XX:SurvivorRatio=32 -XX:+PerfDisableSharedMem -XX:MaxTenuringThreshold=1';
        
        // Dynamic memory flags
        const xms = Math.floor(memoryMb * 0.9);
        const xmx = memoryMb;
        
        return `-Xms${xms}M -Xmx${xmx}M ${flags}`;
    }

    /**
     * Auto-Cleanup: Purges logs and temporary files to save disk space.
     */
    public static async runCleanup(serverCwd: string) {
        const filesToRemove = ['logs/latest.log', 'proxy.log.0', 'crash-reports', '.tmp'];
        let spaceSaved = 0;

        try {
            for (const fileName of filesToRemove) {
                const fullPath = path.join(serverCwd, fileName);
                if (fs.existsSync(fullPath)) {
                    const stats = fs.statSync(fullPath);
                    if (stats.isDirectory()) {
                        fs.rmSync(fullPath, { recursive: true, force: true });
                    } else {
                        fs.unlinkSync(fullPath);
                    }
                    spaceSaved += stats.size;
                }
            }
            logger.info(`RexBoost Auto-Cleanup: Cleared ${(spaceSaved / (1024 * 1024)).toFixed(2)} MB in ${serverCwd}`);
            return spaceSaved;
        } catch (err: any) {
            logger.error(`RexBoost Cleanup error: ${err.message}`);
            return 0;
        }
    }
}
