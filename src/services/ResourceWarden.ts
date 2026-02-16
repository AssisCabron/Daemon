import { prisma } from '../lib/prisma';
import { processManager } from './ProcessManager';
import { SecurityService } from './SecurityService';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [new winston.transports.Console()],
});

export class ResourceWarden {
  private interval: NodeJS.Timeout | null = null;
  private abuseStreaks: Map<string, number> = new Map(); // serverId -> consecutive high CPU checks
  private CHECK_INTERVAL_MS = 30000; // 30 seconds
  private CPU_ABUSE_THRESHOLD = 95; // %
  private STREAK_THRESHOLD = 3; // 3 checks (1.5 mins) triggers alert
  private LOCK_THRESHOLD = 6; // 6 checks (3 mins) triggers mitigation

  public start() {
    if (this.interval) return;
    logger.info('RexShield Resource Warden started monitoring...');
    this.interval = setInterval(() => this.checkResources(), this.CHECK_INTERVAL_MS);
  }

  public stop() {
    if (this.interval) {
      clearInterval(this.interval);
      this.interval = null;
    }
  }

  private async checkResources() {
    try {
      const runningServers = await prisma.server.findMany({
        where: { status: 'running' }
      });

      for (const server of runningServers) {
        const stats = await processManager.getContainerStats(server.id);
        if (!stats) continue;

        const cpuPercent = this.calculateCPUPercent(stats);
        const ramPercent = this.calculateRAMPercent(stats);

        // Anomaly Detection: High CPU
        if (cpuPercent > this.CPU_ABUSE_THRESHOLD) {
          const streak = (this.abuseStreaks.get(server.id) || 0) + 1;
          this.abuseStreaks.set(server.id, streak);

          if (streak === this.STREAK_THRESHOLD) {
            await SecurityService.alert({
              type: 'resource_abuse',
              severity: 'HIGH',
              description: `Server ${server.id} (${server.name}) is consuming ${cpuPercent.toFixed(1)}% CPU for ${streak * 30} seconds. Potential cryptominer or crash loop.`,
              metadata: { cpu: cpuPercent, ram: ramPercent, streak }
            });
            
            // Log to server console to warn user
            processManager.emit('console', { 
              id: server.id, 
              data: `\r\n[RexShield] ALERT: High resource consumption detected! (${cpuPercent.toFixed(1)}% CPU)\r\n` 
            });
          }

          if (streak >= this.LOCK_THRESHOLD) {
            // Automated Mitigation: Abuse Lock (Throttle to 10% of allowed CPU)
            await SecurityService.alert({
              type: 'abuse_mitigation',
              severity: 'CRITICAL',
              description: `Applying automatic Resource Lock to Server ${server.id} due to persistent CPU abuse.`,
              metadata: { cpu: cpuPercent, streak }
            });
            
            // Throttle to a fraction of its original limit
            await processManager.updateContainerResources(server.id, { 
              cpu: Math.max(10, Math.floor(server.cpu * 0.1)) 
            });

            processManager.emit('console', { 
              id: server.id, 
              data: `\r\n[RexShield] PROTECTION: Resource Lock applied. CPU usage throttled.\r\n` 
            });
          }
        } else {
          // Reset streak if usage drops
          if (this.abuseStreaks.has(server.id)) {
              if (this.abuseStreaks.get(server.id)! >= this.LOCK_THRESHOLD) {
                  // Restore resources if it was locked
                  await processManager.updateContainerResources(server.id, { cpu: server.cpu });
                  logger.info(`Restored resources for server ${server.id} (usage normalized)`);
                  processManager.emit('console', { 
                    id: server.id, 
                    data: `\r\n[RexShield] Resource usage normalized. Resource Lock removed.\r\n` 
                  });
              }
              this.abuseStreaks.delete(server.id);
          }
        }
      }
    } catch (err: any) {
      logger.error(`Warden check failed: ${err.message}`);
    }
  }

  private calculateCPUPercent(stats: any): number {
    // Docker stats calculation: (cpu_delta / system_delta) * online_cpus * 100
    const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
    const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
    const onlineCpus = stats.cpu_stats.online_cpus || 1;

    if (systemDelta > 0 && cpuDelta > 0) {
      return (cpuDelta / systemDelta) * onlineCpus * 100;
    }
    return 0;
  }

  private calculateRAMPercent(stats: any): number {
    const usedMemory = stats.memory_stats.usage - (stats.memory_stats.stats?.cache || 0);
    const availableMemory = stats.memory_stats.limit;
    return (usedMemory / availableMemory) * 100;
  }
}

export const resourceWarden = new ResourceWarden();
