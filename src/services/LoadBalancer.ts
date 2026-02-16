import { prisma } from '../lib/prisma';
import axios from 'axios';
import winston from 'winston';
import os from 'os';
import { OSUtils } from 'node-os-utils';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [new winston.transports.Console()],
});

const osu = new OSUtils();

export type HealthStatus = 'healthy' | 'attention' | 'critical' | 'offline';

export interface NodeStats {
  nodeId: string;
  nodeName: string;
  cpu: string;
  memory: {
    total: string;
    used: string;
    percentage: string;
  };
  status: 'online' | 'offline';
  healthStatus: HealthStatus;
  score: number;
}

export class LoadBalancer {
  private static readonly HARD_LIMIT_THRESHOLD = 5; // Block allocation if score is below 5% (critically low)

  /**
   * Helper to get local stats (Duplicate of index.ts logic for self-contained service)
   */
  private static async getLocalStats() {
    try {
      const cpuUsageResult = await osu.cpu.usage();
      // node-os-utils might return a number directly or an object with data
      const cpuUsage = typeof cpuUsageResult === 'number' ? cpuUsageResult : (cpuUsageResult as any).data; // Extract 'data' if it's an object
      
      const totalMemBytes = os.totalmem();
      const freeMemBytes = os.freemem();
      const usedMemBytes = totalMemBytes - freeMemBytes;
      const memPercentage = (usedMemBytes / totalMemBytes) * 100;
      
      const stats = {
        cpu: cpuUsage, // cpuUsage is now guaranteed to be a number
        memory: {
          total: totalMemBytes,
          used: usedMemBytes,
          percentage: memPercentage
        }
      };

      const displayCpu = stats.cpu.toFixed(1); // Now cpu is always a number
      logger.info(`[LoadBalancer] Local Stats: CPU=${displayCpu}%, RAM=${(usedMemBytes/(1024**3)).toFixed(1)}GB/${(totalMemBytes/(1024**3)).toFixed(1)}GB (${memPercentage.toFixed(1)}%)`);
      return stats;
    } catch (err: any) {
      logger.error(`[LoadBalancer] Failed to get local stats: ${err.message}`);
      return null;
    }
  }

  private static calculateHealth(score: number): HealthStatus {
    if (score > 60) return 'healthy';
    if (score > 20) return 'attention';
    return 'critical';
  }

  private static checkIfLocal(ip: string): boolean {
    if (ip === '127.0.0.1' || ip === 'localhost' || ip === '::1' || ip === '0.0.0.0') return true;
    
    // Check against all local network interfaces
    const interfaces = os.networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name] || []) {
        if (iface.address === ip) return true;
      }
    }
    return false;
  }

  /**
   * Fetches health and resource stats for all registered nodes.
   */
  public static async getNodesHealth(): Promise<NodeStats[]> {
    const nodes = await prisma.node.findMany();
    
    const statsPromises = nodes.map(async (node) => {
      const isLocal = this.checkIfLocal(node.ip);

      try {
        let stats: any;
        if (isLocal) {
          const local = await this.getLocalStats();
          if (!local) throw new Error('Failed to get local stats');
          stats = {
            cpu: local.cpu.toString(),
            memory: {
              total: (local.memory.total / (1024**3)).toFixed(1),
              used: (local.memory.used / (1024**3)).toFixed(1),
              percentage: local.memory.percentage.toFixed(1)
            }
          };
        } else {
          const response = await axios.get(`http://${node.ip}:${node.port}/api/stats`, { timeout: 1500 });
          stats = response.data;
        }

        const freeRam = 100 - parseFloat(stats.memory.percentage);
        const freeCpu = 100 - parseFloat(stats.cpu);
        const score = (freeRam * 0.7) + (freeCpu * 0.3);

        return {
          nodeId: node.id,
          nodeName: node.name,
          ...stats,
          status: 'online' as const,
          healthStatus: this.calculateHealth(score),
          score: Math.round(score)
        };
      } catch (err) {
        return {
          nodeId: node.id,
          nodeName: node.name,
          cpu: '0',
          memory: { total: '0', used: '0', percentage: '100' },
          status: 'offline' as const,
          healthStatus: 'offline' as const,
          score: 0
        };
      }
    });

    return Promise.all(statsPromises);
  }

  /**
   * Fail-Safe & Auto-Distribution Logic
   * Finds the best node based on free resources.
   */
  public static async getOptimalNode(): Promise<string | null> {
    const nodesHealth = await this.getNodesHealth();
    
    // Filter out offline nodes (Fail Safe)
    const onlineNodes = nodesHealth.filter(n => n.status === 'online');

    if (onlineNodes.length === 0) {
      logger.error('LoadBalancer: No online nodes available for allocation!');
      return null;
    }

    // Sort by score descending (highest score = most free)
    const sortedNodes = [...onlineNodes].sort((a, b) => b.score - a.score);
    const bestNode = sortedNodes[0];

    // HARD THROTTLING: Even if it's the only node, block if resources are too low
    if (bestNode.score < this.HARD_LIMIT_THRESHOLD) {
        logger.warn(`LoadBalancer: Blocked allocation on ${bestNode.nodeName}. Score ${bestNode.score} is below hard limit of ${this.HARD_LIMIT_THRESHOLD}`);
        return null;
    }

    logger.info(`LoadBalancer: Selected node ${bestNode.nodeId} with score ${bestNode.score}`);
    return bestNode.nodeId;
  }
}
