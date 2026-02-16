import winston from 'winston';
import os from 'os';
import { prisma } from '../lib/prisma';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/network_guardian.log' }),
    new winston.transports.Console()
  ],
});

interface RateLimitEntry {
    count: number;
    lastSeen: number;
    blockedUntil?: number;
}

export class NetworkGuardian {
    private static ipLimits: Map<string, RateLimitEntry> = new Map();
    private static readonly MAX_REQUESTS = 100; // per minute
    private static readonly BLOCK_DURATION = 15 * 60 * 1000; // 15 minutes
    
    // Stats tracking
    private static lastNetInfo: any = null;
    private static lastCheckTime: number = Date.now();
    private static currentPps: number = 0;
    private static currentThroughput: number = 0; // Bytes/sec

    private static geoCache: Map<string, { country: string; expires: number }> = new Map();

    /**
     * Middleware-like check for rate limiting
     */
    public static checkRateLimit(ip: string): { allowed: boolean; remaining?: number } {
        const now = Date.now();
        const entry = this.ipLimits.get(ip) || { count: 0, lastSeen: now };

        // Check if currently blocked
        if (entry.blockedUntil && entry.blockedUntil > now) {
            return { allowed: false };
        }

        // Reset count every minute
        if (now - entry.lastSeen > 60000) {
            entry.count = 0;
            entry.lastSeen = now;
        }

        entry.count++;
        
        if (entry.count > this.MAX_REQUESTS) {
            entry.blockedUntil = now + this.BLOCK_DURATION;
            this.ipLimits.set(ip, entry);
            logger.warn(`NetworkGuardian: IP ${ip} blocked for exceeding rate limit (${entry.count} req/min).`);
            
            // Log security event (failing silently if prisma is not ready)
            try {
                (prisma as any).securityEvent?.create({
                    data: {
                        type: 'network_abuse',
                        severity: 'high',
                        sourceIp: ip,
                        message: `IP blocked for rate limit abuse: ${entry.count} requests in 1 minute.`,
                        metadata: { duration: this.BLOCK_DURATION }
                    }
                }).catch(() => {});
            } catch {}

            return { allowed: false };
        }

        this.ipLimits.set(ip, entry);
        return { allowed: true, remaining: this.MAX_REQUESTS - entry.count };
    }

    /**
     * Placeholder for Geo-IP blocking with lightweight API fallback + Cache.
     */
    public static async isCountryBlocked(ip: string): Promise<boolean> {
        const now = Date.now();
        const cached = this.geoCache.get(ip);
        
        if (cached && cached.expires > now) {
            // Logic: check against a blocked list (e.g. from settings)
            return false; 
        }

        try {
            // In a real scenario, use a local DB. This is a fallback for demonstration.
            const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,countryCode`);
            const data = await response.json() as any;
            
            if (data.status === 'success') {
                this.geoCache.set(ip, { country: data.countryCode, expires: now + 86400000 }); // 24h cache
            }
        } catch (err) {
            logger.error(`NetworkGuardian GeoIP Error: ${err}`);
        }

        return false; 
    }

    /**
     * Monitor network interfaces for Packets Per Second (PPS)
     */
    public static async monitorMetrics() {
        // Note: On Windows, retrieving precise PPS per interface via Node.js 
        // usually requires native bindings or WMI/Performance Counters.
        // We'll use a simplified implementation based on throughput bytes for now.
        
        const now = Date.now();
        const delta = (now - this.lastCheckTime) / 1000;
        
        // This is a placeholder for real PPS calculation.
        // On Windows, one might use `netstat -e` or similar via child_process.
        
        // Let's assume an average packet size of 512 bytes for estimate
        // currentPps = (Bytes Delta / average_packet_size) / delta
        
        this.lastCheckTime = now;
    }

    public static getNetworkStats() {
        return {
            pps: Math.round(this.currentPps),
            throughput: (this.currentThroughput / (1024 * 1024)).toFixed(2), // MB/s
            activeBlocks: Array.from(this.ipLimits.values()).filter(e => e.blockedUntil && e.blockedUntil > Date.now()).length
        };
    }
}
