import { prisma } from '../lib/prisma';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

export class SecurityService {
  /**
   * Logs a user or system action for auditing purposes.
   */
  static async log(params: {
    action: string;
    entity: string;
    entityId?: string;
    userId?: string;
    ip?: string;
    metadata?: any;
  }) {
    try {
      const log = await prisma.auditLog.create({
        data: {
          action: params.action,
          entity: params.entity,
          entityId: params.entityId,
          userId: params.userId,
          ip: params.ip,
          metadata: params.metadata ? JSON.stringify(params.metadata) : null,
        },
      });
      return log;
    } catch (err: any) {
      logger.error(`Failed to create audit log: ${err.message}`, { action: params.action });
    }
  }

  /**
   * Triggers a security alert/event.
   */
  static async alert(params: {
    type: string;
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    description: string;
    metadata?: any;
  }) {
    try {
      const alert = await prisma.securityEvent.create({
        data: {
          type: params.type,
          severity: params.severity,
          description: params.description,
          metadata: params.metadata ? JSON.stringify(params.metadata) : null,
        },
      });
      
      logger.warn(`SECURITY ALERT [${params.severity}]: ${params.description}`, { type: params.type });
      
      // Future: Trigger notifications (Email, Discord, Push)
      return alert;
    } catch (err: any) {
      logger.error(`Failed to create security alert: ${err.message}`, { type: params.type });
    }
  }
}
