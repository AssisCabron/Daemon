import { prisma } from '../lib/prisma';
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [new winston.transports.Console()],
});

export class SettingsService {
  /**
   * Fetches a single setting by key.
   */
  public static async get(key: string, defaultValue: string = ''): Promise<string> {
    try {
      const setting = await prisma.setting.findUnique({ where: { key } });
      return setting ? setting.value : defaultValue;
    } catch (err: any) {
      logger.error(`Failed to fetch setting ${key}: ${err.message}`);
      return defaultValue;
    }
  }

  /**
   * Fetches all settings as a key-value object.
   */
  public static async getAll(): Promise<Record<string, string>> {
    try {
      const settings = await prisma.setting.findMany();
      return settings.reduce((acc, curr) => {
        acc[curr.key] = curr.value;
        return acc;
      }, {} as Record<string, string>);
    } catch (err: any) {
      logger.error(`Failed to fetch all settings: ${err.message}`);
      return {};
    }
  }

  /**
   * Updates or creates a setting.
   */
  public static async set(key: string, value: string): Promise<void> {
    try {
      await prisma.setting.upsert({
        where: { key },
        update: { value },
        create: { key, value }
      });
      logger.info(`Setting updated: ${key} = ${value}`);
    } catch (err: any) {
      logger.error(`Failed to update setting ${key}: ${err.message}`);
      throw err;
    }
  }

  /**
   * Batch updates settings.
   */
  public static async setMany(settings: Record<string, string>): Promise<void> {
    try {
      const operations = Object.entries(settings).map(([key, value]) => 
        prisma.setting.upsert({
          where: { key },
          update: { value },
          create: { key, value }
        })
      );
      await prisma.$transaction(operations);
      logger.info(`Batch settings update successful for ${Object.keys(settings).length} keys.`);
    } catch (err: any) {
      logger.error(`Failed batch setting update: ${err.message}`);
      throw err;
    }
  }
}
