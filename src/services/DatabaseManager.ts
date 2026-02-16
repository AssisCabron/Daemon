import Docker from 'dockerode';
import winston from 'winston';
import { prisma } from '../lib/prisma';
import crypto from 'crypto';
import mysql from 'mysql2/promise';
import Net from 'net';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [new winston.transports.Console()],
});

export class DatabaseManager {
  private docker: Docker;

  constructor() {
    this.docker = new Docker();
  }

  private generatePassword(): string {
    return crypto.randomBytes(12).toString('hex');
  }

  private async findFreePort(): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = Net.createServer();
      server.unref();
      server.on('error', reject);
      server.listen(0, () => {
        const port = (server.address() as Net.AddressInfo).port;
        server.close(() => resolve(port));
      });
    });
  }

  public async createDatabase(serverId: string): Promise<any> {
    const networkName = `rex-db-net-${serverId}`;
    const dbContainerName = `rex-db-${serverId}`;
    const dbUser = `rex_user_${serverId.substring(0, 8)}`;
    const dbPass = this.generatePassword();
    const dbName = `rex_db_${serverId.substring(0, 8)}`;

    try {
      // 0. Ensure MySQL image exists
      await this.ensureImage('mysql:8.0');

      // 1. Create dedicated network if not exists
      try {
        await this.docker.getNetwork(networkName).inspect();
        logger.info(`Network ${networkName} already exists.`);
      } catch (e: any) {
        if (e.statusCode === 404) {
          logger.info(`Creating network ${networkName}...`);
          await this.docker.createNetwork({
            Name: networkName,
            Driver: 'bridge'
          });
        } else {
          throw e;
        }
      }

      // 2. Remove existing MySQL container if it exists (for fresh config)
      try {
        const existingContainer = this.docker.getContainer(dbContainerName);
        await existingContainer.remove({ force: true });
        logger.info(`Removed existing DB container ${dbContainerName} for fresh start.`);
      } catch (e) {}

      // NEW: Find a free port for host binding (Crucial for Windows stability)
      const hostPort = await this.findFreePort();
      logger.info(`Binding MySQL container to host port ${hostPort}`);

      // 3. Create MySQL container
      logger.info(`Creating MySQL container ${dbContainerName}...`);
      const container = await this.docker.createContainer({
        Image: 'mysql:8.0',
        name: dbContainerName,
        Env: [
          `MYSQL_ROOT_PASSWORD=${this.generatePassword()}`,
          `MYSQL_DATABASE=${dbName}`,
          `MYSQL_USER=${dbUser}`,
          `MYSQL_PASSWORD=${dbPass}`
        ],
        HostConfig: {
          NetworkMode: networkName,
          RestartPolicy: { Name: 'always' },
          PortBindings: {
            '3306/tcp': [{ HostPort: hostPort.toString(), HostIp: '127.0.0.1' }]
          }
        }
      });

      await container.start();
      logger.info(`MySQL container ${dbContainerName} started.`);

      // 3. Wait for MySQL to be ready (Critical for stability)
      logger.info(`Waiting for MySQL instance ${dbContainerName} to be ready...`);
      const isReady = await this.waitForMySQL(hostPort, dbUser, dbPass, dbName);
      if (!isReady) {
        throw new Error('MySQL instance failed to become ready within timeout.');
      }

      // 4. Save to DB
      const dbInfo = await prisma.database.create({
        data: {
          name: dbName,
          username: dbUser,
          password: dbPass,
          port: hostPort,
          serverId
        }
      });
      return dbInfo;
    } catch (err: any) {
      logger.error(`Failed to create database for ${serverId}: ${err.message}`);
      throw err;
    }
  }

  private async waitForMySQL(port: number, user: string, pass: string, db: string, timeoutMs: number = 60000): Promise<boolean> {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const connection = await mysql.createConnection({
          host: '127.0.0.1',
          port,
          user,
          password: pass,
          database: db,
          connectTimeout: 2000
        });
        await connection.end();
        logger.info(`MySQL on port ${port} is ready.`);
        return true;
      } catch (err: any) {
        // Expected during startup: ECONNREFUSED or "Server closed connection" or "Access denied" (if still seeding)
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
    return false;
  }

  public async getDatabase(serverId: string) {
    return await prisma.database.findUnique({
      where: { serverId }
    });
  }

  public async executeQuery(serverId: string, sql: string, retries: number = 3): Promise<any> {
    const db = await this.getDatabase(serverId);
    if (!db) throw new Error('Database not found for this server');

    for (let attempt = 1; attempt <= retries; attempt++) {
      try {
        logger.info(`Attempt ${attempt}: Executing query on localhost:${db.port} for server ${serverId}`);
        const connection = await mysql.createConnection({
          host: '127.0.0.1',
          port: db.port,
          user: db.username,
          password: db.password,
          database: db.name,
          connectTimeout: 5000,
          multipleStatements: true
        });

        let [rows, fields] = await connection.query(sql);
        await connection.end();

        // Normalize multi-statement results
        // If multipleStatements is true, fields can be an array of field arrays
        if (Array.isArray(fields) && fields.length > 0 && Array.isArray(fields[0])) {
           // Pick the last result set that actually contains rows/fields (likely the SELECT)
           // Or if none, the last one.
           let bestIndex = fields.length - 1;
           for (let i = fields.length - 1; i >= 0; i--) {
             if (fields[i] && (fields[i] as any).length > 0) {
                bestIndex = i;
                break;
             }
           }
           rows = (rows as any[])[bestIndex];
           fields = (fields as any[])[bestIndex];
        }

        return { rows, fields: fields || [] };
      } catch (err: any) {
        // Skip retries for syntax errors (ER_PARSE_ERROR)
        if (err.code === 'ER_PARSE_ERROR') {
          logger.error(`Syntax error in query for ${serverId}: ${err.message}`);
          throw err;
        }

        if (attempt === retries) {
          logger.error(`Query failed after ${retries} attempts for ${serverId}: ${err.message}`);
          throw err;
        }
        // If connection lost or refused, wait a bit and retry
        logger.warn(`Query attempt ${attempt} failed: ${err.message}. Retrying in 2s...`);
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }

  public async getStatus(serverId: string): Promise<'online' | 'offline' | 'booting'> {
    const db = await this.getDatabase(serverId);
    if (!db) return 'offline';

    const dbContainerName = `rex-db-${serverId}`;
    try {
      const container = this.docker.getContainer(dbContainerName);
      const inspect = await container.inspect();
      
      if (!inspect.State.Running) return 'offline';

      // Check if MySQL is actually accepting connections (heartbeat)
      const isReady = await this.checkConnection(db);
      return isReady ? 'online' : 'booting';
    } catch (e) {
      return 'offline';
    }
  }

  private async checkConnection(db: any): Promise<boolean> {
    try {
      const connection = await mysql.createConnection({
        host: '127.0.0.1',
        port: db.port,
        user: db.username,
        password: db.password,
        database: db.name,
        connectTimeout: 2000
      });
      await connection.end();
      return true;
    } catch (err) {
      return false;
    }
  }

  public async deleteDatabase(serverId: string): Promise<void> {
    const networkName = `rex-db-net-${serverId}`;
    const dbContainerName = `rex-db-${serverId}`;

    try {
      // 1. Remove Container
      try {
        const container = this.docker.getContainer(dbContainerName);
        await container.stop();
        await container.remove();
        logger.info(`Removed DB container ${dbContainerName}`);
      } catch (e) {}

      // 2. Remove Network
      try {
        const network = await this.docker.getNetwork(networkName);
        await network.remove();
        logger.info(`Removed DB network ${networkName}`);
      } catch (e) {}

      // 3. Remove from Prisma
      await prisma.database.delete({
        where: { serverId }
      });
    } catch (err: any) {
      logger.warn(`Cleanup for DB ${serverId} partial: ${err.message}`);
    }
  }

  private async ensureImage(imageName: string): Promise<void> {
    try {
      const image = this.docker.getImage(imageName);
      await image.inspect();
      return;
    } catch (e: any) {
      if (e.statusCode !== 404) throw e;
    }

    logger.info(`Pulling missing database image: ${imageName}...`);
    return new Promise((resolve, reject) => {
      this.docker.pull(imageName, (err: any, stream: NodeJS.ReadableStream) => {
        if (err) return reject(err);
        this.docker.modem.followProgress(stream, (err: any) => {
          if (err) return reject(err);
          resolve();
        });
      });
    });
  }
}

export const databaseManager = new DatabaseManager();
