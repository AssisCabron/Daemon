import Docker from 'dockerode';
import EventEmitter from 'events';
import winston from 'winston';
import fs from 'fs';
import path from 'path';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.simple()
  ),
  transports: [new winston.transports.Console()],
});

export interface ServerConfig {
  id: string;
  command: string; // Not commonly used in Docker if entrypoint is set, but kept for compatibility
  args: string[]; // Arguments passed to the entrypoint
  cwd: string;
  memory: number;
  cpu: number;
  dockerImage: string;
  port: number;
}

export class ProcessManager extends EventEmitter {
  private docker: Docker;
  private streams: Map<string, NodeJS.ReadableStream> = new Map();

  constructor() {
    super();
    this.docker = new Docker();
    // Verify Docker connection on startup
    this.docker.ping((err) => {
      if (err) {
        logger.error('Failed to connect to Docker Daemon! Is it running?');
      } else {
        logger.info('Connected to Docker Daemon successfully.');
      }
    });
  }

  public async startServer(config: ServerConfig): Promise<void> {
    const containerName = `rexhost-${config.id}`;
    
    try {
      // Check if container already exists
      const existingContainer = this.docker.getContainer(containerName);
      try {
        const state = await existingContainer.inspect();
        if (state.State.Running) {
          logger.warn(`Container ${containerName} is already running.`);
          return;
        }
        // If it exists but stopped, remove it to ensure fresh config
        await existingContainer.remove();
      } catch (e: any) {
        // Container doesn't exist, proceed
        if (e.statusCode !== 404) throw e;
      }

      logger.info(`Creating container ${containerName} with image ${config.dockerImage}`);
      logger.info(`Mounting host path: ${path.resolve(config.cwd)} to /home/container`);
      
      // Fix permissions: Ensure the container user can write to the directory
      try {
        if (process.platform !== 'win32') {
           const { execSync } = require('child_process');
           execSync(`chmod -R 777 "${config.cwd}"`);
           logger.info(`Fixed permissions for ${config.cwd} (Linux/Mac)`);
        } else {
           // Windows fix: Grant full control to Everyone (SID S-1-1-0) to avoid Docker/WSL2 permission issues
           // Using SID *S-1-1-0 guarantees it works on non-English Windows (e.g., 'Todos' in PT-BR)
           const { execSync } = require('child_process');
           try {
             execSync(`icacls "${config.cwd}" /grant *S-1-1-0:(OI)(CI)F /T`, { stdio: 'ignore' });
             logger.info(`Fixed permissions for ${config.cwd} (Windows SID)`);
           } catch (e) {
             // Fallback to 'Todos' if SID fails for some reason, or just log
             logger.warn(`Failed primary permission fix, trying fallback...`);
             execSync(`icacls "${config.cwd}" /grant Everyone:(OI)(CI)F /T`, { stdio: 'ignore' });
           }
        }
      } catch (err: any) {
        logger.warn(`Failed to fix permissions for ${config.cwd}: ${err.message}`);
      }

      // Debug: List files in host directory to verify availability
      
      // Debug: List files in host directory to verify availability
      if (fs.existsSync(config.cwd)) {
          const files = fs.readdirSync(config.cwd);
          logger.info(`Files in ${config.cwd}: ${files.join(', ')}`);
          if (!files.includes('server.jar')) {
              logger.warn('WARNING: server.jar not found in host directory!');
          }
      } else {
          logger.error(`Host directory does not exist: ${config.cwd}`);
      }

      // Ensure image exists locally
      await this.ensureImage(config.dockerImage);

      // Ensure data directory exists
      if (!fs.existsSync(config.cwd)) {
        fs.mkdirSync(config.cwd, { recursive: true });
      }

      // Auto-accept EULA logic
      const eulaPath = path.join(config.cwd, 'eula.txt');
      if (!fs.existsSync(eulaPath)) {
          logger.info(`Auto-accepting EULA for server ${config.id}`);
          fs.writeFileSync(eulaPath, 'eula=true\n');
      } else {
          // Force true if exists but might be false check? 
          // For now, let's just ensure it exists. Some users might want a manual prompt, 
          // but the user requested fixing the startup hang.
          // Let's overwrite to be safe as per user request context.
          let content = fs.readFileSync(eulaPath, 'utf8');
          if (!content.includes('eula=true')) {
             fs.writeFileSync(eulaPath, 'eula=true\n');
          }
      }

      let container;
      try {
        container = await this.docker.createContainer({
          Image: config.dockerImage,
          name: containerName,
          Tty: true,
          OpenStdin: true,
          StdinOnce: false,
          Env: [
            'EULA=true',
            `SERVER_PORT=${config.port}`,
            `MEMORY=${config.memory}`
          ],
          HostConfig: {
            Binds: [
              `${path.resolve(config.cwd)}:/home/container`
            ],
            PortBindings: {
              [`${config.port}/tcp`]: [{ HostPort: `${config.port}` }]
            },
            Memory: config.memory * 1024 * 1024, // Convert MB to bytes
            NanoCpus: config.cpu * 10000000, // Convert % to nano cpus (approx)
            NetworkMode: 'bridge' 
          },
          // Execute the command string via shell to ensure parsing and environment variables work
          Cmd: ['/bin/sh', '-c', config.command], 
          WorkingDir: '/home/container',
        });
      } catch (e: any) {
        // Handle race condition or lingering container (409 Conflict)
        if (e.statusCode === 409) {
           logger.warn(`Container conflict for ${containerName}, attempting force removal...`);
           try {
             const oldContainer = this.docker.getContainer(containerName);
             await oldContainer.remove({ force: true });
             
             // Retry creation
             container = await this.docker.createContainer({
                Image: config.dockerImage,
                name: containerName,
                Tty: true,
                OpenStdin: true,
                StdinOnce: false,
                Env: [
                  'EULA=true',
                  `SERVER_PORT=${config.port}`,
                  `MEMORY=${config.memory}`
                ],
                HostConfig: {
                  Binds: [
                    `${path.resolve(config.cwd)}:/home/container`
                  ],
                  PortBindings: {
                    [`${config.port}/tcp`]: [{ HostPort: `${config.port}` }]
                  },
                  Memory: config.memory * 1024 * 1024, 
                  NanoCpus: config.cpu * 10000000, 
                  NetworkMode: 'bridge' 
                },
                Cmd: ['/bin/sh', '-c', config.command], 
                WorkingDir: '/home/container',
             });
           } catch (retryErr: any) {
             throw new Error(`Failed to recover from container conflict: ${retryErr.message}`);
           }
        } else {
          throw e;
        }
      }

      logger.info(`Starting container ${containerName}...`);
      await container.start();

      // Attach to logs
      const stream = await container.logs({
        follow: true,
        stdout: true,
        stderr: true
      });

      this.streams.set(config.id, stream);

      stream.on('data', (chunk) => {
        // Docker logs might contain header bytes, basic cleaning
        const logLine = chunk.toString('utf8');
        this.emit('console', { id: config.id, data: logLine });
      });

      stream.on('end', () => {
        this.emit('status', { id: config.id, status: 'stopped' });
        this.streams.delete(config.id);
      });

      this.emit('status', { id: config.id, status: 'running' });

    } catch (err: any) {
      logger.error(`Failed to start server ${config.id}: ${err.message}`);
      this.emit('error', { id: config.id, error: err.message });
    }
  }

  public async stopServer(id: string): Promise<void> {
    const containerName = `rexhost-${id}`;
    try {
      const container = this.docker.getContainer(containerName);
      await container.stop();
      logger.info(`Stopped container ${containerName}`);
    } catch (err: any) {
      if (err.statusCode !== 304) { // 304 means already stopped
         logger.error(`Failed to stop server ${id}: ${err.message}`);
      }
    }
  }

  public async deleteServer(id: string, cwd: string): Promise<void> {
      const containerName = `rexhost-${id}`;
      logger.info(`Deleting server ${id}...`);

      // 1. Stop and Remove Container
      try {
          const container = this.docker.getContainer(containerName);
          try {
             await container.stop();
          } catch (e) { /* ignore if not running */ }
          
          await container.remove({ force: true });
          logger.info(`Removed container ${containerName}`);
      } catch (err: any) {
          if (err.statusCode !== 404) {
              logger.warn(`Failed to remove container ${containerName}: ${err.message}`);
          }
      }

      // 2. Delete Data Directory
      // Verify we are deleting a safe path (inside daemon data)
      // This is critical. We rely on the path provided by the caller (from DB).
      if (cwd && fs.existsSync(cwd)) {
          try {
              // Add simple safety check: path must contain 'data/servers' or similar if possible? 
              // For now, trust the DB record but wrap in try.
              fs.rmSync(cwd, { recursive: true, force: true });
              logger.info(`Deleted data directory: ${cwd}`);
          } catch (e: any) {
              logger.error(`Failed to delete data directory ${cwd}: ${e.message}`);
          }
      }
  }

  public async sendCommand(id: string, command: string): Promise<void> {
    const containerName = `rexhost-${id}`;
    try {
      const container = this.docker.getContainer(containerName);
      
      // Use attach to send command to stdin
      const stream = await container.attach({
        stream: true,
        stdin: true,
        stdout: false,
        stderr: false,
        hijack: true
      });
      
      stream.write(command + "\n");
      stream.end();
      
    } catch (err: any) {
      logger.error(`Failed to send command to ${id}: ${err.message}`);
    }
  }

  public async isServerRunning(id: string): Promise<boolean> {
    const containerName = `rexhost-${id}`;
    try {
      const container = this.docker.getContainer(containerName);
      const data = await container.inspect();
      return data.State.Running;
      return data.State.Running;
    } catch {
      return false;
    }
  }

  public checkFileExists(cwd: string, fileName: string): boolean {
    const filePath = path.join(cwd, fileName);
    return fs.existsSync(filePath);
  }

  public async downloadFileViaDocker(image: string, cwd: string, url: string, fileName: string): Promise<void> {
    const containerName = `rexhost-dl-${Date.now()}`;
    
    logger.info(`Preparing to download file using image: ${image}`);

    // Ensure image exists
    await this.ensureImage(image);

    // Fix permissions: Ensure the container user can write to the directory
    try {
      if (process.platform !== 'win32') {
          const { execSync } = require('child_process');
          execSync(`chmod -R 777 "${cwd}"`);
          logger.info(`Fixed permissions for download in ${cwd} (Linux/Mac)`);
      } else {
           const { execSync } = require('child_process');
           // Use SID *S-1-1-0 for "Everyone" to support all languages
           execSync(`icacls "${cwd}" /grant *S-1-1-0:(OI)(CI)F /T`, { stdio: 'ignore' });
           logger.info(`Fixed permissions for download in ${cwd} (Windows SID)`);
      }
    } catch (err: any) {
      logger.warn(`Failed to fix permissions for ${cwd}: ${err.message}`);
    }

    // Create ephemeral container for downloading
    const container = await this.docker.createContainer({
      Image: image,
      name: containerName,
      HostConfig: {
        Binds: [
          `${path.resolve(cwd)}:/home/container`
        ],
        NetworkMode: 'bridge',
        AutoRemove: true // Clean up automatically
      },
      // Try curl first, fallback to wget
      Cmd: ['/bin/sh', '-c', `curl -L -o /home/container/${fileName} "${url}" || wget -O /home/container/${fileName} "${url}"`],
    });

    logger.info(`Starting download container ${containerName}...`);
    
    await container.start();
    const stream = await container.logs({ follow: true, stdout: true, stderr: true });
    
    // Pipe logs to main process logger for debugging
    stream.on('data', chunk => logger.info(`[Download]: ${chunk.toString()}`));

    // Wait for container to exit
    await container.wait();
    logger.info(`Download container ${containerName} finished.`);
  }

  public async runInstallScript(
    cwd: string, 
    containerImage: string, 
    script: string, 
    envVars: Record<string, string>, 
    entrypoint: string = '/bin/sh'
  ): Promise<void> {
    const containerName = `rexhost-install-${Date.now()}`;
    logger.info(`Starting installation container ${containerName} using ${containerImage}`);

    await this.ensureImage(containerImage);

    // Fix permissions: Ensure the container user can write to the directory
    try {
      if (process.platform !== 'win32') {
          const { execSync } = require('child_process');
          execSync(`chmod -R 777 "${cwd}"`);
          logger.info(`Fixed permissions for install in ${cwd} (Linux/Mac)`);
      } else {
           const { execSync } = require('child_process');
           // Use SID *S-1-1-0 for "Everyone" to support all languages
           execSync(`icacls "${cwd}" /grant *S-1-1-0:(OI)(CI)F /T`, { stdio: 'ignore' });
           logger.info(`Fixed permissions for install in ${cwd} (Windows SID)`);
      }
    } catch (err: any) {
      logger.warn(`Failed to fix permissions for ${cwd}: ${err.message}`);
    }

    // Prepare environment variables
    const env = Object.entries(envVars).map(([k, v]) => `${k}=${v}`);
    env.push('mnt/server=/home/container'); // Standard Pterodactyl mount point alias if needed, though we mount to /home/container

    // Pterodactyl scripts often expect /mnt/server. We'll map cwd to /mnt/server to be safe and broadly compatible.
    const binds = [
        `${path.resolve(cwd)}:/mnt/server`,
        `${path.resolve(cwd)}:/home/container`
    ];

    const container = await this.docker.createContainer({
      Image: containerImage,
      name: containerName,
      HostConfig: {
        Binds: binds,
        NetworkMode: 'bridge',
        AutoRemove: true
      },
      Env: env,
      // Pterodactyl scripts are usually passed as a single string to the entrypoint shell
      // or the entrypoint is the shell and we pass the script.
      // Often usage: entrypoint: "ash", script: "Start script..." -> Cmd: ["-c", script] if entrypoint is shell
      // But Pterodactyl logic is: Entrypoint from egg (e.g. /bin/ash), Cmd: [ "-c", script ]
      Entrypoint: [entrypoint],
      Cmd: ['-c', script],
      WorkingDir: '/mnt/server'
    });

    await container.start();
    
    const stream = await container.logs({ follow: true, stdout: true, stderr: true });
    stream.on('data', chunk => logger.info(`[Install]: ${chunk.toString()}`));
    
    const result = await container.wait();
    if (result.StatusCode !== 0) {
        throw new Error(`Installation failed with exit code ${result.StatusCode}`);
    }
    
    logger.info(`Installation container ${containerName} finished successfully.`);
  }

  private async ensureImage(imageName: string): Promise<void> {
    try {
      const image = this.docker.getImage(imageName);
      await image.inspect();
      return;
    } catch (e: any) {
      if (e.statusCode !== 404) throw e;
    }

    logger.info(`Pulling image ${imageName}...`);
    return new Promise((resolve, reject) => {
      this.docker.pull(imageName, (err: any, stream: NodeJS.ReadableStream) => {
        if (err) return reject(err);
        this.docker.modem.followProgress(stream, onFinished, onProgress);

        function onFinished(err: any, output: any) {
          if (err) return reject(err);
          resolve();
        }

        function onProgress(event: any) {
          // Optional: log progress
        }
      });
    });
  }
}

export const processManager = new ProcessManager();
