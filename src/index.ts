import 'dotenv/config';
import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import winston from 'winston';
import axios from 'axios';
import { processManager } from './services/ProcessManager';
import { autoUpdater } from './services/AutoUpdater';
import multer from 'multer';
import { SecurityService } from './services/SecurityService';
import { resourceWarden } from './services/ResourceWarden';
import { SettingsService } from './services/SettingsService';
import { LoadBalancer } from './services/LoadBalancer';
import { NetworkGuardian } from './services/NetworkGuardian';
import { RexBoost } from './services/RexBoost';
import { databaseManager } from './services/DatabaseManager';

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

import { SetupService } from './services/SetupService';

const app = express();
const httpServer = createServer(app);

app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-user-id'],
  credentials: true
}));
app.use(express.json());

const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization", "x-user-id"],
    credentials: true
  }
});
// --- RexShield: Network Guardian Rate Limiting ---
app.use((req, res, next) => {
    // Skip if it's the internal loopback or health checks from master
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const isInternal = ip === '127.0.0.1' || ip === '::1';
    
    if (!isInternal) {
        const { allowed } = NetworkGuardian.checkRateLimit(ip);
        if (!allowed) {
            return res.status(429).json({ error: 'RexShield: Too many requests. Source IP has been temporarily locked.' });
        }
    }
    next();
});

app.get('/api/setup/status', (req, res) => {
  res.json({ isSetupComplete: SetupService.isSetupComplete() });
});

app.post('/api/setup/complete', async (req, res) => {
  try {
    const admin = await SetupService.completeSetup(req.body);
    res.json({ message: 'Setup completed successfully', admin: { id: admin.id, username: admin.username } });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

// Middleware to block API if setup not complete (except the setup endpoints)
// Middleware to block API if setup not complete (except the setup endpoints and sync)
app.use((req, res, next) => {
  // Allow /api/setup/* and /api/servers/sync (for node adoption)
  if (!SetupService.isSetupComplete() && !req.path.startsWith('/api/setup') && !req.path.startsWith('/api/servers/sync')) {
    return res.status(403).json({ error: 'System setup required' });
  }
  next();
});

import os from 'os';
import path from 'path';
import fs from 'fs';
import { OSUtils } from 'node-os-utils';
import { prisma } from './lib/prisma';
// Removed duplicate autoUpdater import

const SERVERS_DIR = process.platform === 'win32' 
  ? path.join(process.cwd(), 'data', 'servers')
  : '/var/lib/rexhost/servers';

// Ensure base servers directory exists
if (!fs.existsSync(SERVERS_DIR)) {
  fs.mkdirSync(SERVERS_DIR, { recursive: true });
}

const osu = new OSUtils();

// ... (previous imports and setup)

// API Endpoints
app.get('/api/stats', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;
    const requester = userId ? await prisma.user.findUnique({ where: { id: userId } }) : null;

    // Get all registered nodes to aggregate their stats via LoadBalancer
    const allNodeStats = await LoadBalancer.getNodesHealth();
    
    // If no nodes defined in DB yet, falling back to local only (handled by LoadBalancer mostly, but safe to check)
    if (allNodeStats.length === 0) {
        // This is a safety catch if the DB has zero nodes
        const cpuRes = await osu.cpu.usage();
        const cpuUsage = cpuRes;
        const totalMemBytes = os.totalmem();
        const freeMemBytes = os.freemem();
        const usedMemBytes = totalMemBytes - freeMemBytes;
        
        allNodeStats.push({ 
            nodeId: 'local', 
            nodeName: 'Local Node', 
            cpu: cpuUsage.toString(),
            memory: {
                total: (totalMemBytes / (1024 ** 3)).toFixed(1),
                used: (usedMemBytes / (1024 ** 3)).toFixed(1),
                percentage: ((usedMemBytes / totalMemBytes) * 100).toFixed(1)
            },
            status: 'online',
            healthStatus: 'healthy',
            score: 100
        });
    }

    // Aggregate totals
    const onlineNodes = allNodeStats.filter(n => n.status === 'online');
    const totalCpu = onlineNodes.reduce((acc, n) => acc + parseFloat(n.cpu), 0);
    const totalMemUsed = onlineNodes.reduce((acc, n) => acc + parseFloat(n.memory.used), 0);
    const totalMemMax = onlineNodes.reduce((acc, n) => acc + parseFloat(n.memory.total), 0);

    // Server count filtered by role
    let serverWhere = {};
    if (userId && requester?.role !== 'admin') {
      serverWhere = { ownerId: userId };
    }
    const serverCount = await prisma.server.count({ where: serverWhere });
    const onlineServerCount = await prisma.server.count({ where: { ...serverWhere, status: 'running' } });
    
    res.json({
      cpu: onlineNodes.length > 0 ? (totalCpu / onlineNodes.length).toFixed(1) : "0",
      memory: {
        total: totalMemMax.toFixed(1),
        used: totalMemUsed.toFixed(1),
        percentage: totalMemMax > 0 ? ((totalMemUsed / totalMemMax) * 100).toFixed(1) : "0"
      },
      servers: {
        total: serverCount,
        online: onlineServerCount
      },
      nodes: allNodeStats,
      network: NetworkGuardian.getNetworkStats()
    });
  } catch (err) {
    console.error('Stats error:', err);
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

app.get('/api/servers', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;
    
    // Fetch requester role
    const requester = userId ? await prisma.user.findUnique({ where: { id: userId } }) : null;
    
    let where: any = {};
    if (userId && requester?.role !== 'admin') {
      where = { ownerId: userId };
    }

    const ownedServers = await prisma.server.findMany({
      where,
      include: {
        owner: { select: { id: true, username: true, email: true } },
        node: true,
        egg: true
      }
    });

    // Also fetch servers where this user is a sub-user
    let sharedServers: any[] = [];
    if (userId && requester?.role !== 'admin') {
      const subUserEntries = await prisma.subUser.findMany({
        where: { userId },
        include: {
          server: {
            include: {
              owner: { select: { id: true, username: true, email: true } },
              node: true,
              egg: true
            }
          }
        }
      });
      sharedServers = subUserEntries.map((su: any) => ({
        ...su.server,
        subUserRole: 'subuser',
        subUserPermissions: JSON.parse(su.permissions || '[]')
      }));
    }

    const allServers = [
      ...ownedServers.map((s: any) => ({ ...s, subUserRole: 'owner' })),
      ...sharedServers
    ];

    // Cross-reference live process state so we never return stale status
    const serversWithLiveStatus = await Promise.all(allServers.map(async (s: any) => ({
      ...s,
      status: (await processManager.isServerRunning(s.id)) ? 'running' : 'stopped'
    })));

    logger.info(`Fetched ${serversWithLiveStatus.length} servers for userId: ${userId || 'none'} (Role: ${requester?.role || 'none'})`);
    res.json(serversWithLiveStatus);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch servers' });
  }
});

app.get('/api/servers/:id', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;
    const server = await prisma.server.findUnique({
      where: { id: req.params.id },
      include: {
        owner: { select: { id: true, username: true, email: true, role: true } },
        node: true,
        egg: true,
        subUsers: {
          include: {
            user: { select: { id: true, username: true, email: true } }
          }
        }
      }
    });

    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    // Determine the requester's role relative to this server
    let subUserRole: string = 'none';
    let subUserPermissions: string[] = [];
    if (userId) {
      if ((server as any).ownerId === userId) {
        subUserRole = 'owner';
        subUserPermissions = ['console','files','startup','config','database','start','stop'];
      } else {
        const subEntry = (server as any).subUsers?.find((su: any) => su.userId === userId);
        if (subEntry) {
          subUserRole = 'subuser';
          subUserPermissions = JSON.parse(subEntry.permissions || '[]');
        }
      }
      // Admins get full access
      const requester = await prisma.user.findUnique({ where: { id: userId } });
      if (requester?.role === 'admin') {
        subUserRole = 'admin';
        subUserPermissions = ['console','files','startup','config','database','start','stop'];
      }
    }

    // Cross-reference live process state
    const serverWithLiveStatus = {
      ...server,
      status: (await processManager.isServerRunning(server.id)) ? 'running' : 'stopped',
      subUserRole,
      subUserPermissions
    };
    
    res.json(serverWithLiveStatus);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch server' });
  }
});

app.post('/api/servers', async (req, res) => {
  try {
    const { name, ownerId, nodeId, eggId, docker_image, command, args, cwd, memory, cpu, disk } = req.body;

    // --- RexShield: Automatic Load Distribution ---
    let assignedNodeId = nodeId;
    if (!assignedNodeId || assignedNodeId === 'auto') {
      assignedNodeId = await LoadBalancer.getOptimalNode();
      if (!assignedNodeId) {
        throw new Error('RexShield Fail-Safe: No healthy nodes available or nodes have reached critical resource usage limits (>95%). Allocation blocked to protect infrastructure.');
      }
    }

    // If no command provided, try to inherit from Egg
    let finalCommand = command;
    if (!finalCommand && eggId) {
      const egg = await prisma.egg.findUnique({ where: { id: eggId } });
      if (egg) finalCommand = egg.startup_command;
    }

    // Determine assigned CWD
    const assignedCwd = cwd || path.join(SERVERS_DIR, name.toLowerCase().replace(/\s+/g, '_'));

    // Determine assigned port
    const lastServer = await prisma.server.findFirst({
      where: { nodeId: assignedNodeId },
      orderBy: { port: 'desc' }
    });
    const assignedPort = lastServer && lastServer.port ? lastServer.port + 1 : 25565;

    const serverData = {
      name,
      ownerId: ownerId || null,
      nodeId: assignedNodeId,
      eggId,
      docker_image,
      command: finalCommand || '',
      args: args || '',
      cwd: assignedCwd,
      status: 'stopped',
      memory: parseInt(memory) || 1024,
      cpu: parseInt(cpu) || 100,
      disk: parseInt(disk) || 10240,
      port: assignedPort
    };
    
    const server = await prisma.server.create({
      data: serverData,
      include: {
        owner: { select: { id: true, username: true, email: true } },
        node: true,
        egg: true
      }
    });

    // Ensure the directory exists
    if (!fs.existsSync(assignedCwd)) {
      fs.mkdirSync(assignedCwd, { recursive: true });
    }
    
    logger.info(`Server created: ${server.name} (${server.id}) for owner: ${(server as any).ownerId || 'System'} with port ${server.port}`);
    res.json(server);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to create server' });
  }
});

app.post('/api/servers/sync', async (req, res) => {
  const { server: serverData } = req.body;
  
  if (!serverData) return res.status(400).json({ error: 'No server data provided' });

  try {
    // 1. Ensure the Node exists locally
    if (serverData.node) {
      await prisma.node.upsert({
        where: { id: serverData.node.id },
        update: {
          name: serverData.node.name,
          ip: serverData.node.ip,
          port: serverData.node.port,
          location: serverData.node.location
        },
        create: {
          id: serverData.node.id,
          name: serverData.node.name,
          ip: serverData.node.ip,
          port: serverData.node.port,
          location: serverData.node.location
        }
      });
    }

    // 2. Ensure the Egg exists locally
    if (serverData.egg) {
      await prisma.egg.upsert({
        where: { id: serverData.egg.id },
        update: {
          name: serverData.egg.name,
          description: serverData.egg.description,
          category: serverData.egg.category,
          docker_image: serverData.egg.docker_image,
          docker_images: serverData.egg.docker_images,
          startup_command: serverData.egg.startup_command
        },
        create: {
          id: serverData.egg.id,
          name: serverData.egg.name,
          description: serverData.egg.description,
          category: serverData.egg.category,
          docker_image: serverData.egg.docker_image,
          docker_images: serverData.egg.docker_images,
          startup_command: serverData.egg.startup_command
        }
      });
    }

    // 3. Ensure the Owner (User) exists locally
    if (serverData.owner) {
      await prisma.user.upsert({
        where: { id: serverData.owner.id },
        update: {
          username: serverData.owner.username,
          email: serverData.owner.email,
          // Do NOT overwrite role during sync, as it might demote admins
          // role: serverData.owner.role || 'user' 
        },
        create: {
          id: serverData.owner.id,
          username: serverData.owner.username,
          email: serverData.owner.email,
          password: 'synced_account', // Placeholder for synced accounts
          role: serverData.owner.role || 'user'
        }
      });
    }

    // 4. Finally, UPSERT the Server record
    const server = await (prisma.server as any).upsert({
      where: { id: serverData.id },
      update: {
        name: serverData.name,
        command: serverData.command,
        args: serverData.args,
        cwd: serverData.cwd,
        status: serverData.status || 'stopped',
        memory: serverData.memory,
        cpu: serverData.cpu,
        disk: serverData.disk,
        ownerId: serverData.ownerId,
        nodeId: serverData.nodeId,
        eggId: serverData.eggId,
        docker_image: serverData.docker_image,
        port: serverData.port // Added port for sync
      },
      create: {
        id: serverData.id,
        name: serverData.name,
        command: serverData.command,
        args: serverData.args,
        cwd: serverData.cwd,
        status: serverData.status || 'stopped',
        memory: serverData.memory,
        cpu: serverData.cpu,
        disk: serverData.disk,
        ownerId: serverData.ownerId,
        nodeId: serverData.nodeId,
        eggId: serverData.eggId,
        docker_image: serverData.docker_image,
        port: serverData.port // Added port for sync
      }
    });

    logger.info(`Server synced: ${server.name} (${server.id}) on node: ${os.hostname()}`);
    
    // Auto-complete setup as slave node if not already set up
    if (!SetupService.isSetupComplete()) {
      await SetupService.completeSlaveSetup();
      logger.info('Node auto-initialized as Slave Node via Server Sync.');
    }

    res.json({ success: true, server });
  } catch (err: any) {
    logger.error(`Sync failed: ${err.message}`);
    res.status(500).json({ error: 'Failed to sync server metadata: ' + err.message });
  }
});

app.patch('/api/servers/:id', async (req, res) => {
  const { id } = req.params;
  const data = req.body;
  try {
    const server = await prisma.server.update({
      where: { id },
      data,
      include: {
        owner: { select: { id: true, username: true, email: true } },
        node: true,
        egg: true
      }
    });
    res.json(server);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update server' });
  }
});

app.delete('/api/servers/:id', async (req, res) => {
  try {
    await prisma.server.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete server' });
  }
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        username: true,
        email: true,
        role: true,
        createdAt: true
      }
    });
    res.json(users);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

app.post('/api/users', async (req, res) => {
  const { username, password, email, role } = req.body;
  try {
    const user = await prisma.user.create({
      data: {
        username,
        password, // Reminder: Hash in production
        email,
        role: role || 'user'
      }
    });
    res.json({ id: user.id, username: user.username, email: user.email, role: user.role });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to create user' });
  }
});

app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  try {
    // Prevent deleting the last admin if we wanted to be safe
    const user = await prisma.user.findUnique({ where: { id } });
    if (user?.role === 'admin') {
      const adminCount = await prisma.user.count({ where: { role: 'admin' } });
      if (adminCount <= 1) {
        return res.status(403).json({ error: 'Cannot delete the last administrator' });
      }
    }

    await prisma.user.delete({ where: { id } });
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// --- Nodes API ---
app.get('/api/nodes', async (req, res) => {
  try {
    const nodes = await prisma.node.findMany({
      include: { _count: { select: { servers: true } } }
    });
    
    // Merge with detailed health stats from RexShield LoadBalancer
    const healthStats = await LoadBalancer.getNodesHealth();
    const nodesWithHealth = nodes.map(node => {
        const health = healthStats.find(h => h.nodeId === node.id);
        return {
            ...node,
            ...health,
            status: health?.status || 'offline'
        };
    });
    
    res.json(nodesWithHealth);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch nodes' });
  }
});

app.post('/api/nodes', async (req, res) => {
  const { name, ip, port, location } = req.body;
  try {
    const node = await prisma.node.create({
      data: { name, ip, port: parseInt(port) || 3001, location }
    });
    res.json(node);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to create node' });
  }
});

app.patch('/api/nodes/:id', async (req, res) => {
  const { id } = req.params;
  const { name, ip, port, location } = req.body;
  try {
    const node = await prisma.node.update({
      where: { id },
      data: { 
        ...(name && { name }),
        ...(ip && { ip }),
        ...(port && { port: parseInt(port) }),
        ...(location && { location })
      }
    });
    res.json(node);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update node' });
  }
});

app.delete('/api/nodes/:id', async (req, res) => {
  try {
    await prisma.node.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete node' });
  }
});

// --- Eggs API ---
app.get('/api/eggs', async (req, res) => {
  try {
    const eggs = await prisma.egg.findMany();
    res.json(eggs);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch eggs' });
  }
});

app.post('/api/eggs', async (req, res) => {
  // Support both raw body (Pterodactyl JSON) and form fields
  const body = req.body;
  
  // Detection for Pterodactyl Egg Format
  if (body.meta && body.meta.version === 'PTDL_v2') {
    try {
      const dockerImages = body.docker_images ? JSON.stringify(body.docker_images) : null;
      const features = body.features ? JSON.stringify(body.features) : null;
      const fileDenylist = body.file_denylist ? JSON.stringify(body.file_denylist) : null;
      const config = body.config ? JSON.stringify(body.config) : null;
      const variables = body.variables ? JSON.stringify(body.variables) : null;
      
      const egg = await prisma.egg.create({
        data: {
          name: body.name,
          description: body.description,
          author: body.author,
          features,
          docker_images: dockerImages,
          file_denylist: fileDenylist,
          startup_command: body.startup,
          config,
          installation_script: body.scripts?.installation?.script,
          installation_container: body.scripts?.installation?.container,
          installation_entrypoint: body.scripts?.installation?.entrypoint,
          variables,
          category: 'Imported', // Default category for imports
          docker_image: Object.values(body.docker_images || {})[0] as string || 'eclipse-temurin:17-jre' // Pick first image as default
        }
      });
      return res.json(egg);
    } catch (err: any) {
      return res.status(400).json({ error: 'Failed to import Pterodactyl egg: ' + err.message });
    }
  }

  // Fallback to legacy Manual Creation
  const { name, description, category, docker_image, docker_images, startup_command } = req.body;
  try {
    const egg = await prisma.egg.create({
      data: { name, description, category, docker_image, docker_images, startup_command }
    });
    res.json(egg);
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to create egg' });
  }
});

app.patch('/api/eggs/:id', async (req, res) => {
  const { id } = req.params;
  const data = req.body; // Allow partial updates of any field
  try {
    const egg = await prisma.egg.update({
      where: { id },
      data
    });
    res.json(egg);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update egg' });
  }
});

app.delete('/api/eggs/:id', async (req, res) => {
  try {
    await prisma.egg.delete({ where: { id: req.params.id } });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete egg' });
  }
});

// Initialize default eggs if needed
const seedEggs = async () => {
  const eggCount = await prisma.egg.count();
  if (eggCount === 0) {
    await prisma.egg.createMany({
      data: [
        { name: 'Minecraft (Paper)', category: 'Minecraft', startup_command: 'java -Xms128M -Xmx{{MEMORY}}M -jar paper.jar' },
        { name: 'Node.js Generic', category: 'General', startup_command: 'npm start' },
        { name: 'Python App', category: 'General', startup_command: 'python main.py' }
      ]
    });
    console.log('Seeded default eggs.');
  }
};
seedEggs().catch(console.error);

app.patch('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const { role, username, email } = req.body;
  try {
    const user = await prisma.user.update({
      where: { id },
      data: { 
        ...(role && { role }),
        ...(username && { username }),
        ...(email && { email })
      },
      select: { id: true, username: true, email: true, role: true, createdAt: true }
    });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

// --- Security & Audit API ---
app.get('/api/admin/audit-logs', async (req, res) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    const logs = await prisma.auditLog.findMany({
      take: Number(limit),
      skip: Number(offset),
      orderBy: { createdAt: 'desc' }
    });
    const total = await prisma.auditLog.count();
    res.json({ logs, total });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

app.get('/api/admin/security-events', async (req, res) => {
  try {
    const events = await prisma.securityEvent.findMany({
      orderBy: { createdAt: 'desc' },
      take: 100
    });
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch security events' });
  }
});

// --- Host Settings API ---
app.get('/api/settings', async (req, res) => {
  try {
    const settings = await SettingsService.getAll();
    res.json(settings);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.post('/api/settings', async (req, res) => {
  try {
    const settings = req.body;
    if (typeof settings !== 'object') {
       return res.status(400).json({ error: 'Invalid settings format' });
    }

    await SettingsService.setMany(settings);

    SecurityService.log({
      action: 'settings_update',
      entity: 'system',
      entityId: 'global',
      userId: (req.headers['x-user-id'] as string | undefined),
      ip: req.ip,
      metadata: { keys: Object.keys(settings) }
    });

    res.json({ message: 'Settings updated successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// --- RexBoost API ---
app.post('/api/servers/:id/boost/turbo', async (req, res) => {
  const { id } = req.params;
  const { enabled } = req.body;
  try {
    const success = await RexBoost.setTurboMode(id, enabled);
    if (!success) throw new Error('Failed to toggle Turbo Mode');
    res.json({ success: true, enabled });
  } catch (err: any) {
    res.status(400).json({ error: err.message });
  }
});

app.post('/api/servers/:id/boost/cleanup', async (req, res) => {
  const { id } = req.params;
  try {
    const server = await prisma.server.findUnique({ where: { id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });
    
    const saved = await RexBoost.runCleanup(server.cwd);
    res.json({ success: true, spaceSaved: saved });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/boost/java-flags', (req, res) => {
    const memory = parseInt(req.query.memory as string) || 1024;
    const flags = RexBoost.getOptimizedJavaFlags(memory);
    res.json({ flags });
});

app.post('/api/eggs/import', async (req, res) => {
  try {
    const eggData = req.body;
    
    // Translation map for common Pterodactyl/Pelican placeholders
    const placeholderMap: { [key: string]: string } = {
      '{{SERVER_MEMORY}}': '{{MEMORY}}',
      '{{SERVER_DISK}}': '{{DISK}}',
      '{{SERVER_PORT}}': '{{PORT}}',
      '{{P_SERVER_UUID}}': '{{ID}}',
    };

    let startupCommand = eggData.startup || '';
    
    // Replace known placeholders
    Object.entries(placeholderMap).forEach(([pterodactyl, rexhost]) => {
      startupCommand = startupCommand.replace(new RegExp(pterodactyl.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), rexhost);
    });

    // Handle variables (e.g., {{SERVER_JARFILE}}) by keeping them as-is 
    // or mapping them if we have equivalents. For now, we'll keep them.

    // Extract docker images if available in a format we can parse, or just use the primary one
    const dockerImages = eggData.docker_images ? JSON.stringify(eggData.docker_images) : null; 
    // Note: Pterodactyl usually sends an object map {"Java 17": "image..."}. We might need to transform this.
    // For simplicity, if it's an object, we map to "Key=Value\nKey=Value" string format for our TextArea.
    
    let dockerImagesString = '';
    if (eggData.docker_images && typeof eggData.docker_images === 'object') {
       dockerImagesString = Object.entries(eggData.docker_images)
        .map(([key, val]) => `${key}=${val}`)
        .join('\n');
    }

    const egg = await prisma.egg.create({
      data: {
        name: eggData.name || 'Imported Egg',
        description: eggData.description || `Imported from ${eggData.author || 'Pterodactyl'}`,
        category: eggData.category || 'Imported',
        docker_image: eggData.docker_image || eggData.image || 'eclipse-temurin:17-jre',
        docker_images: dockerImagesString || null,
        startup_command: startupCommand,
      }
    });

    res.json(egg);
  } catch (err: any) {
    res.status(400).json({ error: 'Failed to import egg: ' + err.message });
  }
});

app.get('/api/me', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;
    if (!userId) return res.status(401).json({ error: 'Not authenticated' });

    const user = await prisma.user.findUnique({
      where: { id: userId }
    });
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    });
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await prisma.user.findFirst({
      where: { username, password } // Reminder: In a real app, use hashed passwords
    });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    SecurityService.log({
      action: 'login',
      entity: 'user',
      entityId: user.id,
      userId: user.id,
      ip: req.ip,
      metadata: { username: user.username }
    });

    res.json({
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role
    });
  } catch (err: any) {
    SecurityService.alert({
      type: 'auth_failure',
      severity: 'MEDIUM',
      description: `Failed login attempt for username: ${username}`,
      metadata: { ip: req.ip, username }
    });
    res.status(500).json({ error: 'Authentication failed' });
  }
});

app.post('/api/servers/:id/start', async (req, res) => {
  const { id } = req.params;
  let { command, args, cwd } = req.body || {};
  
  try {
    const server = await prisma.server.findUnique({
      where: { id },
      include: { 
        egg: true,
        node: true
      }
    }) as any;

    if (!server) return res.status(404).json({ error: 'Server not found' });

    // Priority: Request Body > Server Object > Egg Template
    let finalCommand = command || server.command || server.egg?.startup_command || '';
    const finalArgs = args ? (Array.isArray(args) ? args : [args]) : (server.args ? [server.args] : []);
    const finalCwd = cwd || server.cwd;

    // Replace placeholders in command
    finalCommand = finalCommand.replace(/{{MEMORY}}/g, server.memory.toString());
    finalCommand = finalCommand.replace(/{{DISK}}/g, server.disk.toString());
    finalCommand = finalCommand.replace(/{{CPU}}/g, server.cpu.toString());
    finalCommand = finalCommand.replace(/{{PORT}}/g, server.port?.toString() || '3001'); // Use server.port
    finalCommand = finalCommand.replace(/{{SERVER_JARFILE}}/g, 'server.jar'); // Default fallback for Pterodactyl eggs

    if (!finalCommand) return res.status(400).json({ error: 'No startup command available' });

    // Write port to config before starting
    const serverDir = path.resolve(server.cwd);
    const propertiesPath = path.join(serverDir, 'server.properties');
    if (fs.existsSync(propertiesPath)) {
      let content = fs.readFileSync(propertiesPath, 'utf8');
      
      const updates = {
        'server-port': server.port.toString(),
        'query.port': server.port.toString()
      };

      Object.entries(updates).forEach(([key, value]) => {
        const regex = new RegExp(`^${key}=.*$`, 'm');
        if (regex.test(content)) {
          content = content.replace(regex, `${key}=${value}`);
        } else {
          content += `\n${key}=${value}`;
        }
      });

      fs.writeFileSync(propertiesPath, content);
      console.log(`[RexHost] Updated ports in server.properties for ${server.id} to ${server.port}`);
    }

    // Check if the server JAR exists before starting (if command implies a jar)
    // This is a heuristic to detect missing core files and prompt user to install
    if (finalCommand.includes('.jar') && !processManager.checkFileExists(finalCwd, 'server.jar')) {
        // If the command mentions a jar but server.jar is missing, try to find other common entry points
        // or just fail if it's strictly a jar command.
       if (!processManager.checkFileExists(finalCwd, 'server.jar') && !processManager.checkFileExists(finalCwd, 'run.bat') && !processManager.checkFileExists(finalCwd, 'run.sh')) {
           return res.status(400).json({ error: 'Server executable not found', code: 'SERVER_JAR_MISSING' });
       }
    }

    processManager.startServer({ 
      id, 
      command: finalCommand.trim(), 
      args: finalArgs, 
      cwd: finalCwd,
      memory: server.memory, // MB
      cpu: server.cpu, // Shares
      port: server.port || 25565,
      turboMode: server.turboMode,
      isMinecraft: server.egg?.category === 'Minecraft',
      // Use Server-specific Docker Image, fallback to Egg default, fallback to system default
      dockerImage: server.docker_image || server.egg?.docker_image || 'eclipse-temurin:17-jre'
    }).catch(err => {
      logger.error(`Background start failure for ${id}: ${err.message}`, { stack: err.stack });
    });
    
    logger.info(`Server ${id} using Docker Image: ${server.docker_image || server.egg?.docker_image || 'eclipse-temurin:17-jre'}`);
    
    // Update status in DB
    await prisma.server.update({ where: { id }, data: { status: 'running' } });
    
    io.emit('status', { id, status: 'running' }); // Emit status via Socket.IO
    SecurityService.log({
      action: 'server_start',
      entity: 'server',
      entityId: id,
      userId: req.headers['x-user-id'] as string,
      ip: req.ip,
      metadata: { name: server.name, image: server.docker_image }
    });

    res.json({ message: 'Server start sequence initiated' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/servers/:id/stop', async (req, res) => {
  const { id } = req.params;
  try {
    processManager.stopServer(id);
    await prisma.server.update({ where: { id }, data: { status: 'stopped' } });
    SecurityService.log({
      action: 'server_stop',
      entity: 'server',
      entityId: id,
      userId: req.headers['x-user-id'] as string,
      ip: req.ip
    });
    res.json({ message: 'Server stop sequence initiated' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/servers/:id', async (req, res) => {
  const { id } = req.params;
  try {
    const server = await prisma.server.findUnique({ where: { id } });
    if (!server) {
        // If server not in DB, try to clean up container anyway
        await processManager.deleteServer(id, ''); 
        return res.status(404).json({ error: 'Server not found' });
    }

    // Delete container and data
    await processManager.deleteServer(id, server.cwd);

    // Delete from DB
    await prisma.server.delete({ where: { id } });

    SecurityService.log({
      action: 'server_delete',
      entity: 'server',
      entityId: id,
      userId: req.headers['x-user-id'] as string,
      ip: req.ip
    });

    res.json({ message: 'Server deleted successfully' });
  } catch (err: any) {
    logger.error(`Failed to delete server ${id}: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/servers/:id/command', (req, res) => {
  const { id } = req.params;
  const { command } = req.body || {};
  if (!command) return res.status(400).json({ error: 'No command provided' });
  SecurityService.log({
    action: 'server_command',
    entity: 'server',
    entityId: id,
    userId: (req.headers['x-user-id'] as string | undefined),
    ip: req.ip,
    metadata: { command }
  });

  processManager.sendCommand(id, command);
  res.json({ message: 'Command sent' });
});

const downloadFile = async (serverId: string, url: string, fileName: string, req: express.Request, res: express.Response) => {
  try {
    const server = await prisma.server.findUnique({ 
        where: { id: serverId },
        include: { egg: true }
    });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    if (!fs.existsSync(server.cwd)) {
      fs.mkdirSync(server.cwd, { recursive: true });
    }

    logger.info(`Starting download via Docker: ${url} -> ${fileName}`);

    // Use server's Docker image for download to ensure compatibility, or fallback
    const image = server.docker_image || server.egg?.docker_image || 'curlimages/curl:latest';
    
    // Use ProcessManager to download inside a container
    await processManager.downloadFileViaDocker(image, server.cwd, url, fileName);

    logger.info(`Download complete for server ${serverId}: ${fileName}`);
    SecurityService.log({
      action: 'server_download_file',
      entity: 'server',
      entityId: serverId,
      userId: (req.headers['x-user-id'] as string | undefined),
      ip: req.ip,
      metadata: { url, fileName }
    });
    res.json({ message: 'Download complete', fileName });

  } catch (err: any) {
    logger.error(`Download initiation failed: ${err.message}`);
    res.status(500).json({ error: err.message || 'Failed to initiate download' });
  }
};

app.post('/api/servers/:id/download', async (req, res) => {
  const { id } = req.params;
  const { url, fileName } = req.body;
  if (!url) return res.status(400).json({ error: 'URL is required' });
  await downloadFile(id, url, fileName || 'server.jar', req, res);
});

app.post('/api/servers/:id/install', async (req, res) => {
  const { id } = req.params;
  
  try {
    const server = await prisma.server.findUnique({ 
        where: { id },
        include: { egg: true } 
    });
    
    if (!server) return res.status(404).json({ error: 'Server not found' });
    if (!server.egg) return res.status(400).json({ error: 'Server has no egg defined' });

    // 1. Generic Egg Installation
    if (server.egg.installation_script && server.egg.installation_container) {
        logger.info(`Starting generic installation for server ${id}`);
        
        // Parse variables
        let envVars: Record<string, string> = {
            SERVER_MEMORY: server.memory.toString(),
            SERVER_IP: '0.0.0.0',
            SERVER_PORT: server.port.toString()
        };

        // Inject Egg Variables with their default values or server-specific overrides (if we had them)
        if (server.egg.variables) {
            try {
                const vars = JSON.parse(server.egg.variables as string);
                vars.forEach((v: any) => {
                    envVars[v.env_variable] = v.default_value;
                });
            } catch (e) {
                logger.warn('Failed to parse egg variables for installation');
            }
        }
        
        // Populate standard Pterodactyl vars
        envVars['MINECRAFT_VERSION'] = envVars['MINECRAFT_VERSION'] || 'latest';
        
        await processManager.runInstallScript(
            server.cwd,
            server.egg.installation_container,
            server.egg.installation_script,
            envVars,
            server.egg.installation_entrypoint || '/bin/sh'
        );
        
        SecurityService.log({
            action: 'server_install',
            entity: 'server',
            entityId: id,
            userId: (req.headers['x-user-id'] as string | undefined),
            ip: req.ip,
            metadata: { egg: server.egg.name }
        });
        
        return res.json({ message: 'Installation completed successfully' });
    }

    // 2. Legacy PaperMC Fallback (if no script defined)
    // ... keep existing logic for backward compatibility or direct calls ...
    const { version, fileName } = req.body;
    if (version) {
       // ... (existing paper logic) ...
       // For brevity, we redirect to the paper logic or handle it here.
       // But really, if we import the Paper egg, the block above handles it.
       // We'll keep the specialized endpoint below for manual "Install Paper" clicks that bypass the egg script.
    }
    
    return res.status(400).json({ error: 'No installation script found for this server type.' });

  } catch (err: any) {
    logger.error(`Installation failed: ${err.message}`);
    res.status(500).json({ error: `Installation failed: ${err.message}` });
  }
});

// Deprecated: Specific Paper endpoint, keep for older frontend calls
app.post('/api/servers/:id/install/paper', async (req, res) => {
  const { id } = req.params;
  const { version, fileName } = req.body;
  // ... existing implementation ...
  if (!version) return res.status(400).json({ error: 'Version is required' });

  const fetchStableBuild = async (v: string) => {
    try {
      const buildsRes = await axios.get(`https://fill.papermc.io/v3/projects/paper/versions/${v}/builds`, {
        headers: { 'User-Agent': 'RexHost/1.0' }
      });
      const builds = Array.isArray(buildsRes.data) ? buildsRes.data : (buildsRes.data.builds || []);
      return builds.reverse().find((b: any) => b.channel === 'STABLE');
    } catch (err) {
      return null;
    }
  };

  try {
    let stableBuild = await fetchStableBuild(version);
    let resolvedVersion = version;

    if (!stableBuild) {
      logger.info(`No stable build for ${version}, searching latest stable version...`);
      const projectsRes = await axios.get('https://fill.papermc.io/v3/projects/paper', {
        headers: { 'User-Agent': 'RexHost/1.0' }
      });
      
      const versionsObj = projectsRes.data.versions;
      const allVersions = Object.keys(versionsObj)
        .sort((a, b) => b.localeCompare(a, undefined, { numeric: true }))
        .flatMap(v => versionsObj[v]);

      for (const v of allVersions) {
        stableBuild = await fetchStableBuild(v);
        if (stableBuild) {
          resolvedVersion = v;
          break;
        }
      }
    }

    if (!stableBuild) {
      return res.status(404).json({ error: 'No stable PaperMC build found for any version' });
    }

    const downloadUrl = stableBuild.downloads['server:default']?.url;
    if (!downloadUrl) {
      return res.status(404).json({ error: `Download URL not found for PaperMC ${resolvedVersion}` });
    }

    await downloadFile(id, downloadUrl, fileName || 'server.jar', req, res);

  } catch (err: any) {
    logger.error(`PaperMC installation failed: ${err.message}`);
    res.status(500).json({ error: `Failed to resolve PaperMC download: ${err.message}` });
  }
});

app.post('/api/servers/:id/eula', async (req, res) => {
  const { id } = req.params;

  try {
    const server = await prisma.server.findUnique({ where: { id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const eulaPath = path.join(server.cwd, 'eula.txt');
    
    // Create or overwrite eula.txt with eula=true
    const content = '#By changing the setting below to TRUE you are indicating your agreement to our EULA (https://aka.ms/MinecraftEULA).\neula=true\n';
    
    fs.writeFileSync(eulaPath, content);
    logger.info(`EULA accepted for server ${id}`);
    
    res.json({ message: 'EULA accepted successfully' });
  } catch (err: any) {
    logger.error(`Failed to update EULA for server ${id}: ${err.message}`);
    res.status(500).json({ error: 'Failed to update EULA file' });
  }
});

// ═══════════════════════════════════════════
// FILE MANAGEMENT API
// ═══════════════════════════════════════════

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

// Helper: resolve & sandbox path to server cwd
function safePath(serverCwd: string, relativePath: string): string | null {
  // On Windows, path.resolve with a leading slash treats it as a drive root.
  // We want to force it to be relative to the server root.
  const normalizedRelative = relativePath.replace(/^[\\\/]+/, '');
  const root = path.resolve(serverCwd);
  const resolved = path.resolve(root, normalizedRelative);
  
  if (!resolved.startsWith(root)) {
    return null; // path traversal blocked
  }
  return resolved;
}

// List directory
app.get('/api/servers/:id/files', async (req, res) => {
  try {
    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const dirPath = safePath(server.cwd, (req.query.path as string) || '/');
    if (!dirPath) return res.status(403).json({ error: 'Access denied' });
    if (!fs.existsSync(dirPath)) return res.status(404).json({ error: 'Directory not found' });

    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    const files = entries.map(entry => {
      const fullPath = path.join(dirPath, entry.name);
      try {
        const stat = fs.statSync(fullPath);
        return {
          name: entry.name,
          type: entry.isDirectory() ? 'directory' : 'file',
          size: stat.size,
          modified: stat.mtime.toISOString()
        };
      } catch {
        return { name: entry.name, type: entry.isDirectory() ? 'directory' : 'file', size: 0, modified: '' };
      }
    });

    // Sort: directories first, then by name
    files.sort((a, b) => {
      if (a.type !== b.type) return a.type === 'directory' ? -1 : 1;
      return a.name.localeCompare(b.name);
    });

    res.json({ path: (req.query.path as string) || '/', files });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Read file content
app.get('/api/servers/:id/files/content', async (req, res) => {
  try {
    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const filePath = safePath(server.cwd, (req.query.path as string) || '');
    if (!filePath) return res.status(403).json({ error: 'Access denied' });
    if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
      return res.status(404).json({ error: 'File not found' });
    }

    const content = fs.readFileSync(filePath, 'utf8');
    res.json({ path: req.query.path, content });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Save file content
app.put('/api/servers/:id/files/content', async (req, res) => {
  try {
    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const { path: filePath, content } = req.body;
    const resolved = safePath(server.cwd, filePath || '');
    if (!resolved) return res.status(403).json({ error: 'Access denied' });

    fs.writeFileSync(resolved, content, 'utf8');
    SecurityService.log({
      action: 'file_save',
      entity: 'file',
      entityId: req.params.id,
      userId: (req.headers['x-user-id'] as string | undefined),
      ip: req.ip,
      metadata: { path: filePath }
    });
    res.json({ message: 'File saved successfully' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Upload file
app.post('/api/servers/:id/files/upload', upload.single('file'), async (req, res) => {
  try {
    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

    const targetDir = safePath(server.cwd, (req.body.path as string) || '/');
    if (!targetDir) return res.status(403).json({ error: 'Access denied' });
    if (!fs.existsSync(targetDir)) fs.mkdirSync(targetDir, { recursive: true });

    const targetPath = path.join(targetDir, req.file.originalname);
    fs.writeFileSync(targetPath, req.file.buffer);
    
    SecurityService.log({
      action: 'file_upload',
      entity: 'file',
      entityId: req.params.id,
      userId: (req.headers['x-user-id'] as string | undefined),
      ip: req.ip,
      metadata: { path: req.body.path || '/', filename: req.file.originalname }
    });

    res.json({ message: 'File uploaded successfully', name: req.file.originalname });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Delete file or folder
app.delete('/api/servers/:id/files/delete', async (req, res) => {
  try {
    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const targetPath = safePath(server.cwd, (req.body.path as string) || '');
    if (!targetPath) return res.status(403).json({ error: 'Access denied' });
    if (!fs.existsSync(targetPath)) return res.status(404).json({ error: 'Not found' });

    // Prevent deleting the server root
    if (path.resolve(targetPath) === path.resolve(server.cwd)) {
      return res.status(403).json({ error: 'Cannot delete server root' });
    }

    const stat = fs.statSync(targetPath);
    if (stat.isDirectory()) {
      fs.rmSync(targetPath, { recursive: true, force: true });
    } else {
      fs.unlinkSync(targetPath);
    }

    SecurityService.log({
      action: 'file_delete',
      entity: 'file',
      entityId: req.params.id,
      userId: Array.isArray(req.headers['x-user-id']) ? req.headers['x-user-id'][0] : req.headers['x-user-id'],
      ip: req.ip,
      metadata: { path: req.body.path }
    });

    res.json({ message: 'Deleted successfully' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Create directory
app.post('/api/servers/:id/files/mkdir', async (req, res) => {
  try {
    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const targetPath = safePath(server.cwd, (req.body.path as string) || '');
    if (!targetPath) return res.status(403).json({ error: 'Access denied' });

    fs.mkdirSync(targetPath, { recursive: true });
    
    SecurityService.log({
      action: 'mkdir',
      entity: 'directory',
      entityId: req.params.id,
      userId: req.headers['x-user-id'] as string,
      ip: req.ip,
      metadata: { path: req.body.path }
    });

    res.json({ message: 'Directory created successfully' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Update server settings
app.put('/api/servers/:id', async (req, res) => {
  try {
    const { command, args, memory, cpu, disk } = req.body;
    const server = await prisma.server.update({
      where: { id: req.params.id },
      data: {
        ...(command !== undefined && { command }),
        ...(args !== undefined && { args }),
        ...(memory !== undefined && { memory: parseInt(memory) }),
        ...(cpu !== undefined && { cpu: parseInt(cpu) }),
        ...(disk !== undefined && { disk: parseInt(disk) })
      },
      include: { node: true, egg: true }
    });
      res.json(server);
    } catch (err: any) {
      res.status(400).json({ error: err.message });
    }
});

// --- Database Management ---
app.post('/api/servers/:id/database', async (req, res) => {
    try {
        const db = await databaseManager.createDatabase(req.params.id);
        res.json(db);
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/servers/:id/database', async (req, res) => {
    try {
        const db = await databaseManager.getDatabase(req.params.id);
        if (!db) return res.status(404).json({ error: 'No database found' });
        res.json(db);
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

app.delete('/api/servers/:id/database', async (req, res) => {
    try {
        await databaseManager.deleteDatabase(req.params.id);
        res.json({ success: true });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/servers/:id/database/status', async (req, res) => {
    try {
        const status = await databaseManager.getStatus(req.params.id);
        res.json({ status });
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/servers/:id/database/query', async (req, res) => {
    try {
        const { sql } = req.body;
        if (!sql) return res.status(400).json({ error: 'SQL query required' });
        const result = await databaseManager.executeQuery(req.params.id, sql);
        res.json(result);
    } catch (err: any) {
        res.status(500).json({ error: err.message });
    }
});

// Proxy logic...

app.get('/api/proxy/paper', async (req, res) => {
  try {
    const response = await axios.get('https://fill.papermc.io/v3/projects/paper', {
      headers: { 'User-Agent': 'RexHost/1.0' }
    });
    res.json(response.data);
  } catch (err: any) {
    logger.error(`Proxy request failed: ${err.message}`);
    res.status(500).json({ error: 'Failed to fetch PaperMC data' });
  }
});

// ===== Sub-User Management =====

// List sub-users for a server
app.get('/api/servers/:id/subusers', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;
    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    // Only owner or admin can view sub-users
    const requester = userId ? await prisma.user.findUnique({ where: { id: userId } }) : null;
    if (server.ownerId !== userId && requester?.role !== 'admin') {
      return res.status(403).json({ error: 'Only the server owner or an admin can manage sub-users' });
    }

    const subUsers = await prisma.subUser.findMany({
      where: { serverId: req.params.id },
      include: {
        user: { select: { id: true, username: true, email: true } }
      }
    });

    res.json(subUsers.map((su: any) => ({
      ...su,
      permissions: JSON.parse(su.permissions || '[]')
    })));
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Add a sub-user to a server
app.post('/api/servers/:id/subusers', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;
    const { email, permissions } = req.body;

    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const requester = userId ? await prisma.user.findUnique({ where: { id: userId } }) : null;
    if (server.ownerId !== userId && requester?.role !== 'admin') {
      return res.status(403).json({ error: 'Only the server owner or an admin can manage sub-users' });
    }

    // Find target user by email, or auto-create if not found
    let targetUser = await prisma.user.findUnique({ where: { email } });
    let autoCreated = false;
    let generatedPassword: string | null = null;

    if (!targetUser) {
      // Auto-create the user with a random password
      generatedPassword = Math.random().toString(36).slice(-10);
      const username = email.split('@')[0];
      targetUser = await prisma.user.create({
        data: {
          username,
          password: generatedPassword,
          email,
          role: 'user'
        }
      });
      autoCreated = true;
    }

    if (targetUser.id === server.ownerId) {
      return res.status(400).json({ error: 'Cannot add the server owner as a sub-user' });
    }

    // Check if already a sub-user
    const existing = await prisma.subUser.findUnique({
      where: { userId_serverId: { userId: targetUser.id, serverId: server.id } }
    });
    if (existing) return res.status(409).json({ error: 'User is already a sub-user of this server' });

    const subUser = await prisma.subUser.create({
      data: {
        userId: targetUser.id,
        serverId: server.id,
        permissions: JSON.stringify(permissions || ['console'])
      },
      include: {
        user: { select: { id: true, username: true, email: true } }
      }
    });

    SecurityService.log({
      action: 'SUBUSER_ADD',
      entity: 'subuser',
      entityId: subUser.id,
      userId,
      ip: req.ip,
      metadata: { targetEmail: email, serverId: server.id, permissions }
    });

    res.json({ ...subUser, permissions: JSON.parse(subUser.permissions || '[]'), autoCreated, generatedPassword });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Update a sub-user's permissions
app.put('/api/servers/:id/subusers/:subUserId', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;
    const { permissions } = req.body;

    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const requester = userId ? await prisma.user.findUnique({ where: { id: userId } }) : null;
    if (server.ownerId !== userId && requester?.role !== 'admin') {
      return res.status(403).json({ error: 'Only the server owner or an admin can manage sub-users' });
    }

    const subUser = await prisma.subUser.update({
      where: { id: req.params.subUserId },
      data: { permissions: JSON.stringify(permissions) },
      include: {
        user: { select: { id: true, username: true, email: true } }
      }
    });

    SecurityService.log({
      action: 'SUBUSER_UPDATE',
      entity: 'subuser',
      entityId: subUser.id,
      userId,
      ip: req.ip,
      metadata: { serverId: server.id, newPermissions: permissions }
    });

    res.json({ ...subUser, permissions: JSON.parse(subUser.permissions || '[]') });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// Remove a sub-user
app.delete('/api/servers/:id/subusers/:subUserId', async (req, res) => {
  try {
    const userId = req.headers['x-user-id'] as string;

    const server = await prisma.server.findUnique({ where: { id: req.params.id } });
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const requester = userId ? await prisma.user.findUnique({ where: { id: userId } }) : null;
    if (server.ownerId !== userId && requester?.role !== 'admin') {
      return res.status(403).json({ error: 'Only the server owner or an admin can manage sub-users' });
    }

    await prisma.subUser.delete({ where: { id: req.params.subUserId } });

    SecurityService.log({
      action: 'SUBUSER_REMOVE',
      entity: 'subuser',
      entityId: req.params.subUserId,
      userId,
      ip: req.ip,
      metadata: { serverId: server.id }
    });

    res.json({ message: 'Sub-user removed successfully' });
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', platform: process.platform });
});

// WebSocket Integration
processManager.on('console', (data) => {
  io.to(data.id).emit('console', data);
});

processManager.on('status', async (data) => {
  io.to(data.id).emit('status', data);
  // Persist status change to DB
  try {
    await prisma.server.update({
      where: { id: data.id },
      data: { status: data.status }
    });
  } catch (err) {
    console.error(`Failed to persist status for ${data.id}:`, err);
  }
});

io.on('connection', (socket) => {
  logger.info(`New client connected: ${socket.id}`);
  
  socket.on('join', (serverId) => {
    socket.join(serverId);
    logger.info(`Client ${socket.id} joined room ${serverId}`);
    
    // Send history to the joining client
    const history = processManager.getConsoleHistory(serverId);
    if (history.length > 0) {
      // Send as simple strings for now, Panel handles parsing
      socket.emit('console', { id: serverId, data: history.join(''), isHistory: true });
    }
  });

  socket.on('command', async (data: { id: string, command: string }) => {
    if (!data.id || !data.command) return;
    logger.info(`Command received for ${data.id}: ${data.command}`);
    await processManager.sendCommand(data.id, data.command);
  });
  
  socket.on('disconnect', () => {
    logger.info(`Client disconnected: ${socket.id}`);
  });
});

// Global Error Handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  logger.error('Unhandled Error:', err);
  res.status(500).json({ error: err.message || 'Internal Server Error' });
});

process.on('uncaughtException', (err) => {
  logger.error('Uncaught Exception:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('CRITICAL: Unhandled Rejection', {
    reason: reason instanceof Error ? { message: reason.message, stack: reason.stack } : reason,
    promise: 'Promise' // Promise object itself is not easily serializable
  });
});

const PORT = process.env.DAEMON_PORT || 3001;

// Periodic stats emitter for all running servers
function startStatsEmitter() {
  setInterval(async () => {
    try {
      const servers = await prisma.server.findMany({
        where: { status: 'running' }
      });

      for (const server of servers) {
        const stats = await processManager.getContainerStats(server.id);
        if (stats) {
          // Calculate CPU percentage
          const cpuDelta = stats.cpu_stats.cpu_usage.total_usage - stats.precpu_stats.cpu_usage.total_usage;
          const systemDelta = stats.cpu_stats.system_cpu_usage - stats.precpu_stats.system_cpu_usage;
          const cpuPercent = systemDelta > 0 && cpuDelta > 0 
            ? ((cpuDelta / systemDelta) * (stats.cpu_stats.online_cpus || 1) * 100).toFixed(1) 
            : "0.0";

          // Calculate Memory
          const usedMem = stats.memory_stats.usage || 0;
          const maxMem = stats.memory_stats.limit || 0;

          io.to(server.id).emit('container_stats', {
            id: server.id,
            cpu: cpuPercent,
            memory: {
              used: Math.round(usedMem / (1024 * 1024)), // MB
              total: Math.round(maxMem / (1024 * 1024)), // MB
              percentage: maxMem > 0 ? ((usedMem / maxMem) * 100).toFixed(1) : "0"
            }
          });
        }
      }
    } catch (err) { }
  }, 3000);
}

// Auto-bootstrap: ensure a default node always exists
async function bootstrap() {
  try {
    const nodeCount = await prisma.node.count();
    if (nodeCount === 0) {
      const os = await import('os');
      await prisma.node.create({
        data: {
          name: 'Node 01',
          ip: '127.0.0.1',
          port: parseInt(PORT as string),
          location: os.hostname()
        }
      });
      logger.info('Auto-created default local node (Node 01)');
    }
  } catch (err) {
    logger.error('Bootstrap error:', err);
  }
}

// Start everything
bootstrap().then(() => {
  httpServer.listen(PORT, () => {
    logger.info(`RexDaemon running on port ${PORT}`);
    autoUpdater.startService();
    resourceWarden.start();
    startStatsEmitter();
  });
}).catch(err => {
  logger.error('Failed to start daemon:', err);
});
