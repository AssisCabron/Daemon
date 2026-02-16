import fs from 'fs';
import path from 'path';
import { prisma } from '../lib/prisma';

const LOCK_FILE = path.join(process.cwd(), '.setup_lock');

export class SetupService {
  public static isSetupComplete(): boolean {
    return fs.existsSync(LOCK_FILE);
  }

  public static async completeSetup(adminData: any) {
    if (this.isSetupComplete()) {
      throw new Error('Setup already completed');
    }

    // Create admin user
    const admin = await prisma.user.create({
      data: {
        username: adminData.username,
        password: adminData.password, // In a real app, hash this!
        email: adminData.email,
        role: 'admin'
      }
    });

    // Save initial settings
    await prisma.setting.create({
      data: {
        key: 'system_name',
        value: 'RexHost'
      }
    });

    // Create lock file
    fs.writeFileSync(LOCK_FILE, JSON.stringify({ completedAt: new Date(), adminId: admin.id }));

    // Auto-create default local node
    const os = await import('os');
    const existingNode = await prisma.node.findFirst();
    if (!existingNode) {
      await prisma.node.create({
        data: {
          name: 'Node 01',
          ip: '127.0.0.1',
          port: parseInt(process.env.DAEMON_PORT || '3001'),
          location: os.hostname()
        }
      });
    }
    
    return admin;
  }

  public static async completeSlaveSetup() {
    if (this.isSetupComplete()) return;

    // Save initial settings
    await prisma.setting.create({
      data: {
        key: 'system_name',
        value: 'RexHost Node'
      }
    });

    // Create lock file
    fs.writeFileSync(LOCK_FILE, JSON.stringify({ completedAt: new Date(), type: 'slave' }));
  }
}
