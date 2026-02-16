import { execSync } from 'child_process';
import fs from 'fs';
import path from 'path';

const rootDir = path.join(__dirname, '..');
const envPath = path.join(rootDir, '.env');

console.log('🚀 Starting RexDaemon Setup...');

// 1. Environment Setup
if (!fs.existsSync(envPath)) {
  console.log('📝 Creating .env file...');
  const defaultEnv = 'DATABASE_URL="file:./dev.db"\nDAEMON_PORT=3001\n';
  fs.writeFileSync(envPath, defaultEnv);
} else {
  console.log('✅ .env file already exists.');
}

// Helper to run commands
const run = (command: string) => {
  try {
    console.log(`\n🏃 Running: ${command}`);
    execSync(command, { stdio: 'inherit', cwd: rootDir });
  } catch (error) {
    console.error(`❌ Error running command: ${command}`);
    process.exit(1);
  }
};

// 2. Install Dependencies
console.log('\n📦 Installing dependencies...');
run('npm install');

// 3. Database Sync
console.log('\n🗄️ Setting up database...');
run('npx prisma db push');

// 4. Generate Client
console.log('\n💎 Generating Prisma Client...');
run('npx prisma generate');

console.log('\n✨ Setup complete! You can now start the daemon with: npm run dev');
