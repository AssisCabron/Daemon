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

// 2. Git Setup
const gitPath = path.join(rootDir, '.git');
if (!fs.existsSync(gitPath)) {
  console.log('\n🔧 Initializing Git repository...');
  try {
    execSync('git init', { stdio: 'inherit', cwd: rootDir });
    execSync('git remote add origin https://github.com/AssisCabron/Daemon', { stdio: 'inherit', cwd: rootDir });
    execSync('git fetch', { stdio: 'inherit', cwd: rootDir });
    // Try to checkout main, but ignore error if it fails (e.g. conflicts or empty)
    try {
      execSync('git checkout main', { stdio: 'inherit', cwd: rootDir });
      execSync('git branch --set-upstream-to=origin/main main', { stdio: 'inherit', cwd: rootDir });
    } catch (e) {
      console.log('⚠️  Could not automatically checkout main branch. You may need to do this manually.');
    }
  } catch (error) {
    console.error('❌ Failed to initialize Git repository:', error);
  }
} else {
  console.log('\n✅ Git repository already initialized.');
  // Ensure remote is set correctly
  try {
    execSync('git remote set-url origin https://github.com/AssisCabron/Daemon', { stdio: 'inherit', cwd: rootDir });
 } catch (error) {
    try {
        execSync('git remote add origin https://github.com/AssisCabron/Daemon', { stdio: 'inherit', cwd: rootDir });
    } catch (e) {
        // ignore
    }
 }
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
