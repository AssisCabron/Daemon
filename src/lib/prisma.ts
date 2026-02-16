import { PrismaClient } from '@prisma/client';
import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';

const url = process.env.DATABASE_URL || 'file:./prisma/dev.db';

const adapter = new PrismaBetterSqlite3({ url });

export const prisma = new PrismaClient({ adapter });
