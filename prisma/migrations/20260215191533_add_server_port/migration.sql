-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Server" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "command" TEXT NOT NULL,
    "args" TEXT NOT NULL,
    "cwd" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'stopped',
    "memory" INTEGER NOT NULL DEFAULT 1024,
    "cpu" INTEGER NOT NULL DEFAULT 100,
    "disk" INTEGER NOT NULL DEFAULT 10240,
    "port" INTEGER NOT NULL DEFAULT 25565,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "ownerId" TEXT,
    "nodeId" TEXT,
    "eggId" TEXT,
    CONSTRAINT "Server_ownerId_fkey" FOREIGN KEY ("ownerId") REFERENCES "User" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Server_nodeId_fkey" FOREIGN KEY ("nodeId") REFERENCES "Node" ("id") ON DELETE SET NULL ON UPDATE CASCADE,
    CONSTRAINT "Server_eggId_fkey" FOREIGN KEY ("eggId") REFERENCES "Egg" ("id") ON DELETE SET NULL ON UPDATE CASCADE
);
INSERT INTO "new_Server" ("args", "command", "createdAt", "cwd", "eggId", "id", "name", "nodeId", "ownerId", "status") SELECT "args", "command", "createdAt", "cwd", "eggId", "id", "name", "nodeId", "ownerId", "status" FROM "Server";
DROP TABLE "Server";
ALTER TABLE "new_Server" RENAME TO "Server";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
