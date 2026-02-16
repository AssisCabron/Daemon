"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SetupService = void 0;
const client_1 = require("@prisma/client");
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const prisma = new client_1.PrismaClient();
const LOCK_FILE = path_1.default.join(process.cwd(), '.setup_lock');
class SetupService {
    static isSetupComplete() {
        return fs_1.default.existsSync(LOCK_FILE);
    }
    static async completeSetup(adminData) {
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
        fs_1.default.writeFileSync(LOCK_FILE, JSON.stringify({ completedAt: new Date(), adminId: admin.id }));
        return admin;
    }
}
exports.SetupService = SetupService;
