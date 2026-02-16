"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const http_1 = require("http");
const socket_io_1 = require("socket.io");
const cors_1 = __importDefault(require("cors"));
const dotenv_1 = __importDefault(require("dotenv"));
const winston_1 = __importDefault(require("winston"));
const ProcessManager_1 = require("./services/ProcessManager");
dotenv_1.default.config();
const logger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.json()),
    transports: [
        new winston_1.default.transports.Console({
            format: winston_1.default.format.combine(winston_1.default.format.colorize(), winston_1.default.format.simple()),
        }),
    ],
});
const SetupService_1 = require("./services/SetupService");
const app = (0, express_1.default)();
const httpServer = (0, http_1.createServer)(app);
const io = new socket_io_1.Server(httpServer, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});
app.use((0, cors_1.default)());
app.use(express_1.default.json());
app.get('/api/setup/status', (req, res) => {
    res.json({ isSetupComplete: SetupService_1.SetupService.isSetupComplete() });
});
app.post('/api/setup/complete', async (req, res) => {
    try {
        const admin = await SetupService_1.SetupService.completeSetup(req.body);
        res.json({ message: 'Setup completed successfully', admin: { id: admin.id, username: admin.username } });
    }
    catch (err) {
        res.status(400).json({ error: err.message });
    }
});
// Middleware to block API if setup not complete (except the setup endpoints)
app.use((req, res, next) => {
    if (!SetupService_1.SetupService.isSetupComplete() && !req.path.startsWith('/api/setup')) {
        return res.status(403).json({ error: 'System setup required' });
    }
    next();
});
// API Endpoints
app.post('/api/servers/:id/start', (req, res) => {
    const { id } = req.params;
    const { command, args, cwd } = req.body;
    ProcessManager_1.processManager.startServer({ id, command, args, cwd });
    res.json({ message: 'Server start sequence initiated' });
});
app.post('/api/servers/:id/stop', (req, res) => {
    const { id } = req.params;
    ProcessManager_1.processManager.stopServer(id);
    res.json({ message: 'Server stop sequence initiated' });
});
app.post('/api/servers/:id/command', (req, res) => {
    const { id } = req.params;
    const { command } = req.body;
    ProcessManager_1.processManager.sendCommand(id, command);
    res.json({ message: 'Command sent' });
});
app.get('/health', (req, res) => {
    res.json({ status: 'ok', platform: process.platform });
});
// WebSocket Integration
ProcessManager_1.processManager.on('console', (data) => {
    io.to(data.id).emit('console', data);
});
ProcessManager_1.processManager.on('status', (data) => {
    io.to(data.id).emit('status', data);
});
io.on('connection', (socket) => {
    logger.info(`New client connected: ${socket.id}`);
    socket.on('join', (serverId) => {
        socket.join(serverId);
        logger.info(`Client ${socket.id} joined room ${serverId}`);
    });
    socket.on('disconnect', () => {
        logger.info(`Client disconnected: ${socket.id}`);
    });
});
const PORT = process.env.DAEMON_PORT || 3001;
httpServer.listen(PORT, () => {
    logger.info(`RexDaemon running on port ${PORT}`);
});
