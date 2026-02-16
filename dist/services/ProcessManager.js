"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.processManager = exports.ProcessManager = void 0;
const child_process_1 = require("child_process");
const events_1 = __importDefault(require("events"));
const winston_1 = __importDefault(require("winston"));
const logger = winston_1.default.createLogger({
    level: 'info',
    format: winston_1.default.format.combine(winston_1.default.format.timestamp(), winston_1.default.format.simple()),
    transports: [new winston_1.default.transports.Console()],
});
class ProcessManager extends events_1.default {
    processes = new Map();
    constructor() {
        super();
    }
    startServer(config) {
        if (this.processes.has(config.id)) {
            logger.warn(`Server ${config.id} is already running.`);
            return;
        }
        logger.info(`Starting server ${config.id}: ${config.command} ${config.args.join(' ')}`);
        const child = (0, child_process_1.spawn)(config.command, config.args, {
            cwd: config.cwd,
            shell: true,
            windowsHide: true,
        });
        this.processes.set(config.id, child);
        child.stdout?.on('data', (data) => {
            this.emit('console', { id: config.id, data: data.toString() });
        });
        child.stderr?.on('data', (data) => {
            this.emit('console', { id: config.id, data: data.toString(), type: 'error' });
        });
        child.on('close', (code) => {
            logger.info(`Server ${config.id} exited with code ${code}`);
            this.processes.delete(config.id);
            this.emit('status', { id: config.id, status: 'stopped', code });
        });
        child.on('error', (err) => {
            logger.error(`Failed to start server ${config.id}: ${err.message}`);
            this.processes.delete(config.id);
            this.emit('error', { id: config.id, error: err.message });
        });
        this.emit('status', { id: config.id, status: 'running' });
    }
    stopServer(id) {
        const child = this.processes.get(id);
        if (!child) {
            logger.warn(`Server ${id} is not running.`);
            return;
        }
        logger.info(`Stopping server ${id}...`);
        child.kill(); // On Windows, this might need a more aggressive approach for some processes
    }
    sendCommand(id, command) {
        const child = this.processes.get(id);
        if (!child || !child.stdin) {
            logger.warn(`Cannot send command to server ${id}: process not running or stdin not available.`);
            return;
        }
        child.stdin.write(`${command}\n`);
    }
}
exports.ProcessManager = ProcessManager;
exports.processManager = new ProcessManager();
