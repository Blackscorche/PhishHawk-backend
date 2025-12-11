import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

class Logger {
  constructor() {
    this.logsDir = path.join(__dirname, '../logs');
    if (!fs.existsSync(this.logsDir)) {
      fs.mkdirSync(this.logsDir, { recursive: true });
    }

    this.logFile = path.join(this.logsDir, `app-${this.getDateString()}.log`);
  }

  getDateString() {
    return new Date().toISOString().split('T')[0];
  }

  formatMessage(level, message, ...args) {
    const timestamp = new Date().toISOString();
    const formattedArgs = args.length > 0 ? ' ' + args.map(arg =>
      typeof arg === 'object' ? JSON.stringify(arg, null, 2) : String(arg)
    ).join(' ') : '';
    return `[${timestamp}] [${level}] ${message}${formattedArgs}\n`;
  }

  log(level, message, ...args) {
    const formatted = this.formatMessage(level, message, ...args);
    process.stdout.write(formatted);

    try {
      fs.appendFileSync(this.logFile, formatted);
    } catch (error) {
      console.error('Failed to write to log file:', error);
    }
  }

  info(message, ...args) {
    this.log('INFO', message, ...args);
  }

  error(message, ...args) {
    this.log('ERROR', message, ...args);
  }

  warn(message, ...args) {
    this.log('WARN', message, ...args);
  }

  debug(message, ...args) {
    if (process.env.NODE_ENV === 'development') {
      this.log('DEBUG', message, ...args);
    }
  }
}

export const logger = new Logger();
