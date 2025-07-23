const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Define custom log levels
const logLevels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// Define colors for each log level
const logColors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  http: 'magenta',
  debug: 'white',
};

winston.addColors(logColors);

// Define log format for files
const fileLogFormat = winston.format.combine(
  winston.format.timestamp(),
  winston.format.errors({ stack: true }),
  winston.format.json()
);

// Define transports (NO console transport here — handled below based on environment)
const transports = [
  // Error log file
  new winston.transports.File({
    filename: path.join(logsDir, 'error.log'),
    level: 'error',
    format: fileLogFormat,
  }),

  // Combined log file
  new winston.transports.File({
    filename: path.join(logsDir, 'combined.log'),
    format: fileLogFormat,
  }),
];

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  levels: logLevels,
  format: fileLogFormat,
  defaultMeta: { service: 'chatnest-backend' },
  transports,
  exceptionHandlers: [
    new winston.transports.File({ filename: path.join(logsDir, 'exceptions.log') }),
  ],
  rejectionHandlers: [
    new winston.transports.File({ filename: path.join(logsDir, 'rejections.log') }),
  ],
});

// ✅ Add console logging only in non-production environments
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.combine(
      winston.format.colorize(),
      winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss:ms' }),
      winston.format.printf(
        info => `${info.timestamp} ${info.level}: ${info.message}`
      )
    ),
  }));
}

module.exports = logger;
