const fs = require('fs');
const path = require('path');
// Remove the circular dependency
// const { logApiRequest } = require('../db-operations');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Log file paths
const errorLogPath = path.join(logsDir, 'error.log');
const accessLogPath = path.join(logsDir, 'access.log');

// We'll store this function to avoid circular dependency
let dbLogApiRequest = null;

/**
 * Set the database logging function to avoid circular dependency
 * @param {Function} logFunction - The database logging function
 */
function setDbLogger(logFunction) {
  dbLogApiRequest = logFunction;
}

/**
 * Log error to file and database
 * @param {Error} error - The error object
 * @param {Object} requestInfo - Information about the request
 */
function logError(error, requestInfo = {}) {
  try {
    const timestamp = new Date().toISOString();
    const errorMessage = error.message || 'Unknown error';
    const stack = error.stack || '';
    
    // Format error log entry
    const logEntry = `[${timestamp}] ERROR: ${errorMessage}\n${stack}\nRequest: ${JSON.stringify(requestInfo)}\n\n`;
    
    // Append to error log file
    fs.appendFileSync(errorLogPath, logEntry);
    
    // Log to database if request info is available and dbLogApiRequest is set
    if (requestInfo.path && dbLogApiRequest) {
      dbLogApiRequest({
        endpoint: requestInfo.path,
        domain: requestInfo.domain || 'unknown',
        ipAddress: requestInfo.ip || 'unknown',
        statusCode: error.status || 500,
        responseTime: requestInfo.responseTime || 0,
        errorMessage
      }).catch(dbError => {
        console.error('Error logging to database:', dbError);
      });
    }
    
    // Log to console in development
    if (process.env.NODE_ENV !== 'production') {
      console.error(`[${timestamp}] ERROR:`, error);
    }
  } catch (logError) {
    // Fallback to console if file logging fails
    console.error('Error logging error:', logError);
    console.error('Original error:', error);
  }
}

/**
 * Log API access
 * @param {Object} requestInfo - Information about the request
 */
function logAccess(requestInfo) {
  try {
    const timestamp = new Date().toISOString();
    
    // Format access log entry
    const logEntry = `[${timestamp}] ${requestInfo.method} ${requestInfo.path} ${requestInfo.statusCode} ${requestInfo.responseTime}ms ${requestInfo.ip}\n`;
    
    // Append to access log file
    fs.appendFileSync(accessLogPath, logEntry);
    
    // Log to database for domain lookups if dbLogApiRequest is set
    if (requestInfo.domain && requestInfo.path.includes('/api/lookup') && dbLogApiRequest) {
      dbLogApiRequest({
        endpoint: requestInfo.path,
        domain: requestInfo.domain,
        ipAddress: requestInfo.ip,
        statusCode: requestInfo.statusCode,
        responseTime: requestInfo.responseTime,
        errorMessage: null
      }).catch(dbError => {
        console.error('Error logging to database:', dbError);
      });
    }
  } catch (logError) {
    // Fallback to console if file logging fails
    console.error('Error logging access:', logError);
  }
}

// Create a simple error logger object for use in db.js
const errorLogger = {
  error: (message, context = {}) => {
    logError(new Error(message), context);
  }
};

module.exports = {
  logError,
  logAccess,
  setDbLogger,
  errorLogger
}; 