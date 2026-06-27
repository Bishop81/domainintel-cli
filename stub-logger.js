/**
 * Stderr-only replacement for lib/utils/errorLogger.js, used in the bundled
 * CLI package. The real logger writes to a logs/ directory, which is wrong for
 * a globally-installed CLI, so everything here goes to stderr instead.
 */
function logError(error, context = {}) {
  const msg = (error && error.message) || String(error);
  console.error(`[@domainintel/cli] error: ${msg}`, context && Object.keys(context).length ? context : '');
}

function logAccess() {
  // No-op: access logging is a web-app concern, not relevant to the CLI.
}

function setDbLogger() {
  // No-op: the CLI has no database.
}

const errorLogger = {
  error: (message, context = {}) => logError(new Error(message), context)
};

module.exports = { logError, logAccess, setDbLogger, errorLogger };
