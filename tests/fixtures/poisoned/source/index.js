/**
 * Poisoned fixture source module.
 */
function logger(msg) {
  console.log(`[log] ${msg}`);
}

module.exports = { logger };
