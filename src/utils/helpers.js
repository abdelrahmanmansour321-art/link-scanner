'use strict';

const crypto = require('crypto');

/**
 * Generates a unique scan ID, e.g. "scan_1a2b3c4d5e6f..."
 */
function generateScanId() {
  return `scan_${crypto.randomUUID().replace(/-/g, '')}`;
}

/**
 * Simple structured logger. Never logs secrets.
 * Usage: log('info', 'scan.started', { scanId, url })
 */
function log(level, event, meta = {}) {
  const safeMeta = { ...meta };
  // Defensive redaction in case a caller accidentally passes a secret-ish key.
  const REDACT_KEYS = ['apikey', 'api_key', 'authorization', 'token', 'secret', 'password'];
  for (const key of Object.keys(safeMeta)) {
    if (REDACT_KEYS.includes(key.toLowerCase())) {
      safeMeta[key] = '[REDACTED]';
    }
  }
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    event,
    ...safeMeta,
  };
  const line = JSON.stringify(entry);
  if (level === 'error') {
    // eslint-disable-next-line no-console
    console.error(line);
  } else {
    // eslint-disable-next-line no-console
    console.log(line);
  }
}

/**
 * Clamp a number between min and max.
 */
function clamp(value, min, max) {
  return Math.max(min, Math.min(max, value));
}

module.exports = {
  generateScanId,
  log,
  clamp,
};
