'use strict';

require('dotenv').config();

const createApp = require('./src/app');
const { log } = require('./src/utils/helpers');
const { isConfigured } = require('./src/services/virusTotalService');
const { isConfigured: whoisConfigured } = require('./src/services/whoisService');

const PORT = process.env.PORT || 3000;

const app = createApp();

let server = null;

if (process.env.NODE_ENV !== 'production' && !process.env.VERCEL) {
  server = app.listen(PORT, () => {
    log('info', 'server.started', { port: PORT, env: process.env.NODE_ENV || 'development' });
    // eslint-disable-next-line no-console
    console.log(`Link Scanner Backend listening on http://localhost:${PORT}`);
    if (!isConfigured()) {
      // eslint-disable-next-line no-console
      console.warn('VIRUSTOTAL_API_KEY is not set. VirusTotal checks will be reported as unavailable; the local Threat Engine will still run.');
    }
    if (!whoisConfigured()) {
      // eslint-disable-next-line no-console
      console.warn('WHOIS_API_KEY is not set. WHOIS checks will be reported as unavailable.');
    }
  });

  process.on('SIGTERM', () => {
    log('info', 'server.shutdown', { signal: 'SIGTERM' });
    if (server) server.close(() => process.exit(0));
  });
  process.on('SIGINT', () => {
    log('info', 'server.shutdown', { signal: 'SIGINT' });
    if (server) server.close(() => process.exit(0));
  });
}

module.exports = app;
