'use strict';

const path = require('path');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const scanRoutes = require('./routes/scanRoutes');
const authRoutes = require('./routes/authRoutes');
const contactRoutes = require('./routes/contactRoutes');

const { healthCheck } = require('./controllers/scanController');
const {
  errorHandler,
  notFoundHandler,
} = require('./middleware/errorHandler');

function createApp() {
  const app = express();

  // Security headers
  app.use(helmet());

  // CORS
  const corsOrigin = process.env.CORS_ORIGIN || '*';

  app.use(
    cors({
      origin:
        corsOrigin === '*'
          ? true
          : corsOrigin.split(',').map((o) => o.trim()),
    })
  );

  // Request body parsing
  app.use(express.json({ limit: '10kb' }));

  // Hide Express fingerprint
  app.disable('x-powered-by');

  // Health check
  app.get('/health', healthCheck);

  // Serve frontend static files
  app.use(express.static(path.join(__dirname, '../public')));

  // API routes
  app.use('/api/auth', authRoutes);
  app.use('/api/contact', contactRoutes);
  app.use('/api', scanRoutes);

  // 404 handler
  app.use(notFoundHandler);

  // Global error handler
  app.use(errorHandler);

  return app;
}

module.exports = createApp;