'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

const scanRoutes = require('./routes/scanRoutes');
const authRoutes = require('./routes/authRoutes');
const { healthCheck } = require('./controllers/scanController');
const { errorHandler, notFoundHandler } = require('./middleware/errorHandler');

function createApp() {
  const app = express();

app.use(helmet());

const corsOrigin = process.env.CORS_ORIGIN || '*';
app.use(cors({
    origin: corsOrigin === '*' ? true : corsOrigin.split(',').map((o) => o.trim()),
}));

app.use(express.json({ limit: '10kb' }));

app.disable('x-powered-by');

app.get('/health', healthCheck);

app.use(express.static('public'));

app.use('/api/auth', authRoutes);

app.use('/api', scanRoutes);

app.use(notFoundHandler);

app.use(errorHandler);

  return app;
}

module.exports = createApp;
