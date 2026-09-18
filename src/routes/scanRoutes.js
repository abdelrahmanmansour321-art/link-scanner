'use strict';

const express = require('express');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { scanUrl, scanFile } = require('../controllers/scanController');
const { validateScanRequestBody } = require('../middleware/validation');
const { authenticateUser } = require('../middleware/authentication');

const router = express.Router();
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 } // 5MB limit
});

const scanRateLimiter = rateLimit({
  windowMs: Number(process.env.RATE_LIMIT_WINDOW_MS) || 60000,
  max: Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: 'Too many scan requests. Please try again later.',
    },
  },
});

router.post(
  '/scan',
  authenticateUser,
  scanRateLimiter,
  validateScanRequestBody,
  scanUrl
);

router.post(
  '/scan/file',
  authenticateUser,
  scanRateLimiter,
  upload.single('file'),
  scanFile
);

module.exports = router;
