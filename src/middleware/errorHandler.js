'use strict';

const { log } = require('../utils/helpers');
const { UrlValidationError } = require('../services/urlAnalysisService');
const multer = require('multer');

const CODE_TO_STATUS = {
  MISSING_URL: 400,
  EMPTY_URL: 400,
  INVALID_URL: 400,
  URL_TOO_LONG: 400,
  MALFORMED_URL: 400,
  UNSUPPORTED_PROTOCOL: 400,
  CREDENTIALS_IN_URL: 400,
  SSRF_BLOCKED: 400,
  DNS_RESOLUTION_FAILED: 400,
  INVALID_REQUEST_BODY: 400,
};

function notFoundHandler(req, res) {
  res.status(404).json({
    success: false,
    error: {
      code: 'NOT_FOUND',
      message: `Route ${req.method} ${req.originalUrl} does not exist.`,
    },
  });
}

function errorHandler(err, req, res, next) {
  if (err.type === 'entity.parse.failed' || err instanceof SyntaxError) {
    log('error', 'request.malformed_json', { path: req.originalUrl });
    return res.status(400).json({
      success: false,
      error: {
        code: 'MALFORMED_JSON',
        message: 'The request body is not valid JSON.',
      },
    });
  }

  if (err.type === 'entity.too.large' || err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      success: false,
      error: {
        code: 'PAYLOAD_TOO_LARGE',
        message: 'Request body or file exceeds the maximum allowed size.',
      },
    });
  }

  if (err instanceof UrlValidationError) {
    const status = CODE_TO_STATUS[err.code] || 400;
    log('info', 'scan.validation_error', { code: err.code, path: req.originalUrl });
    return res.status(status).json({
      success: false,
      error: {
        code: err.code,
        message: err.message,
      },
    });
  }

  log('error', 'request.unhandled_error', {
    path: req.originalUrl,
    message: err.message,
  });

  return res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected error occurred. Please try again later.',
    },
  });
}

module.exports = { errorHandler, notFoundHandler };
