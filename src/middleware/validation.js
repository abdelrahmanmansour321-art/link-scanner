'use strict';

function validateScanRequestBody(req, res, next) {
  const body = req.body;

  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'INVALID_REQUEST_BODY',
        message: 'Request body must be a JSON object.',
      },
    });
  }

  if (!('url' in body)) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_URL',
        message: 'A "url" field is required in the request body.',
      },
    });
  }

  return next();
}

module.exports = { validateScanRequestBody };
