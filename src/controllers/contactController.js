'use strict';

const validator = require('validator');
const { log } = require('../utils/helpers');

async function submitContact(req, res, next) {
  const { name, email, message } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_NAME',
        message: 'Name is required.',
      },
    });
  }

  if (!email || typeof email !== 'string' || !validator.isEmail(email.trim())) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'INVALID_EMAIL',
        message: 'A valid email address is required.',
      },
    });
  }

  if (!message || typeof message !== 'string' || !message.trim()) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_MESSAGE',
        message: 'Message content is required.',
      },
    });
  }

  try {
    log('info', 'contact.submitted', {
      name: name.trim(),
      email: email.trim(),
      messageLength: message.trim().length,
    });

    return res.status(200).json({
      success: true,
      message: 'Thank you for your message! We have received your inquiry and will respond shortly.',
    });
  } catch (err) {
    log('error', 'contact.submission_error', { message: err.message });
    return next(err);
  }
}

module.exports = { submitContact };
