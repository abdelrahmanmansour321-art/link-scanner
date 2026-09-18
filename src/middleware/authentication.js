'use strict';

const { getSupabaseClient } = require('../services/supabaseClient');
const { log } = require('../utils/helpers');

async function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required. Missing or malformed Authorization header.',
      },
    });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication required. Token not provided.',
      },
    });
  }

  try {
    const supabase = getSupabaseClient();
    const { data: { user }, error } = await supabase.auth.getUser(token);

    if (error || !user) {
      log('error', 'auth.unauthorized', { message: error?.message || 'Invalid token or session' });
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: 'Authentication required. Invalid or expired token.',
        },
      });
    }

    req.user = user;
    return next();
  } catch (err) {
    log('error', 'auth.error', { message: err.message });
    return res.status(401).json({
      success: false,
      error: {
        code: 'UNAUTHORIZED',
        message: 'Authentication failed.',
      },
    });
  }
}

module.exports = { authenticateUser };
