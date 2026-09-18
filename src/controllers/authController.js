'use strict';

const { getSupabaseClient } = require('../services/supabaseClient');
const { log } = require('../utils/helpers');

async function signup(req, res, next) {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Email and password are required for registration.',
      },
    });
  }

  try {
    const supabase = getSupabaseClient();
    const { data, error } = await supabase.auth.signUp({ email, password });

    if (error) {
      log('error', 'auth.signup_failed', { message: error.message });
      return res.status(400).json({
        success: false,
        error: {
          code: 'SIGNUP_FAILED',
          message: error.message,
        },
      });
    }

    return res.status(201).json({
      success: true,
      data: {
        user: data.user ? { id: data.user.id, email: data.user.email } : null,
        session: data.session ? {
          accessToken: data.session.access_token,
          refreshToken: data.session.refresh_token,
          expiresIn: data.session.expires_in,
        } : null,
        message: 'Account created successfully. Please check your email for confirmation if required by Supabase settings.',
      },
    });
  } catch (err) {
    log('error', 'auth.signup_error', { message: err.message });
    return next(err);
  }
}

async function login(req, res, next) {
  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'VALIDATION_ERROR',
        message: 'Email and password are required for login.',
      },
    });
  }

  try {
    const supabase = getSupabaseClient();
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });

    if (error || !data.session) {
      log('error', 'auth.login_failed', { message: error?.message || 'Invalid credentials' });
      return res.status(401).json({
        success: false,
        error: {
          code: 'UNAUTHORIZED',
          message: error?.message || 'Invalid email or password.',
        },
      });
    }

    return res.status(200).json({
      success: true,
      data: {
        user: { id: data.user.id, email: data.user.email },
        session: {
          accessToken: data.session.access_token,
          refreshToken: data.session.refresh_token,
          expiresIn: data.session.expires_in,
        },
      },
    });
  } catch (err) {
    log('error', 'auth.login_error', { message: err.message });
    return next(err);
  }
}

async function logout(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.split(' ')[1];
      const supabase = getSupabaseClient();
      // create client scoped to token if needed or call signOut
      await supabase.auth.signOut();
    }
    return res.status(200).json({
      success: true,
      message: 'Logged out successfully.',
    });
  } catch (err) {
    log('error', 'auth.logout_error', { message: err.message });
    return next(err);
  }
}

async function me(req, res) {
  return res.status(200).json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      createdAt: req.user.created_at,
    },
  });
}

module.exports = { signup, login, logout, me };
