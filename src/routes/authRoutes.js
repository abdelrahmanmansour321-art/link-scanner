'use strict';

const express = require('express');
const { signup, login, logout, me } = require('../controllers/authController');
const { authenticateUser } = require('../middleware/authentication');

const router = express.Router();

router.post('/signup', signup);
router.post('/login', login);
router.post('/logout', logout);
router.get('/me', authenticateUser, me);

module.exports = router;
