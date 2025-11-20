// src/routes/auth.js
const express = require('express');
const { body } = require('express-validator');
const router = express.Router();
const controller = require('../controllers/authController');

// register
router.post('/register',
  [
    body('name').isLength({ min: 2 }).trim().withMessage('Name is required'),
    body('email').isEmail().normalizeEmail().withMessage('Valid email required'),
    body('password').isLength({ min: 6 }).withMessage('Password min 6 chars'),
    body('role').isIn(['farm_worker', 'farm_owner', 'analyst', 'supervisor']).withMessage('Invalid role')
  ],
  controller.register
);

// login
router.post('/login',
  [
    body('email').isEmail().normalizeEmail(),
    body('password').isString().notEmpty()
  ],
  controller.login
);

// get me (protected)
router.get('/me', controller.authMiddleware, controller.me);

module.exports = router;
