// src/controllers/authController.js
const { validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../db');

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret';
const JWT_EXPIRY = process.env.JWT_EXPIRY || '7d';
const SALT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '10', 10);

// Helper: create JWT
function createToken(payload){
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

// Middleware to verify JWT
async function authMiddleware(req, res, next){
  try{
    const auth = req.headers.authorization;
    if(!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    const token = auth.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  }catch(err){
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// Register controller
async function register(req, res){
  const errors = validationResult(req);
  if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { name, email, password, phone, role, role_meta } = req.body;
  // role_meta expected as object (frontend should send JSON)
  const roleMetaJson = role_meta && typeof role_meta === 'object' ? JSON.stringify(role_meta) : (role_meta || null);

  try{
    const conn = await pool.getConnection();
    try{
      const [existing] = await conn.query('SELECT id FROM users WHERE email = ?', [email]);
      if(existing.length > 0){
        return res.status(409).json({ error: 'Email already registered' });
      }
      const password_hash = await bcrypt.hash(password, SALT_ROUNDS);
      const now = new Date();

      const [result] = await conn.query(
        'INSERT INTO users (name, email, phone, password_hash, role, role_meta, verified, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
        [name, email, phone || null, password_hash, role, roleMetaJson, false, now, now]
      );

      const id = result.insertId;
      const token = createToken({ id, email, role });

      return res.status(201).json({ id, name, email, role, token, message: 'Registered. Please verify email (mock).' });
    } finally {
      conn.release();
    }
  }catch(err){
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
}

// Login controller
async function login(req, res){
  const errors = validationResult(req);
  if(!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

  const { email, password } = req.body;
  try{
    const conn = await pool.getConnection();
    try{
      const [rows] = await conn.query('SELECT id, name, email, password_hash, role, role_meta, verified FROM users WHERE email = ?', [email]);
      if(rows.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

      const user = rows[0];
      const ok = await bcrypt.compare(password, user.password_hash);
      if(!ok) return res.status(401).json({ error: 'Invalid credentials' });

      if(!user.verified){
        // For demo, allow login only if verified. Frontend has mock verify button.
        return res.status(403).json({ error: 'Email not verified' });
      }

      const token = createToken({ id: user.id, email: user.email, role: user.role });
      return res.json({
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        role_meta: user.role_meta ? JSON.parse(user.role_meta) : null,
        token
      });
    } finally {
      conn.release();
    }
  }catch(err){
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
}

// ME controller
async function me(req, res){
  const userId = req.user?.id;
  if(!userId) return res.status(401).json({ error: 'Unauthorized' });

  try{
    const conn = await pool.getConnection();
    try{
      const [rows] = await conn.query('SELECT id, name, email, phone, role, role_meta, verified, created_at FROM users WHERE id = ?', [userId]);
      if(rows.length === 0) return res.status(404).json({ error: 'Not found' });
      const u = rows[0];
      res.json({
        id: u.id, name: u.name, email: u.email, phone: u.phone,
        role: u.role,
        role_meta: u.role_meta ? JSON.parse(u.role_meta) : null,
        verified: !!u.verified,
        created_at: u.created_at
      });
    } finally {
      conn.release();
    }
  }catch(err){
    console.error(err);
    return res.status(500).json({ error: 'Server error' });
  }
}

module.exports = {
  register,
  login,
  me,
  authMiddleware
};
