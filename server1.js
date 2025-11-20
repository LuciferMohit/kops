/**
 * server.js
 * Minimal backend for your login/register page.
 *
 * - Serves static frontend from ./public
 * - Provides /api/auth/register and /api/auth/login
 * - Simple JSON file persistence (demo_data.json)
 * - Serves uploaded image (user-provided) at /assets/icon.png
 *
 * Run:
 *   npm init -y
 *   npm i express fs-extra bcryptjs jsonwebtoken body-parser cors cookie-parser uuid
 *   node server.js
 *
 * Then open: http://localhost:4000/login.html  (or /)
 */

const express = require('express');
const fs = require('fs-extra');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { v4: uuidv4 } = require('uuid');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'dev_jwt_secret_change_me';
const DATA_FILE = path.join(__dirname, 'demo_data.json');

// IMPORTANT: user-supplied uploaded file path (from your workspace)
// Developer instruction: use the uploaded file path from history as-is.
const UPLOADED_ICON_PATH = '/mnt/data/19b3c913-c824-4860-862c-ec0419d227fb.png';

const app = express();

// middlewares
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json({ limit: '5mb' }));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

// minimal security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  next();
});

// serve static frontend (drop your login/register HTML into ./public)
// Example: public/login.html should contain the HTML you pasted earlier
const PUBLIC_DIR = path.join(__dirname, 'public');
fs.ensureDirSync(PUBLIC_DIR);
app.use(express.static(PUBLIC_DIR));

// serve the uploaded image at a friendly route so frontend can reference it
app.get('/assets/icon.png', (req, res) => {
  // Serve the local uploaded file. If not found, return 404.
  const p = UPLOADED_ICON_PATH;
  fs.pathExists(p).then(exists => {
    if (!exists) {
      return res.status(404).send('Icon not found on server');
    }
    res.sendFile(p, err => {
      if (err) {
        console.error('Error sending uploaded icon:', err);
        if (!res.headersSent) res.status(500).end();
      }
    });
  }).catch(err => {
    console.error(err);
    res.status(500).end();
  });
});

// --- simple JSON store helpers ---
const defaultData = {
  users: [],        // { id, name, email, phone, password_hash, role, role_meta, verified, created_at }
  gigs: [],         // placeholder for future use
  notifications: []
};

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8');
      const parsed = JSON.parse(raw);
      // ensure keys exist
      const data = Object.assign({}, defaultData, parsed);
      return data;
    } else {
      // create file with seed user
      const now = new Date().toISOString();
      const seedPassHash = bcrypt.hashSync('password', 8);
      const seed = {
        users: [
          { id: 'u1', name: 'Raju Worker', email: 'raju@example.com', phone: '9000000001', password_hash: seedPassHash, role: 'farm_worker', role_meta: { worker_id: 'WKR-001' }, verified: true, created_at: now },
          { id: 'u2', name: 'Sita Owner', email: 'sita@example.com', phone: '9000000002', password_hash: bcrypt.hashSync('password',8), role: 'farm_owner', role_meta: { farm_name: 'Sita Farms' }, verified: true, created_at: now }
        ],
        gigs: [],
        notifications: []
      };
      fs.writeFileSync(DATA_FILE, JSON.stringify(seed, null, 2), 'utf8');
      return seed;
    }
  } catch (e) {
    console.error('Failed to load data file:', e);
    return Object.assign({}, defaultData);
  }
}

function saveData(data) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
  } catch (e) {
    console.error('Failed to save data file:', e);
  }
}

let STORE = loadData();

// helper: find user by email (case-insensitive)
function findUserByEmail(email) {
  if (!email) return null;
  return STORE.users.find(u => u.email && u.email.toLowerCase() === email.toLowerCase());
}

function getUserById(id) {
  return STORE.users.find(u => u.id === id);
}

function signToken(user) {
  return jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// auth middleware
function authMiddleware(req, res, next) {
  const header = req.headers.authorization || req.cookies['gigi_token'];
  if (!header) return res.status(401).json({ error: 'Missing auth token' });
  const token = header.startsWith('Bearer ') ? header.split(' ')[1] : header;
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid token' });
  const user = getUserById(payload.userId);
  if (!user) return res.status(401).json({ error: 'User not found' });
  req.user = user;
  next();
}

// --- API endpoints ---

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, phone, password, role, role_meta } = req.body;
    if (!name || !email || !password || !role) return res.status(400).json({ error: 'Missing required fields' });
    if (findUserByEmail(email)) return res.status(409).json({ error: 'Email already registered' });

    const id = 'u_' + uuidv4().split('-')[0];
    const password_hash = bcrypt.hashSync(password, 8);
    const newUser = {
      id, name, email, phone: phone || null, password_hash,
      role, role_meta: role_meta || {}, verified: false,
      created_at: new Date().toISOString()
    };
    STORE.users.push(newUser);
    saveData(STORE);

    // mock email-verification notification
    STORE.notifications.push({ id: 'n_' + uuidv4().split('-')[0], user_id: id, type: 'email_verification', payload: { token: 'mock-verif-token' }, read: false, created_at: new Date().toISOString() });
    saveData(STORE);

    // return minimal user + token
    const token = signToken(newUser);
    return res.status(201).json({ user: { id: newUser.id, name: newUser.name, email: newUser.email, role: newUser.role, role_meta: newUser.role_meta }, token });
  } catch (e) {
    console.error('Register error', e);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Missing credentials' });
    const user = findUserByEmail(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    if (!bcrypt.compareSync(password, user.password_hash)) return res.status(401).json({ error: 'Invalid credentials' });
    if (!user.verified) {
      // For demo: allow login but warn — or change behavior as desired
      // return res.status(403).json({ error: 'Email not verified' });
    }
    const token = signToken(user);
    return res.json({ token, user: { id: user.id, name: user.name, email: user.email, role: user.role, role_meta: user.role_meta } });
  } catch (e) {
    console.error('Login error', e);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// Protected profile endpoint
app.get('/api/users/me', authMiddleware, (req, res) => {
  const u = req.user;
  res.json({ id: u.id, name: u.name, email: u.email, role: u.role, role_meta: u.role_meta });
});

// small OpenAPI stub
app.get('/openapi.yaml', (req,res) => {
  const yaml = `
openapi: 3.0.3
info:
  title: GigiFarm Demo API
  version: "0.1"
paths:
  /api/auth/register:
    post:
      summary: Register user
  /api/auth/login:
    post:
      summary: Login user
  /api/users/me:
    get:
      summary: Current user profile (JWT)
`;
  res.type('text/yaml').send(yaml);
});

// health
app.get('/health', (req,res) => res.json({ ok: true }));

// fallback for SPA (serve index or leave static routing to nginx in prod)
app.get('/', (req,res) => {
  const indexPath = path.join(PUBLIC_DIR, 'index.html');
  if (fs.existsSync(indexPath)) return res.sendFile(indexPath);
  res.send('GigiFarm backend running. Place your frontend files in ./public and visit /login.html');
});

// graceful shutdown: persist STORE
process.on('SIGINT', () => {
  console.log('SIGINT: saving data and exiting');
  saveData(STORE);
  process.exit(0);
});

// Start server
app.listen(PORT, () => {
  console.log(`GigiFarm backend running at http://localhost:${PORT}`);
  console.log('Data file:', DATA_FILE);
  console.log('Serving static files from:', PUBLIC_DIR);
  console.log('Uploaded icon mapped at: http://localhost:' + PORT + '/assets/icon.png (serves ' + UPLOADED_ICON_PATH + ')');
});
