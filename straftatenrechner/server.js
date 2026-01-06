require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const cookieParser = require('cookie-parser');

const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==================== AUTO-GENERATE SESSION SECRET ====================
// If no SESSION_SECRET is in .env, generate one and save it.
const envPath = path.join(__dirname, '.env');
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET === 'straftatenrechner-secret-key-change-me') {
  console.log('⚠️  No secure SESSION_SECRET found. Generating a new one...');
  try {
    const newSecret = crypto.randomBytes(64).toString('hex');
    process.env.SESSION_SECRET = newSecret;

    let envContent = fs.existsSync(envPath) ? fs.readFileSync(envPath, 'utf8') : '';
    if (envContent.includes('SESSION_SECRET=')) {
      envContent = envContent.replace(/SESSION_SECRET=.*/g, `SESSION_SECRET=${newSecret}`);
    } else {
      if (envContent && !envContent.endsWith('\n')) envContent += '\n';
      envContent += `SESSION_SECRET=${newSecret}\n`;
    }
    fs.writeFileSync(envPath, envContent);
    console.log('✅ Generated and saved new SESSION_SECRET to .env');
  } catch (err) {
    console.error('❌ Failed to save SESSION_SECRET to .env:', err);
    // Fallback to memory-only secret if file write fails (better than default)
    process.env.SESSION_SECRET = crypto.randomBytes(64).toString('hex');
  }
}

// Create HTTP server for both Express and WebSocket
const server = http.createServer(app);

// Configuration
const LICENSE_KEY = process.env.LICENSE_KEY || 'LICENSE-XNVH-OPEO-IP5Z';
let LICENSE_ADMIN_USER_ID = null;
let IS_LICENSE_VALID = false;
let LICENSE_ERROR_MSG = '';
const NEXUS_URL = 'https://nexus.zm0kie.de';

// License Validation
async function validateLicense() {
  console.log('Validating license against Nexus...');
  try {
    const response = await fetch(`${NEXUS_URL}/api/v1/license/validate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        license_key: LICENSE_KEY,
        module_slug: process.env.MODULE_SLUG || 'straftatenrechner'
      })
    });

    if (!response.ok) {
      const text = await response.text();
      try {
        const error = JSON.parse(text);
        throw new Error(error.message || 'License validation failed');
      } catch (e) {
        throw new Error(text);
      }
    }

    const data = await response.json();
    if (!data.valid) {
      throw new Error('License is invalid');
    }

    // Store admin user ID if present
    if (data.admin_user_id) {
      LICENSE_ADMIN_USER_ID = data.admin_user_id;
      // console.log(`🔑 License Admin User ID set to: ${LICENSE_ADMIN_USER_ID}`);
    }

    console.log('✅ License validated successfully via Nexus');
    IS_LICENSE_VALID = true;
    return true;
  } catch (error) {
    console.error('❌ LICENSE ERROR:', error.message);
    IS_LICENSE_VALID = false;
    LICENSE_ERROR_MSG = error.message;
    // Do NOT exit process, just mark invalid
  }
}

// Check license every 10 seconds
setInterval(validateLicense, 10 * 1000);

// Trust Proxy (Required for secure cookies behind Nginx/Apache)
app.set('trust proxy', 1);

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(session({
  secret: process.env.SESSION_SECRET || 'straftatenrechner-secret-key-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true, // Force Secure Cookies (Requires HTTPS)
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Authentication Middleware
const authMiddleware = async (req, res, next) => {
  // 1. Always allow public access to calculator page and assets
  if (req.method === 'GET' && (
    req.path === '/' ||
    req.path === '/index.html' ||
    req.path === '/login' ||
    req.path === '/login.html' ||
    req.path.startsWith('/css/') ||
    req.path.startsWith('/js/') ||
    req.path.startsWith('/api/laws') ||     // Public read access to laws
    req.path.startsWith('/api/law-categories') || // Public read access to categories
    req.path.startsWith('/api/calc-sessions') || // Public join/read sessions
    req.path === '/api/user' // Check user status is public (returns null if empty)
  )) {
    res.locals.user = req.session ? req.session.user : null;
    return next();
  }

  // 2. Allow login API
  if (req.path === '/api/auth/login' && req.method === 'POST') {
    return next();
  }

  // 3. Allow session creation and updates (Public)
  if (req.path.startsWith('/api/calc-sessions') && (req.method === 'POST' || req.method === 'PUT')) {
    return next();
  }

  // 4. Allow reading settings (Public)
  if (req.path === '/api/settings' && req.method === 'GET') {
    return next();
  }

  // 5. Allow access to static assets (logos, images, etc.)
  if (req.path.startsWith('/assets/')) {
    return next();
  }

  // 6. Everything else (Admin pages, write APIs) is PROTECTED
  if (!req.session || !req.session.user) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: 'Unauthorized' });
    }
    return res.redirect('/login');
  }

  // Pass user info to response locals for potential use
  res.locals.user = req.session.user;
  next();
};

// Serve login page
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// API Endpoint for License Status (Public/No Auth)
app.get('/api/license-status', async (req, res) => {
  // If currently invalid, try to revalidate immediately
  if (!IS_LICENSE_VALID) {
    await validateLicense();
  }
  res.json({ valid: IS_LICENSE_VALID });
});

// License Protection Middleware
app.use((req, res, next) => {
  // 1. Allow license error page
  if (req.path === '/license-error') {
    return next();
  }

  // 2. Allow static assets (css, js, fonts) so error page renders nicely
  if (req.path.startsWith('/css/') || req.path.startsWith('/js/') || req.path.startsWith('/assets/')) {
    return next();
  }

  // 3. Block everything else if license is invalid
  if (!IS_LICENSE_VALID) {
    return res.redirect('/license-error');
  }

  next();
});

// Serve license error page
app.get('/license-error', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'license-error.html'));
});

// Protect all routes and static files
app.use(authMiddleware);
app.use(express.static(path.join(__dirname, 'public')));

// Login endpoint (Proxy to Nexus)
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Call Nexus API to verify credentials
    const response = await fetch('https://nexus.zm0kie.de/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (response.ok) {
      const user = data.user;

      // Grant admin rights if user matches the license admin
      if (LICENSE_ADMIN_USER_ID && user.id === LICENSE_ADMIN_USER_ID) {
        console.log(`User ${user.username} recognized as License Admin. Granting admin rights.`);
        user.is_admin = true;
      }

      req.session.user = user;
      req.session.save();
      res.json({ success: true, user: user });
    } else {
      res.status(401).json({ error: 'Ungültige Zugangsdaten' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Verbindungsfehler zum Auth-Server' });
  }
});

// Logout route
app.get('/auth/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Logout error:', err);
    res.clearCookie('connect.sid'); // Force clear cookie
    res.redirect('/'); // Redirect to Home (Guest Mode)
  });
});

// API endpoint to get current user info
app.get('/api/user', (req, res) => {
  if (req.session && req.session.user) {
    res.json(req.session.user);
  } else {
    res.json(null); // Explicit null for guests
  }
});

// Data directory for database
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Single application database
const dbPath = path.join(dataDir, 'app.db');
const db = new Database(dbPath);

// Initialize application tables
db.exec(`
    CREATE TABLE IF NOT EXISTS laws (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category TEXT NOT NULL,
      paragraph TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      fine_min INTEGER DEFAULT 0,
      fine_max INTEGER DEFAULT 0,
      jail_min INTEGER DEFAULT 0,
      jail_max INTEGER DEFAULT 0,
      points INTEGER DEFAULT 0,
      is_felony INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

db.exec(`
    CREATE TABLE IF NOT EXISTS law_categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      sort_order INTEGER DEFAULT 0
    )
  `);

db.exec(`
    CREATE TABLE IF NOT EXISTS calc_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      selected_offenses TEXT DEFAULT '[]',
      modifiers TEXT DEFAULT '{}',
      notes TEXT DEFAULT '',
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

// Insert default laws if empty
const lawCount = db.prepare('SELECT COUNT(*) as count FROM laws').get().count;
if (lawCount === 0) {
  console.log('Inserting default laws...');
  insertDefaultLaws(db);
}

db.exec(`
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);

// Initialize default settings
const insertSetting = db.prepare('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)');
insertSetting.run('limit_fine', '50000');
insertSetting.run('limit_jail', '90');
insertSetting.run('tax_judiciary', '20');
insertSetting.run('multiplier_crime', '1.5');
insertSetting.run('multiplier_terror', '2.0');

// Default laws template
function insertDefaultLaws(db) {
  const defaultLaws = [
    // Verkehrsdelikte
    { category: 'Verkehrsdelikte', paragraph: '§ 1', title: 'Geschwindigkeitsüberschreitung', fine_min: 500, fine_max: 2000, jail_min: 0, jail_max: 0, points: 1 },
    { category: 'Verkehrsdelikte', paragraph: '§ 2', title: 'Fahren ohne Licht', fine_min: 200, fine_max: 500, jail_min: 0, jail_max: 0, points: 1 },
    { category: 'Verkehrsdelikte', paragraph: '§ 3', title: 'Alkoholfahrt', fine_min: 2000, fine_max: 5000, jail_min: 5, jail_max: 15, points: 3 },
    { category: 'Verkehrsdelikte', paragraph: '§ 4', title: 'Drogenfahrt', fine_min: 3000, fine_max: 8000, jail_min: 10, jail_max: 20, points: 3 },
    { category: 'Verkehrsdelikte', paragraph: '§ 5', title: 'Fahren ohne Führerschein', fine_min: 1500, fine_max: 3500, jail_min: 5, jail_max: 10, points: 2 },
    { category: 'Verkehrsdelikte', paragraph: '§ 6', title: 'Flucht vor AVK', fine_min: 5000, fine_max: 15000, jail_min: 15, jail_max: 30, points: 5 },
    { category: 'Verkehrsdelikte', paragraph: '§ 7', title: 'Gefährliches Fahren', fine_min: 3000, fine_max: 8000, jail_min: 10, jail_max: 25, points: 4 },

    // Gewaltdelikte
    { category: 'Gewaltdelikte', paragraph: '§ 10', title: 'Körperverletzung', fine_min: 2000, fine_max: 5000, jail_min: 5, jail_max: 15, points: 0, is_felony: 0 },
    { category: 'Gewaltdelikte', paragraph: '§ 11', title: 'Gefährliche Körperverletzung', fine_min: 5000, fine_max: 15000, jail_min: 15, jail_max: 35, points: 0, is_felony: 1 },
    { category: 'Gewaltdelikte', paragraph: '§ 12', title: 'Schwere Körperverletzung', fine_min: 10000, fine_max: 25000, jail_min: 25, jail_max: 50, points: 0, is_felony: 1 },
    { category: 'Gewaltdelikte', paragraph: '§ 13', title: 'Totschlag', fine_min: 25000, fine_max: 50000, jail_min: 45, jail_max: 90, points: 0, is_felony: 1 },
    { category: 'Gewaltdelikte', paragraph: '§ 14', title: 'Mord', fine_min: 50000, fine_max: 100000, jail_min: 90, jail_max: 180, points: 0, is_felony: 1 },
    { category: 'Gewaltdelikte', paragraph: '§ 15', title: 'Bedrohung', fine_min: 1000, fine_max: 3000, jail_min: 0, jail_max: 10, points: 0, is_felony: 0 },
    { category: 'Gewaltdelikte', paragraph: '§ 16', title: 'Geiselnahme', fine_min: 15000, fine_max: 40000, jail_min: 30, jail_max: 60, points: 0, is_felony: 1 },

    // Eigentumsdelikte
    { category: 'Eigentumsdelikte', paragraph: '§ 20', title: 'Diebstahl', fine_min: 1000, fine_max: 5000, jail_min: 5, jail_max: 15, points: 0, is_felony: 0 },
    { category: 'Eigentumsdelikte', paragraph: '§ 21', title: 'Schwerer Diebstahl', fine_min: 5000, fine_max: 15000, jail_min: 15, jail_max: 30, points: 0, is_felony: 1 },
    { category: 'Eigentumsdelikte', paragraph: '§ 22', title: 'Raub', fine_min: 10000, fine_max: 30000, jail_min: 20, jail_max: 45, points: 0, is_felony: 1 },
    { category: 'Eigentumsdelikte', paragraph: '§ 23', title: 'Schwerer Raub', fine_min: 20000, fine_max: 50000, jail_min: 35, jail_max: 70, points: 0, is_felony: 1 },
    { category: 'Eigentumsdelikte', paragraph: '§ 24', title: 'Sachbeschädigung', fine_min: 500, fine_max: 3000, jail_min: 0, jail_max: 10, points: 0, is_felony: 0 },
    { category: 'Eigentumsdelikte', paragraph: '§ 25', title: 'Fahrzeugdiebstahl', fine_min: 3000, fine_max: 10000, jail_min: 10, jail_max: 25, points: 0, is_felony: 1 },

    // Waffendelikte
    { category: 'Waffendelikte', paragraph: '§ 30', title: 'Illegaler Waffenbesitz', fine_min: 5000, fine_max: 15000, jail_min: 10, jail_max: 30, points: 0, is_felony: 1 },
    { category: 'Waffendelikte', paragraph: '§ 31', title: 'Illegaler Waffenhandel', fine_min: 15000, fine_max: 40000, jail_min: 25, jail_max: 50, points: 0, is_felony: 1 },
    { category: 'Waffendelikte', paragraph: '§ 32', title: 'Führen einer Schusswaffe', fine_min: 3000, fine_max: 8000, jail_min: 5, jail_max: 20, points: 0, is_felony: 0 },
    { category: 'Waffendelikte', paragraph: '§ 33', title: 'Schießen in der Öffentlichkeit', fine_min: 5000, fine_max: 15000, jail_min: 15, jail_max: 35, points: 0, is_felony: 1 },

    // Drogendelikte
    { category: 'Drogendelikte', paragraph: '§ 40', title: 'Drogenbesitz (geringe Menge)', fine_min: 1000, fine_max: 3000, jail_min: 0, jail_max: 10, points: 0, is_felony: 0 },
    { category: 'Drogendelikte', paragraph: '§ 41', title: 'Drogenbesitz (große Menge)', fine_min: 5000, fine_max: 15000, jail_min: 15, jail_max: 30, points: 0, is_felony: 1 },
    { category: 'Drogendelikte', paragraph: '§ 42', title: 'Drogenhandel', fine_min: 15000, fine_max: 40000, jail_min: 25, jail_max: 50, points: 0, is_felony: 1 },
    { category: 'Drogendelikte', paragraph: '§ 43', title: 'Drogenproduktion', fine_min: 25000, fine_max: 60000, jail_min: 35, jail_max: 70, points: 0, is_felony: 1 },

    // Sonstige
    { category: 'Sonstige Straftaten', paragraph: '§ 50', title: 'Widerstand gegen Vollstreckungsbeamte', fine_min: 2000, fine_max: 6000, jail_min: 5, jail_max: 20, points: 0, is_felony: 0 },
    { category: 'Sonstige Straftaten', paragraph: '§ 51', title: 'Beamtenbeleidigung', fine_min: 500, fine_max: 2000, jail_min: 0, jail_max: 5, points: 0, is_felony: 0 },
    { category: 'Sonstige Straftaten', paragraph: '§ 52', title: 'Flucht aus Gewahrsam', fine_min: 3000, fine_max: 10000, jail_min: 10, jail_max: 25, points: 0, is_felony: 0 },
    { category: 'Sonstige Straftaten', paragraph: '§ 53', title: 'Hausfriedensbruch', fine_min: 1000, fine_max: 3000, jail_min: 0, jail_max: 10, points: 0, is_felony: 0 },
    { category: 'Sonstige Straftaten', paragraph: '§ 54', title: 'Betrug', fine_min: 2000, fine_max: 10000, jail_min: 5, jail_max: 20, points: 0, is_felony: 0 },
    { category: 'Sonstige Straftaten', paragraph: '§ 55', title: 'Erpressung', fine_min: 5000, fine_max: 20000, jail_min: 15, jail_max: 35, points: 0, is_felony: 1 },
  ];

  const insertLaw = db.prepare(`
    INSERT INTO laws (category, paragraph, title, fine_min, fine_max, jail_min, jail_max, points, is_felony)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  for (const law of defaultLaws) {
    insertLaw.run(law.category, law.paragraph, law.title, law.fine_min, law.fine_max, law.jail_min, law.jail_max, law.points, law.is_felony || 0);
  }

  console.log(`Inserted ${defaultLaws.length} default laws`);
}

// Generate unique network ID
function generateNetworkId() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let id;
  do {
    id = '';
    for (let i = 0; i < 8; i++) {
      id += chars.charAt(Math.floor(Math.random() * chars.length));
    }
  } while (mainDb.prepare('SELECT id FROM networks WHERE id = ?').get(id));
  return id;
}

// WebSocket setup
const wss = new WebSocketServer({ server });
const calcSessions = new Map(); // networkId:code -> Set of WebSocket clients

wss.on('connection', (ws) => {
  ws.sessionKey = null;

  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);

      if (data.type === 'join') {
        // Join a calculator session
        ws.sessionKey = data.code;
        if (!calcSessions.has(ws.sessionKey)) {
          calcSessions.set(ws.sessionKey, new Set());
        }
        calcSessions.get(ws.sessionKey).add(ws);
        console.log(`Client joined session: ${ws.sessionKey}`);

        // Send current session state to the new client
        const currentSession = db.prepare('SELECT * FROM calc_sessions WHERE code = ?').get(data.code);
        if (currentSession) {
          ws.send(JSON.stringify({
            type: 'sync',
            selected_offenses: JSON.parse(currentSession.selected_offenses),
            modifiers: JSON.parse(currentSession.modifiers),
            notes: currentSession.notes
          }));
        }
      }

      if (data.type === 'update' && ws.sessionKey) {
        // Broadcast update to all clients in the same session
        const clients = calcSessions.get(ws.sessionKey);
        if (clients) {
          const syncMessage = JSON.stringify({
            type: 'sync',
            selected_offenses: data.selected_offenses,
            modifiers: data.modifiers,
            notes: data.notes
          });
          clients.forEach(client => {
            if (client !== ws && client.readyState === 1) {
              client.send(syncMessage);
            }
          });
        }
      }
    } catch (err) {
      console.error('WebSocket message error:', err);
    }
  });

  ws.on('close', () => {
    if (ws.sessionKey && calcSessions.has(ws.sessionKey)) {
      calcSessions.get(ws.sessionKey).delete(ws);
      if (calcSessions.get(ws.sessionKey).size === 0) {
        calcSessions.delete(ws.sessionKey);
      }
    }
  });
});

// ==================== LAW MANAGEMENT ROUTES ====================

// Get all laws
app.get('/api/laws', (req, res) => {
  const { category, search } = req.query;
  let query = 'SELECT * FROM laws';
  const params = [];
  const conditions = [];

  if (category) {
    conditions.push('category = ?');
    params.push(category);
  }
  if (search) {
    conditions.push('(paragraph LIKE ? OR title LIKE ? OR description LIKE ?)');
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  if (conditions.length > 0) {
    query += ' WHERE ' + conditions.join(' AND ');
  }
  query += ' ORDER BY category, paragraph';

  const laws = db.prepare(query).all(...params);
  res.json(laws);
});

// Get single law
app.get('/api/laws/:id', (req, res) => {
  const law = db.prepare('SELECT * FROM laws WHERE id = ?').get(req.params.id);
  if (!law) {
    return res.status(404).json({ error: 'Gesetz nicht gefunden' });
  }
  res.json(law);
});

// Create law
app.post('/api/laws', (req, res) => {
  const { category, paragraph, title, description, fine_min, fine_max, jail_min, jail_max, points, is_felony } = req.body;

  if (!category || !paragraph || !title) {
    return res.status(400).json({ error: 'Kategorie, Paragraph und Titel sind erforderlich' });
  }

  const result = db.prepare(`
    INSERT INTO laws (category, paragraph, title, description, fine_min, fine_max, jail_min, jail_max, points, is_felony)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(category, paragraph, title, description,
    fine_min || 0, fine_max || 0, jail_min || 0, jail_max || 0, points || 0, is_felony ? 1 : 0);

  res.json({ id: result.lastInsertRowid, message: 'Gesetz erstellt' });
});

// Update law
app.put('/api/laws/:id', (req, res) => {
  const { category, paragraph, title, description, fine_min, fine_max, jail_min, jail_max, points, is_felony } = req.body;

  db.prepare(`
    UPDATE laws SET category = ?, paragraph = ?, title = ?, description = ?,
    fine_min = ?, fine_max = ?, jail_min = ?, jail_max = ?, points = ?, is_felony = ?,
    updated_at = CURRENT_TIMESTAMP
    WHERE id = ?
  `).run(category, paragraph, title, description,
    fine_min || 0, fine_max || 0, jail_min || 0, jail_max || 0, points || 0, is_felony ? 1 : 0,
    req.params.id);

  res.json({ message: 'Gesetz aktualisiert' });
});

// Delete law
app.delete('/api/laws/:id', (req, res) => {
  db.prepare('DELETE FROM laws WHERE id = ?').run(req.params.id);
  res.json({ message: 'Gesetz geloescht' });
});

// Get law categories
app.get('/api/law-categories', (req, res) => {
  const categories = db.prepare('SELECT DISTINCT category FROM laws ORDER BY category').all();
  res.json(categories.map(c => c.category));
});

// Create new category
app.post('/api/law-categories', (req, res) => {
  const { name } = req.body;
  if (!name || !name.trim()) {
    return res.status(400).json({ error: 'Kategorie-Name ist erforderlich' });
  }

  const existing = db.prepare('SELECT DISTINCT category FROM laws WHERE category = ?').get(name.trim());
  if (existing) {
    return res.status(400).json({ error: 'Kategorie existiert bereits' });
  }

  try {
    db.prepare('INSERT OR IGNORE INTO law_categories (name) VALUES (?)').run(name.trim());
    res.json({ message: 'Kategorie erstellt', name: name.trim() });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Rename category
app.put('/api/law-categories/rename', (req, res) => {
  const { oldName, newName } = req.body;
  if (!oldName || !newName || !newName.trim()) {
    return res.status(400).json({ error: 'Alter und neuer Name sind erforderlich' });
  }

  try {
    const result = db.prepare('UPDATE laws SET category = ? WHERE category = ?').run(newName.trim(), oldName);
    db.prepare('UPDATE law_categories SET name = ? WHERE name = ?').run(newName.trim(), oldName);
    res.json({ message: 'Kategorie umbenannt', updated: result.changes });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Delete category
app.delete('/api/law-categories/:name', (req, res) => {
  const name = decodeURIComponent(req.params.name);

  const lawCount = db.prepare('SELECT COUNT(*) as count FROM laws WHERE category = ?').get(name).count;
  if (lawCount > 0) {
    return res.status(400).json({ error: `Kategorie enthaelt ${lawCount} Gesetze und kann nicht geloescht werden` });
  }

  db.prepare('DELETE FROM law_categories WHERE name = ?').run(name);
  res.json({ message: 'Kategorie geloescht' });
});



// ==================== SETTINGS (ADMIN) ====================

app.get('/api/settings', (req, res) => {
  try {
    const limits = {};
    const settings = db.prepare('SELECT * FROM settings').all();
    settings.forEach(s => limits[s.key] = s.value);
    res.json(limits);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/settings', (req, res) => {
  try {
    const { limit_fine, limit_jail } = req.body;
    const upsert = db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value');

    if (limit_fine) upsert.run('limit_fine', limit_fine.toString());
    if (limit_jail) upsert.run('limit_jail', limit_jail.toString());

    res.json({ message: 'Einstellungen gespeichert' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ==================== CALCULATOR SESSIONS ====================

function generateCalcSessionCode() {
  let code;
  do {
    code = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
  } while (db.prepare('SELECT id FROM calc_sessions WHERE code = ?').get(code));
  return code;
}

// Create calculator session
app.post('/api/calc-sessions', (req, res) => {
  try {
    const code = generateCalcSessionCode();
    const { selected_offenses, modifiers, notes } = req.body;

    db.prepare(`
      INSERT INTO calc_sessions (code, selected_offenses, modifiers, notes)
      VALUES (?, ?, ?, ?)
    `).run(
      code,
      JSON.stringify(selected_offenses || []),
      JSON.stringify(modifiers || {}),
      notes || ''
    );

    res.json({ code });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get calculator session
app.get('/api/calc-sessions/:code', (req, res) => {
  try {
    const session = db.prepare('SELECT * FROM calc_sessions WHERE code = ?').get(req.params.code);
    if (!session) {
      return res.status(404).json({ error: 'Session nicht gefunden' });
    }
    res.json({
      code: session.code,
      selected_offenses: JSON.parse(session.selected_offenses),
      modifiers: JSON.parse(session.modifiers),
      notes: session.notes,
      updated_at: session.updated_at
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Update calculator session
app.put('/api/calc-sessions/:code', (req, res) => {
  try {
    const { selected_offenses, modifiers, notes } = req.body;
    const code = req.params.code;

    const session = db.prepare('SELECT id FROM calc_sessions WHERE code = ?').get(code);
    if (!session) {
      return res.status(404).json({ error: 'Session nicht gefunden' });
    }

    db.prepare(`
      UPDATE calc_sessions
      SET selected_offenses = ?, modifiers = ?, notes = ?, updated_at = CURRENT_TIMESTAMP
      WHERE code = ?
    `).run(
      JSON.stringify(selected_offenses || []),
      JSON.stringify(modifiers || {}),
      notes || '',
      code
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Cleanup old calculator sessions
setInterval(() => {
  try {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const result = db.prepare('DELETE FROM calc_sessions WHERE updated_at < ?').run(cutoff);
    if (result.changes > 0) {
      console.log(`${result.changes} alte Calculator-Sessions geloescht`);
    }
  } catch (error) {
    console.error('Fehler beim Aufraeumen der Calculator-Sessions:', error);
  }
}, 60 * 60 * 1000);

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
validateLicense().then(() => {
  server.listen(PORT, () => {
    console.log(`Straftatenrechner running on port ${PORT}`);
    console.log(`License Key: ${LICENSE_KEY.substring(0, 10)}...`);
  });
});
