const express = require('express');
const Database = require('better-sqlite3');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

// Create HTTP server for both Express and WebSocket
const server = http.createServer(app);

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Data directory for network databases
const dataDir = process.env.DATA_DIR || path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Main database for networks management
const mainDbPath = path.join(dataDir, 'main.db');
const mainDb = new Database(mainDbPath);

// Initialize main database tables
mainDb.exec(`
  CREATE TABLE IF NOT EXISTS networks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    admin_password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

// Cache for network database connections
const networkDbs = new Map();

// Get or create network database connection
function getNetworkDb(networkId) {
  if (networkDbs.has(networkId)) {
    return networkDbs.get(networkId);
  }

  const dbPath = path.join(dataDir, `network_${networkId}.db`);
  const db = new Database(dbPath);

  // Initialize network-specific tables
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
    console.log(`Inserting default laws for network ${networkId}...`);
    insertDefaultLaws(db);
  }

  networkDbs.set(networkId, db);
  return db;
}

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
        // Join a calculator session (network-scoped)
        ws.sessionKey = `${data.networkId}:${data.code}`;
        if (!calcSessions.has(ws.sessionKey)) {
          calcSessions.set(ws.sessionKey, new Set());
        }
        calcSessions.get(ws.sessionKey).add(ws);
        console.log(`Client joined session: ${ws.sessionKey}`);
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

// ==================== NETWORK ROUTES ====================

// Get all networks (public list)
app.get('/api/networks', (req, res) => {
  const networks = mainDb.prepare('SELECT id, name, created_at FROM networks ORDER BY name').all();
  res.json(networks);
});

// Create new network
app.post('/api/networks', (req, res) => {
  const { name, password, adminPassword } = req.body;

  if (!name || !password || !adminPassword) {
    return res.status(400).json({ error: 'Name, Passwort und Admin-Passwort sind erforderlich' });
  }

  if (password.length < 4) {
    return res.status(400).json({ error: 'Passwort muss mindestens 4 Zeichen haben' });
  }

  if (adminPassword.length < 4) {
    return res.status(400).json({ error: 'Admin-Passwort muss mindestens 4 Zeichen haben' });
  }

  try {
    const id = generateNetworkId();
    mainDb.prepare('INSERT INTO networks (id, name, password, admin_password) VALUES (?, ?, ?, ?)').run(id, name.trim(), password, adminPassword);

    // Initialize the network database
    getNetworkDb(id);

    res.json({ id, name: name.trim(), message: 'Netzwerk erstellt' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Join network (verify password)
app.post('/api/networks/:id/join', (req, res) => {
  const { password } = req.body;
  const network = mainDb.prepare('SELECT * FROM networks WHERE id = ?').get(req.params.id);

  if (!network) {
    return res.status(404).json({ error: 'Netzwerk nicht gefunden' });
  }

  if (network.password !== password) {
    return res.status(401).json({ error: 'Falsches Passwort' });
  }

  res.json({ id: network.id, name: network.name });
});

// Verify admin password for a network
app.post('/api/networks/:id/admin', (req, res) => {
  const { adminPassword } = req.body;
  const network = mainDb.prepare('SELECT * FROM networks WHERE id = ?').get(req.params.id);

  if (!network) {
    return res.status(404).json({ error: 'Netzwerk nicht gefunden' });
  }

  if (network.admin_password !== adminPassword) {
    return res.status(401).json({ error: 'Falsches Admin-Passwort' });
  }

  res.json({ success: true });
});

// Update network settings
app.put('/api/networks/:id', (req, res) => {
  const { name, password, adminPassword, currentAdminPassword } = req.body;
  const network = mainDb.prepare('SELECT * FROM networks WHERE id = ?').get(req.params.id);

  if (!network) {
    return res.status(404).json({ error: 'Netzwerk nicht gefunden' });
  }

  if (network.admin_password !== currentAdminPassword) {
    return res.status(401).json({ error: 'Falsches Admin-Passwort' });
  }

  const updates = [];
  const params = [];

  if (name) {
    updates.push('name = ?');
    params.push(name.trim());
  }
  if (password) {
    updates.push('password = ?');
    params.push(password);
  }
  if (adminPassword) {
    updates.push('admin_password = ?');
    params.push(adminPassword);
  }

  if (updates.length > 0) {
    params.push(req.params.id);
    mainDb.prepare(`UPDATE networks SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  }

  res.json({ message: 'Netzwerk aktualisiert' });
});

// Delete network
app.delete('/api/networks/:id', (req, res) => {
  const { adminPassword } = req.body;
  const network = mainDb.prepare('SELECT * FROM networks WHERE id = ?').get(req.params.id);

  if (!network) {
    return res.status(404).json({ error: 'Netzwerk nicht gefunden' });
  }

  if (network.admin_password !== adminPassword) {
    return res.status(401).json({ error: 'Falsches Admin-Passwort' });
  }

  // Close and delete network database
  if (networkDbs.has(req.params.id)) {
    networkDbs.get(req.params.id).close();
    networkDbs.delete(req.params.id);
  }

  const dbPath = path.join(dataDir, `network_${req.params.id}.db`);
  if (fs.existsSync(dbPath)) {
    fs.unlinkSync(dbPath);
  }

  mainDb.prepare('DELETE FROM networks WHERE id = ?').run(req.params.id);
  res.json({ message: 'Netzwerk gelöscht' });
});

// ==================== NETWORK-SCOPED API ROUTES ====================

// Get all laws for a network
app.get('/api/networks/:networkId/laws', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
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
app.get('/api/networks/:networkId/laws/:id', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
  const law = db.prepare('SELECT * FROM laws WHERE id = ?').get(req.params.id);
  if (!law) {
    return res.status(404).json({ error: 'Gesetz nicht gefunden' });
  }
  res.json(law);
});

// Create law
app.post('/api/networks/:networkId/laws', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
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
app.put('/api/networks/:networkId/laws/:id', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
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
app.delete('/api/networks/:networkId/laws/:id', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
  db.prepare('DELETE FROM laws WHERE id = ?').run(req.params.id);
  res.json({ message: 'Gesetz gelöscht' });
});

// Get law categories
app.get('/api/networks/:networkId/law-categories', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
  const categories = db.prepare('SELECT DISTINCT category FROM laws ORDER BY category').all();
  res.json(categories.map(c => c.category));
});

// Create new category
app.post('/api/networks/:networkId/law-categories', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
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
app.put('/api/networks/:networkId/law-categories/rename', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
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
app.delete('/api/networks/:networkId/law-categories/:name', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
  const name = decodeURIComponent(req.params.name);

  const lawCount = db.prepare('SELECT COUNT(*) as count FROM laws WHERE category = ?').get(name).count;
  if (lawCount > 0) {
    return res.status(400).json({ error: `Kategorie enthält ${lawCount} Gesetze und kann nicht gelöscht werden` });
  }

  db.prepare('DELETE FROM law_categories WHERE name = ?').run(name);
  res.json({ message: 'Kategorie gelöscht' });
});

// ==================== CALCULATOR SESSIONS (Network-scoped) ====================

function generateCalcSessionCode(db) {
  let code;
  do {
    code = Math.floor(Math.random() * 10000).toString().padStart(4, '0');
  } while (db.prepare('SELECT id FROM calc_sessions WHERE code = ?').get(code));
  return code;
}

// Create calculator session
app.post('/api/networks/:networkId/calc-sessions', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
  try {
    const code = generateCalcSessionCode(db);
    db.prepare('INSERT INTO calc_sessions (code) VALUES (?)').run(code);
    res.json({ code });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Get calculator session
app.get('/api/networks/:networkId/calc-sessions/:code', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
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
app.put('/api/networks/:networkId/calc-sessions/:code', (req, res) => {
  const db = getNetworkDb(req.params.networkId);
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

// Cleanup old calculator sessions (runs for all networks)
setInterval(() => {
  try {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    networkDbs.forEach((db, networkId) => {
      const result = db.prepare('DELETE FROM calc_sessions WHERE updated_at < ?').run(cutoff);
      if (result.changes > 0) {
        console.log(`${result.changes} alte Calculator-Sessions in Netzwerk ${networkId} gelöscht`);
      }
    });
  } catch (error) {
    console.error('Fehler beim Aufraeumen der Calculator-Sessions:', error);
  }
}, 60 * 60 * 1000);

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, () => {
  console.log(`Straftatenrechner running on port ${PORT}`);
});
