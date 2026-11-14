const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Load .env locally if present
const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').replace(/^\uFEFF/, '').split(/\r?\n/).forEach(line => {
    const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
    if (match && !process.env[match[1]]) {
      process.env[match[1]] = (match[2] || '').replace(/^['"]|['"]$/g, '');
    }
  });
}

const app = express();
const PORT = process.env.PORT || 3001;
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'config.json');

const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/+$/, '');
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';
const USE_SUPABASE = Boolean(SUPABASE_URL && SUPABASE_KEY);

// Stateless HMAC signing secret for serverless session cookies
const SESSION_SECRET = process.env.SESSION_SECRET || SUPABASE_KEY || 'local-dev-blinkit-hub-secret';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

function supabaseHeaders(extra = {}) {
  const headers = { apikey: SUPABASE_KEY, ...extra };
  // Legacy JWT keys start with eyJ; new sb_secret_ keys only use apikey header
  if (SUPABASE_KEY.startsWith('eyJ')) {
    headers.Authorization = `Bearer ${SUPABASE_KEY}`;
  }
  return headers;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  const derived = crypto.scryptSync(password, salt, 64);
  const target = Buffer.from(storedHash, 'hex');
  if (derived.length !== target.length) return false;
  return crypto.timingSafeEqual(derived, target);
}

// Stateless signed session tokens (works across serverless function instances)
function createSessionToken(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifySessionToken(token) {
  if (!token || !token.includes('.')) return null;
  const [data, sig] = token.split('.');
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(data).digest('base64url');
  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expected);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const parsed = JSON.parse(Buffer.from(data, 'base64url').toString('utf8'));
    if (!parsed.expiresAt || Date.now() > parsed.expiresAt) return null;
    return parsed;
  } catch {
    return null;
  }
}

function buildDefaultConfig() {
  const superCreds = hashPassword('superadmin@123');
  return {
    security: {
      users: [
        {
          id: 'u-super-taz',
          username: 'taz',
          role: 'superadmin',
          active: true,
          salt: superCreds.salt,
          passwordHash: superCreds.hash,
          createdAt: new Date().toISOString(),
          lastLogin: null
        }
      ]
    },
    auditLog: [
      {
        id: 'log-init',
        action: 'System initialized with default superadmin (taz)',
        by: 'system',
        at: new Date().toISOString()
      }
    ],
    announcement: {
      enabled: false,
      level: 'info',
      text: ''
    },
    site: {
      title: 'Blinkit Ops Hub',
      badge: '10-MIN CX',
      logoUrl: '',
      logoIcon: 'B',
      footerText: 'Blinkit Quick-Commerce Operations • Internal Operations Portal',
      author: 'Mr.Anonmus'
    },
    theme: {
      mode: 'dark',
      primaryColor: '#0c831f',
      accentColor: '#f8cb46'
    },
    navLinks: [
      { id: 'n1', label: 'Live Order OMS', url: '#' },
      { id: 'n2', label: 'Dark Store SLA', url: '#' },
      { id: 'n3', label: 'Rider Fleet Map', url: '#' },
      { id: 'n4', label: 'CX Refund SOP', url: '#' }
    ],
    sections: [
      {
        id: 'sec-1',
        title: 'Customer Support & Order Ops (CX)',
        icon: '🎧',
        links: [
          { id: 'b-101', title: 'Order Management (OMS)', url: '#', tag: 'Core OMS', tagColor: 'emerald', status: 'live', footer: 'Modify, Cancel & Track' },
          { id: 'b-102', title: 'Kapture / Support CRM', url: '#', tag: 'Ticketing', tagColor: 'amber', status: 'live', footer: 'Live Customer Chats' },
          { id: 'b-103', title: 'Instant Refund & Wallet', url: '#', tag: 'Finance', tagColor: 'blue', status: 'live', footer: 'Blinkit Money & Source' },
          { id: 'b-104', title: 'Missing / Damaged Item Desk', url: '#', tag: 'Claims', tagColor: 'rose', status: 'live', footer: 'Photo Proof & Replacement' },
          { id: 'b-105', title: 'CX Escalation Matrix', url: '#', tag: 'L2 / L3', tagColor: 'purple', status: 'internal', footer: 'Shift Leads & On-Call' }
        ]
      },
      {
        id: 'sec-2',
        title: 'Dark Store & Inventory Control',
        icon: '🏪',
        links: [
          { id: 'b-201', title: 'Dark Store Live Pulse', url: '#', tag: 'Store Ops', tagColor: 'emerald', status: 'live', footer: 'Packing Time & Backlog' },
          { id: 'b-202', title: 'SKU & Stock Availability', url: '#', tag: 'Inventory', tagColor: 'amber', status: 'live', footer: 'Bin Location & Fill Rate' },
          { id: 'b-203', title: 'Store Outage / Rain Mode', url: '#', tag: 'Controls', tagColor: 'rose', status: 'vpn', footer: 'Surge & Radius Toggle' },
          { id: 'b-204', title: 'Picker & Packer SLA', url: '#', tag: 'Metrics', tagColor: 'blue', status: 'live', footer: '2-Min Dispatch Tracker' },
          { id: 'b-205', title: 'Cold Chain & Expiry Audit', url: '#', tag: 'Quality', tagColor: 'purple', status: 'live', footer: 'Perishables & Wastage' }
        ]
      },
      {
        id: 'sec-3',
        title: 'Rider Fleet & Last-Mile Delivery',
        icon: '🛵',
        links: [
          { id: 'b-301', title: 'Rider Live Telemetry Map', url: '#', tag: 'GPS Live', tagColor: 'emerald', status: 'live', footer: 'Active & Idle Partners' },
          { id: 'b-302', title: 'Partner Payouts & Surge', url: '#', tag: 'Earnings', tagColor: 'amber', status: 'live', footer: 'Order Fee & Rain Bonus' },
          { id: 'b-303', title: 'Rider SOS & Emergency Desk', url: '#', tag: 'Priority', tagColor: 'rose', status: 'live', footer: 'Accident & Breakdown Help' },
          { id: 'b-304', title: 'Shift & Attendance Roster', url: '#', tag: 'Fleet', tagColor: 'blue', status: 'internal', footer: 'Peak Hour Login Compliance' },
          { id: 'b-305', title: 'Delivery Zone & Geo-Fence', url: '#', tag: 'Mapping', tagColor: 'purple', status: 'vpn', footer: 'Polygon & Blacklist Config' }
        ]
      },
      {
        id: 'sec-4',
        title: 'SOPs, Compliance & IT Systems',
        icon: '⚙️',
        links: [
          { id: 'b-401', title: 'Call & Chat Opening SOP', url: '#', tag: 'Guidelines', tagColor: 'amber', status: 'live', footer: 'Standard Greeting & Tone' },
          { id: 'b-402', title: 'ZTP & Data Privacy Ack', url: '#', tag: 'Mandatory', tagColor: 'rose', status: 'live', footer: 'Zero Tolerance Policy' },
          { id: 'b-403', title: 'Okta SSO & VPN Access', url: '#', tag: 'Security', tagColor: 'blue', status: 'vpn', footer: 'Internal Network Auth' },
          { id: 'b-404', title: 'Cloud Dialer / Softphone', url: '#', tag: 'Voice', tagColor: 'emerald', status: 'live', footer: 'Agent Calling Console' },
          { id: 'b-405', title: 'IT Infra & System Ticket', url: '#', tag: 'Support', tagColor: 'purple', status: 'live', footer: 'Hardware & Login Issues' }
        ]
      }
    ]
  };
}

function getSeedConfig() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf8').replace(/^\uFEFF/, '').trim();
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed.security && Array.isArray(parsed.security.users) && parsed.security.users.length > 0) {
          return parsed;
        }
      }
    }
  } catch (e) {}
  return buildDefaultConfig();
}

async function readConfig() {
  if (USE_SUPABASE) {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/hub_config?id=eq.main&select=payload`, {
      headers: supabaseHeaders()
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Supabase read error (${res.status}): ${errText}`);
    }
    const rows = await res.json();
    if (!Array.isArray(rows) || rows.length === 0 || !rows[0].payload) {
      const seed = getSeedConfig();
      await writeConfig(seed);
      return seed;
    }
    const parsed = rows[0].payload;
    if (!parsed.security || !Array.isArray(parsed.security.users) || parsed.security.users.length === 0) {
      const def = buildDefaultConfig();
      parsed.security = def.security;
      parsed.auditLog = parsed.auditLog || def.auditLog;
      await writeConfig(parsed);
    }
    return parsed;
  }

  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  try {
    if (!fs.existsSync(DATA_FILE)) {
      const fresh = buildDefaultConfig();
      fs.writeFileSync(DATA_FILE, JSON.stringify(fresh, null, 2), 'utf8');
      return fresh;
    }
    const raw = fs.readFileSync(DATA_FILE, 'utf8').replace(/^\uFEFF/, '').trim();
    if (!raw) throw new Error('Empty config file');
    return JSON.parse(raw);
  } catch (err) {
    const fresh = buildDefaultConfig();
    fs.writeFileSync(DATA_FILE, JSON.stringify(fresh, null, 2), 'utf8');
    return fresh;
  }
}

async function writeConfig(data) {
  if (USE_SUPABASE) {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/hub_config`, {
      method: 'POST',
      headers: supabaseHeaders({
        'Content-Type': 'application/json',
        Prefer: 'resolution=merge-duplicates,return=minimal'
      }),
      body: JSON.stringify({
        id: 'main',
        payload: data,
        updated_at: new Date().toISOString()
      })
    });
    if (!res.ok) {
      const errText = await res.text();
      console.error(`Supabase write error (${res.status}):`, errText);
      return false;
    }
    return true;
  }

  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
    return true;
  } catch (err) {
    console.error('Disk write error:', err);
    return false;
  }
}

function appendAudit(config, action, by) {
  if (!Array.isArray(config.auditLog)) config.auditLog = [];
  config.auditLog.unshift({
    id: `log-${Date.now()}`,
    action,
    by,
    at: new Date().toISOString()
  });
  if (config.auditLog.length > 50) config.auditLog.length = 50;
}

function parseCookies(req) {
  const list = {};
  const header = req.headers?.cookie;
  if (!header) return list;
  header.split(';').forEach(cookie => {
    const parts = cookie.split('=');
    const key = parts.shift().trim();
    if (key) list[key] = decodeURIComponent(parts.join('='));
  });
  return list;
}

function getSession(req) {
  const cookies = parseCookies(req);
  return verifySessionToken(cookies.blinkit_sid);
}

function cookieFlags(req) {
  const isHttps = req.headers['x-forwarded-proto'] === 'https' || process.env.URL?.startsWith('https');
  return `HttpOnly; Path=/; SameSite=Strict${isHttps ? '; Secure' : ''}`;
}

function requireAuth(requiredRole = null) {
  return async (req, res, next) => {
    try {
      const session = getSession(req);
      if (!session) return res.status(401).json({ error: 'Authentication required' });

      const config = await readConfig();
      const dbUser = config.security.users.find(u => u.id === session.userId);
      if (!dbUser || !dbUser.active) {
        return res.status(403).json({ error: 'Account is disabled or no longer exists' });
      }
      if (requiredRole === 'superadmin' && dbUser.role !== 'superadmin') {
        return res.status(403).json({ error: 'Superadmin privileges required' });
      }
      req.user = dbUser;
      req.session = session;
      next();
    } catch (err) {
      next(err);
    }
  };
}

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const api = express.Router();

api.get('/config', async (req, res, next) => {
  try {
    const config = await readConfig();
    const safe = JSON.parse(JSON.stringify(config));
    delete safe.security;
    delete safe.auditLog;
    res.json(safe);
  } catch (err) {
    next(err);
  }
});

api.post('/auth/login', async (req, res, next) => {
  try {
    const { username, password, requiredRole } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required.' });
    }

    const config = await readConfig();
    const user = config.security.users.find(
      u => u.username.toLowerCase() === String(username).trim().toLowerCase()
    );

    if (!user || !verifyPassword(String(password), user.salt, user.passwordHash)) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
    if (!user.active) {
      return res.status(403).json({ error: 'This account has been suspended by Superadmin.' });
    }
    if (requiredRole === 'superadmin' && user.role !== 'superadmin') {
      return res.status(403).json({ error: 'Access denied. Superadmin credentials required.' });
    }

    user.lastLogin = new Date().toISOString();
    await writeConfig(config);

    const token = createSessionToken({
      userId: user.id,
      username: user.username,
      role: user.role,
      expiresAt: Date.now() + SESSION_TTL_MS
    });

    res.setHeader(
      'Set-Cookie',
      `blinkit_sid=${token}; ${cookieFlags(req)}; Max-Age=${Math.floor(SESSION_TTL_MS / 1000)}`
    );

    return res.json({
      success: true,
      user: { id: user.id, username: user.username, role: user.role }
    });
  } catch (err) {
    next(err);
  }
});

api.get('/auth/me', requireAuth(), (req, res) => {
  res.json({
    authenticated: true,
    user: { id: req.user.id, username: req.user.username, role: req.user.role }
  });
});

api.post('/auth/logout', (req, res) => {
  res.setHeader('Set-Cookie', `blinkit_sid=; ${cookieFlags(req)}; Max-Age=0`);
  res.json({ success: true });
});

api.post('/auth/change-password', requireAuth(), async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword || String(newPassword).length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters.' });
    }

    const config = await readConfig();
    const user = config.security.users.find(u => u.id === req.user.id);
    if (!verifyPassword(String(currentPassword), user.salt, user.passwordHash)) {
      return res.status(401).json({ error: 'Current password is incorrect.' });
    }

    const updated = hashPassword(String(newPassword));
    user.salt = updated.salt;
    user.passwordHash = updated.hash;
    appendAudit(config, `Password updated for user "${user.username}"`, user.username);
    await writeConfig(config);

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

api.post('/admin/save', requireAuth(), async (req, res, next) => {
  try {
    const incoming = req.body;
    if (!incoming || !incoming.site || !Array.isArray(incoming.sections)) {
      return res.status(400).json({ error: 'Malformed configuration payload.' });
    }

    const config = await readConfig();
    config.site = incoming.site;
    config.theme = incoming.theme || config.theme;
    config.announcement = incoming.announcement || config.announcement;
    config.navLinks = incoming.navLinks || [];
    config.sections = incoming.sections;

    appendAudit(config, 'Updated hub layout, branding, or tool links', req.user.username);

    if (await writeConfig(config)) {
      return res.json({ success: true });
    }
    return res.status(500).json({ error: 'Failed to save configuration to database.' });
  } catch (err) {
    next(err);
  }
});

api.get('/superadmin/overview', requireAuth('superadmin'), async (req, res, next) => {
  try {
    const config = await readConfig();
    const users = config.security.users.map(u => ({
      id: u.id,
      username: u.username,
      role: u.role,
      active: u.active,
      createdAt: u.createdAt,
      lastLogin: u.lastLogin
    }));
    res.json({ users, auditLog: config.auditLog || [] });
  } catch (err) {
    next(err);
  }
});

api.post('/superadmin/users', requireAuth('superadmin'), async (req, res, next) => {
  try {
    const { username, password, role } = req.body || {};
    const cleanUser = String(username || '').trim();
    const cleanPass = String(password || '');
    const cleanRole = role === 'superadmin' ? 'superadmin' : 'admin';

    if (!cleanUser || cleanUser.length < 3) {
      return res.status(400).json({ error: 'Username must be at least 3 characters.' });
    }
    if (!cleanPass || cleanPass.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters.' });
    }

    const config = await readConfig();
    const exists = config.security.users.some(
      u => u.username.toLowerCase() === cleanUser.toLowerCase()
    );
    if (exists) {
      return res.status(409).json({ error: `Username "${cleanUser}" already exists.` });
    }

    const creds = hashPassword(cleanPass);
    const newUser = {
      id: `u-${Date.now()}`,
      username: cleanUser,
      role: cleanRole,
      active: true,
      salt: creds.salt,
      passwordHash: creds.hash,
      createdAt: new Date().toISOString(),
      lastLogin: null
    };

    config.security.users.push(newUser);
    appendAudit(config, `Created ${cleanRole} account "${cleanUser}"`, req.user.username);
    await writeConfig(config);

    res.json({
      success: true,
      user: {
        id: newUser.id,
        username: newUser.username,
        role: newUser.role,
        active: newUser.active,
        createdAt: newUser.createdAt,
        lastLogin: null
      }
    });
  } catch (err) {
    next(err);
  }
});

api.put('/superadmin/users/:id', requireAuth('superadmin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { password, active, role } = req.body || {};

    const config = await readConfig();
    const target = config.security.users.find(u => u.id === id);
    if (!target) return res.status(404).json({ error: 'User not found.' });

    if (target.username.toLowerCase() === 'taz') {
      if (active === false) return res.status(400).json({ error: 'Primary superadmin "taz" cannot be suspended.' });
      if (role && role !== 'superadmin') return res.status(400).json({ error: 'Primary superadmin "taz" role cannot be downgraded.' });
    }

    const changes = [];
    if (typeof active === 'boolean') {
      target.active = active;
      changes.push(active ? 'activated' : 'suspended');
    }

    if (role === 'admin' || role === 'superadmin') {
      target.role = role;
      changes.push(`role set to ${role}`);
    }

    if (password && String(password).trim().length > 0) {
      if (String(password).length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters.' });
      const updated = hashPassword(String(password));
      target.salt = updated.salt;
      target.passwordHash = updated.hash;
      changes.push('password reset');
    }

    appendAudit(config, `Updated "${target.username}" (${changes.join(', ')})`, req.user.username);
    await writeConfig(config);

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

api.delete('/superadmin/users/:id', requireAuth('superadmin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    const config = await readConfig();
    const idx = config.security.users.findIndex(u => u.id === id);

    if (idx === -1) return res.status(404).json({ error: 'User not found.' });

    const target = config.security.users[idx];
    if (target.username.toLowerCase() === 'taz' || target.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot delete primary superadmin or your active account.' });
    }

    config.security.users.splice(idx, 1);
    appendAudit(config, `Deleted user account "${target.username}"`, req.user.username);
    await writeConfig(config);

    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// Mount on both /api and / so Netlify function rewrites match cleanly
app.use('/api', api);
app.use('/', api);

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/superadmin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'superadmin.html'));
});

app.use((err, req, res, next) => {
  console.error('Server Error:', err.message);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

if (require.main === module) {
  app.listen(PORT, '0.0.0.0', async () => {
    console.log(`=================================================`);
    console.log(` Blinkit Ops Hub:  http://localhost:${PORT}`);
    console.log(` Storage Backend:  ${USE_SUPABASE ? 'Supabase PostgreSQL' : 'Local JSON (data/config.json)'}`);
    console.log(` Admin Panel:      http://localhost:${PORT}/admin`);
    console.log(` Superadmin Panel: http://localhost:${PORT}/superadmin`);
    console.log(` Default Login:    taz / superadmin@123`);
    console.log(`=================================================`);
  });
}

module.exports = app;
