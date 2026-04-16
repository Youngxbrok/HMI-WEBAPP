/**
 * server.js
 * ─────────────────────────────────────────────────────────────
 * TitanControl-HMI — Main Express Server
 * Handles routing, session management, auth middleware,
 * and all API endpoints.
 * ─────────────────────────────────────────────────────────────
 */

'use strict';

const express        = require('express');
const session        = require('express-session');
const path           = require('path');
const db             = require('./database');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── View engine ──────────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ── Static assets ────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));

// ── Body parsers ─────────────────────────────────────────────
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// ── Session configuration ────────────────────────────────────
app.use(session({
  secret           : process.env.SESSION_SECRET || 'titan-hmi-super-secret-key-2024',
  resave           : false,
  saveUninitialized: false,
  cookie: {
    secure  : false,          // set true in production with HTTPS
    httpOnly: true,           // prevent XSS access to cookie
    maxAge  : 1000 * 60 * 60  // 1 hour session
  }
}));

// ── Security headers (minimal hardening) ────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  next();
});

// ═══════════════════════════════════════════════════════════
//  AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════

/**
 * requireAuth — redirects to /login if no active session.
 */
function requireAuth(req, res, next) {
  if (req.session && req.session.userId) return next();
  return res.redirect('/login');
}

/**
 * requireBiometric — ensures biometric step was completed.
 */
function requireBiometric(req, res, next) {
  if (req.session && req.session.biometricPassed) return next();
  return res.redirect('/biometric');
}

/**
 * redirectIfLoggedIn — for login/register pages.
 */
function redirectIfLoggedIn(req, res, next) {
  if (req.session && req.session.userId && req.session.biometricPassed) {
    return res.redirect('/dashboard');
  }
  next();
}

// ═══════════════════════════════════════════════════════════
//  ROUTES — AUTH
// ═══════════════════════════════════════════════════════════

// GET /
app.get('/', (req, res) => res.redirect('/login'));

// GET /login
app.get('/login', redirectIfLoggedIn, (req, res) => {
  res.render('login', { error: null, email: '' });
});

// POST /login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ipAddress = req.ip || req.connection.remoteAddress;

  // Basic server-side validation
  if (!email || !password) {
    return res.render('login', { error: 'Email y contraseña son requeridos.', email });
  }

  try {
    const user = await db.findUserByEmail(email);

    if (!user) {
      await db.logActivity({ username: email, eventType: 'LOGIN_FAILURE', detail: 'User not found', ipAddress });
      return res.render('login', { error: 'Credenciales incorrectas.', email });
    }

    const passwordMatch = await db.verifyPassword(password, user.passwordHash);

    if (!passwordMatch) {
      await db.logActivity({ userId: user.id, username: user.username, eventType: 'LOGIN_FAILURE', detail: 'Wrong password', ipAddress });
      return res.render('login', { error: 'Credenciales incorrectas.', email });
    }

    // Credentials OK — set partial session, redirect to biometric
    req.session.userId        = user.id;
    req.session.username      = user.username;
    req.session.role          = user.role;
    req.session.biometricPassed = false;

    await db.updateLastLogin(user.id);
    await db.logActivity({ userId: user.id, username: user.username, eventType: 'LOGIN_SUCCESS', ipAddress });

    res.redirect('/biometric');

  } catch (err) {
    console.error('[LOGIN]', err);
    res.render('login', { error: 'Error interno del servidor.', email });
  }
});

// GET /register
app.get('/register', redirectIfLoggedIn, (req, res) => {
  res.render('register', { error: null, success: null });
});

// POST /register
app.post('/register', async (req, res) => {
  const { username, email, password, confirmPassword } = req.body;

  if (!username || !email || !password) {
    return res.render('register', { error: 'Todos los campos son requeridos.', success: null });
  }
  if (password !== confirmPassword) {
    return res.render('register', { error: 'Las contraseñas no coinciden.', success: null });
  }
  if (password.length < 8) {
    return res.render('register', { error: 'La contraseña debe tener al menos 8 caracteres.', success: null });
  }

  try {
    await db.createUser({ username, email, password });
    res.render('register', { error: null, success: 'Cuenta creada. Ya puedes iniciar sesión.' });
  } catch (err) {
    if (err.message && err.message.includes('UNIQUE')) {
      return res.render('register', { error: 'El email o usuario ya están registrados.', success: null });
    }
    console.error('[REGISTER]', err);
    res.render('register', { error: 'Error interno del servidor.', success: null });
  }
});

// GET /logout
app.get('/logout', async (req, res) => {
  if (req.session.userId) {
    await db.logActivity({
      userId  : req.session.userId,
      username: req.session.username,
      eventType: 'LOGOUT',
      ipAddress: req.ip
    }).catch(() => {});
  }
  req.session.destroy(() => res.redirect('/login'));
});

// ═══════════════════════════════════════════════════════════
//  ROUTES — BIOMETRIC
// ═══════════════════════════════════════════════════════════

// GET /biometric — only accessible after credentials pass
app.get('/biometric', requireAuth, (req, res) => {
  if (req.session.biometricPassed) return res.redirect('/dashboard');
  res.render('biometric', { username: req.session.username });
});

// POST /api/biometric/pass — called by frontend after scan
app.post('/api/biometric/pass', requireAuth, async (req, res) => {
  const { voiceTranscript } = req.body;

  req.session.biometricPassed = true;

  await db.logActivity({
    userId   : req.session.userId,
    username : req.session.username,
    eventType: 'BIOMETRIC_PASS',
    detail   : `Voice: "${voiceTranscript || 'N/A'}"`,
    ipAddress: req.ip
  }).catch(() => {});

  res.json({ success: true, redirect: '/dashboard' });
});

// POST /api/biometric/fail — called if user cancels scan
app.post('/api/biometric/fail', requireAuth, async (req, res) => {
  await db.logActivity({
    userId   : req.session.userId,
    username : req.session.username,
    eventType: 'BIOMETRIC_FAIL',
    ipAddress: req.ip
  }).catch(() => {});

  req.session.destroy(() => res.json({ success: true, redirect: '/login' }));
});

// ═══════════════════════════════════════════════════════════
//  ROUTES — DASHBOARD
// ═══════════════════════════════════════════════════════════

// GET /dashboard
app.get('/dashboard', requireAuth, requireBiometric, async (req, res) => {
  try {
    const user = await db.findUserById(req.session.userId);
    const logs = await db.getLogsByUser(req.session.userId, 10);
    res.render('dashboard', { user, logs });
  } catch (err) {
    console.error('[DASHBOARD]', err);
    res.status(500).send('Error cargando el dashboard.');
  }
});

// ═══════════════════════════════════════════════════════════
//  ROUTES — API
// ═══════════════════════════════════════════════════════════

/**
 * POST /api/voice-command
 * Logs a voice command transcription from the dashboard.
 */
app.post('/api/voice-command', requireAuth, requireBiometric, async (req, res) => {
  const { transcript } = req.body;
  if (!transcript) return res.status(400).json({ error: 'No transcript provided' });

  await db.logActivity({
    userId   : req.session.userId,
    username : req.session.username,
    eventType: 'VOICE_COMMAND',
    detail   : transcript,
    ipAddress: req.ip
  }).catch(() => {});

  res.json({ success: true });
});

/**
 * POST /api/emergency-stop
 * Logs an emergency stop event.
 */
app.post('/api/emergency-stop', requireAuth, requireBiometric, async (req, res) => {
  await db.logActivity({
    userId   : req.session.userId,
    username : req.session.username,
    eventType: 'EMERGENCY_STOP',
    detail   : 'Operator triggered emergency stop',
    ipAddress: req.ip
  });

  console.warn(`[⚠ EMERGENCY STOP] Triggered by ${req.session.username}`);
  res.json({ success: true, message: 'PARADA DE EMERGENCIA ACTIVADA' });
});

/**
 * GET /api/logs
 * Returns recent activity logs (supervisor only).
 */
app.get('/api/logs', requireAuth, requireBiometric, async (req, res) => {
  try {
    const logs = await db.getRecentLogs(100);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: 'Could not retrieve logs' });
  }
});

// ── 404 handler ──────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).render('404');
});

// ── Global error handler ─────────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[UNHANDLED ERROR]', err);
  res.status(500).send('Error interno del servidor.');
});

// ═══════════════════════════════════════════════════════════
//  STARTUP
// ═══════════════════════════════════════════════════════════
async function startServer() {
  try {
    await db.initializeDatabase();
    app.listen(PORT, () => {
      console.log(`\n🔩 TitanControl-HMI running on http://localhost:${PORT}`);
      console.log(`   Default login → admin@titancontrol.io / Titan2024!\n`);
    });
  } catch (err) {
    console.error('[STARTUP FAILED]', err);
    process.exit(1);
  }
}

startServer();
