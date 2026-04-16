/**
 * database.js
 * ─────────────────────────────────────────────────────────────
 * TitanControl-HMI — Database Layer
 * Handles all SQLite interactions: initialization, user CRUD,
 * and activity logging.  The DB file lives in /data/ so it
 * survives Docker container restarts.
 * ─────────────────────────────────────────────────────────────
 */

'use strict';

const sqlite3 = require('sqlite3').verbose();
const path    = require('path');
const fs      = require('fs');
const bcrypt  = require('bcrypt');

// ── Constants ────────────────────────────────────────────────
const DB_DIR       = path.join(__dirname, 'data');
const DB_PATH      = path.join(DB_DIR, 'titancontrol.db');
const SALT_ROUNDS  = 12;   // bcrypt cost factor
const SEED_USER    = {     // default admin created on first boot
  username : 'admin',
  email    : 'admin@titancontrol.io',
  password : 'Titan2024!',
  role     : 'supervisor',
};

// ── Ensure /data directory exists ────────────────────────────
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
  console.log('[DB] Created /data directory');
}

// ── Open (or create) the SQLite database ─────────────────────
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('[DB] Failed to open database:', err.message);
    process.exit(1);
  }
  console.log(`[DB] Connected → ${DB_PATH}`);
});

// ── Enable WAL mode for better concurrent read performance ───
db.run('PRAGMA journal_mode = WAL');
db.run('PRAGMA foreign_keys = ON');

// ═══════════════════════════════════════════════════════════
//  SCHEMA INITIALIZATION
// ═══════════════════════════════════════════════════════════

/**
 * initializeDatabase()
 * Creates tables if they don't exist and seeds the default admin.
 * Returns a Promise so server.js can await it before listening.
 */
function initializeDatabase() {
  return new Promise((resolve, reject) => {
    db.serialize(() => {

      // ── users table ─────────────────────────────────────
      db.run(`
        CREATE TABLE IF NOT EXISTS users (
          id           INTEGER PRIMARY KEY AUTOINCREMENT,
          username     TEXT    NOT NULL UNIQUE,
          email        TEXT    NOT NULL UNIQUE,
          passwordHash TEXT    NOT NULL,
          role         TEXT    NOT NULL DEFAULT 'operator',
          isActive     INTEGER NOT NULL DEFAULT 1,
          createdAt    TEXT    NOT NULL DEFAULT (datetime('now')),
          lastLoginAt  TEXT
        )
      `, (err) => {
        if (err) return reject(err);
        console.log('[DB] Table `users` ready');
      });

      // ── activity_logs table ──────────────────────────────
      db.run(`
        CREATE TABLE IF NOT EXISTS activity_logs (
          id           INTEGER PRIMARY KEY AUTOINCREMENT,
          userId       INTEGER REFERENCES users(id),
          username     TEXT    NOT NULL,
          eventType    TEXT    NOT NULL,
          detail       TEXT,
          ipAddress    TEXT,
          createdAt    TEXT    NOT NULL DEFAULT (datetime('now'))
        )
      `, (err) => {
        if (err) return reject(err);
        console.log('[DB] Table \`activity_logs\` ready');
      });

      // ── Seed default admin (only if table is empty) ──────
      db.get('SELECT COUNT(*) AS count FROM users', async (err, row) => {
        if (err) return reject(err);

        if (row.count === 0) {
          try {
            const passwordHash = await bcrypt.hash(SEED_USER.password, SALT_ROUNDS);
            db.run(
              `INSERT INTO users (username, email, passwordHash, role)
               VALUES (?, ?, ?, ?)`,
              [SEED_USER.username, SEED_USER.email, passwordHash, SEED_USER.role],
              (err) => {
                if (err) return reject(err);
                console.log(`[DB] Default admin seeded → ${SEED_USER.email} / ${SEED_USER.password}`);
                resolve();
              }
            );
          } catch (hashErr) {
            reject(hashErr);
          }
        } else {
          resolve();
        }
      });
    });
  });
}

// ═══════════════════════════════════════════════════════════
//  USER FUNCTIONS
// ═══════════════════════════════════════════════════════════

/**
 * findUserByEmail(email)
 * Returns the user row matching the email, or null.
 */
function findUserByEmail(email) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT * FROM users WHERE email = ? AND isActive = 1',
      [email],
      (err, row) => (err ? reject(err) : resolve(row || null))
    );
  });
}

/**
 * findUserById(id)
 * Returns the user row matching the id, or null.
 */
function findUserById(id) {
  return new Promise((resolve, reject) => {
    db.get(
      'SELECT id, username, email, role, createdAt, lastLoginAt FROM users WHERE id = ?',
      [id],
      (err, row) => (err ? reject(err) : resolve(row || null))
    );
  });
}

/**
 * createUser({ username, email, password, role })
 * Hashes password and inserts a new user row.
 * Returns the new user's id.
 */
async function createUser({ username, email, password, role = 'operator' }) {
  const passwordHash = await bcrypt.hash(password, SALT_ROUNDS);
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO users (username, email, passwordHash, role)
       VALUES (?, ?, ?, ?)`,
      [username, email, passwordHash, role],
      function (err) {
        if (err) return reject(err);
        resolve(this.lastID);
      }
    );
  });
}

/**
 * updateLastLogin(userId)
 * Stamps the current UTC datetime into lastLoginAt.
 */
function updateLastLogin(userId) {
  return new Promise((resolve, reject) => {
    db.run(
      `UPDATE users SET lastLoginAt = datetime('now') WHERE id = ?`,
      [userId],
      (err) => (err ? reject(err) : resolve())
    );
  });
}

/**
 * verifyPassword(plainText, hash)
 * Returns true if the plaintext matches the bcrypt hash.
 */
function verifyPassword(plainText, hash) {
  return bcrypt.compare(plainText, hash);
}

// ═══════════════════════════════════════════════════════════
//  ACTIVITY LOG FUNCTIONS
// ═══════════════════════════════════════════════════════════

/**
 * logActivity({ userId, username, eventType, detail, ipAddress })
 * Inserts an activity record.  eventType examples:
 *   'LOGIN_SUCCESS', 'LOGIN_FAILURE', 'BIOMETRIC_PASS',
 *   'BIOMETRIC_FAIL', 'EMERGENCY_STOP', 'VOICE_COMMAND', 'LOGOUT'
 */
function logActivity({ userId = null, username, eventType, detail = null, ipAddress = null }) {
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO activity_logs (userId, username, eventType, detail, ipAddress)
       VALUES (?, ?, ?, ?, ?)`,
      [userId, username, eventType, detail, ipAddress],
      function (err) {
        if (err) return reject(err);
        resolve(this.lastID);
      }
    );
  });
}

/**
 * getRecentLogs(limit)
 * Returns the most recent activity log entries.
 */
function getRecentLogs(limit = 50) {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT * FROM activity_logs ORDER BY createdAt DESC LIMIT ?`,
      [limit],
      (err, rows) => (err ? reject(err) : resolve(rows))
    );
  });
}

/**
 * getLogsByUser(userId, limit)
 * Returns log entries for a specific user.
 */
function getLogsByUser(userId, limit = 20) {
  return new Promise((resolve, reject) => {
    db.all(
      `SELECT * FROM activity_logs WHERE userId = ? ORDER BY createdAt DESC LIMIT ?`,
      [userId, limit],
      (err, rows) => (err ? reject(err) : resolve(rows))
    );
  });
}

// ═══════════════════════════════════════════════════════════
//  EXPORTS
// ═══════════════════════════════════════════════════════════
module.exports = {
  initializeDatabase,
  findUserByEmail,
  findUserById,
  createUser,
  updateLastLogin,
  verifyPassword,
  logActivity,
  getRecentLogs,
  getLogsByUser,
};
