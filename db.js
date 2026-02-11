/**
 * Database abstraction layer.
 * Uses PostgreSQL (via DATABASE_URL) in production, SQLite locally.
 */
const path = require('path');
const fs = require('fs');

let pool = null;
let sqliteDb = null;
let isPostgres = false;

function convertPlaceholders(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

function adaptSql(sql) {
  let s = convertPlaceholders(sql);
  // INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
  if (/INSERT\s+OR\s+IGNORE/i.test(sql)) {
    s = s.replace(/INSERT\s+OR\s+IGNORE/i, 'INSERT');
    // Append ON CONFLICT DO NOTHING before any RETURNING
    if (!s.includes('ON CONFLICT')) {
      s = s.replace(/(VALUES\s*\([^)]+\))/, '$1 ON CONFLICT DO NOTHING');
    }
  }
  return s;
}

async function initDb() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: { rejectUnauthorized: false }
    });
    isPostgres = true;
    // Test connection
    await pool.query('SELECT 1');
    console.log('Connected to PostgreSQL');
  } else {
    const Database = require('better-sqlite3');
    const dataDir = fs.existsSync('/var/data') ? '/var/data' : path.join(__dirname, 'data');
    if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });
    sqliteDb = new Database(path.join(dataDir, 'integration.db'));
    sqliteDb.pragma('journal_mode = WAL');
    sqliteDb.pragma('foreign_keys = ON');
    console.log('Using SQLite:', path.join(dataDir, 'integration.db'));
  }
}

async function exec(sql) {
  if (isPostgres) {
    // Split multi-statement SQL and execute each
    const statements = sql.split(';').map(s => s.trim()).filter(Boolean);
    for (let stmt of statements) {
      // Skip SQLite-specific ALTER TABLE that PG might reject
      try {
        await pool.query(stmt);
      } catch (e) {
        // Ignore "already exists" errors for CREATE TABLE IF NOT EXISTS / ALTER TABLE ADD COLUMN
        if (!e.message.includes('already exists') && !e.message.includes('duplicate column')) {
          throw e;
        }
      }
    }
  } else {
    sqliteDb.exec(sql);
  }
}

async function query(sql, ...params) {
  if (isPostgres) {
    const result = await pool.query(adaptSql(sql), params);
    return result.rows;
  }
  return sqliteDb.prepare(sql).all(...params);
}

async function queryOne(sql, ...params) {
  if (isPostgres) {
    const result = await pool.query(adaptSql(sql), params);
    return result.rows[0] || null;
  }
  return sqliteDb.prepare(sql).get(...params);
}

async function execute(sql, ...params) {
  if (isPostgres) {
    const result = await pool.query(adaptSql(sql), params);
    return { changes: result.rowCount };
  }
  return sqliteDb.prepare(sql).run(...params);
}

module.exports = { initDb, exec, query, queryOne, execute, isPostgres: () => isPostgres };
