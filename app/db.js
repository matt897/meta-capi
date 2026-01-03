import sqlite3 from "sqlite3";
import { open } from "sqlite";

export async function initDb(dbPath) {
  const db = await open({
    filename: dbPath,
    driver: sqlite3.Database
  });

  await db.exec(`
    PRAGMA journal_mode = WAL;
    CREATE TABLE IF NOT EXISTS sites (
      site_id TEXT PRIMARY KEY,
      site_key TEXT UNIQUE NOT NULL,
      name TEXT,
      pixel_id TEXT,
      access_token TEXT,
      test_event_code TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      time TEXT,
      type TEXT,
      site_id TEXT,
      message TEXT,
      status INTEGER,
      meta TEXT,
      error TEXT
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT
    );
    CREATE TABLE IF NOT EXISTS event_dedup (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT,
      event_id TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  return db;
}

export async function ensureSetting(db, key, value) {
  const row = await db.get("SELECT value FROM settings WHERE key = ?", key);
  if (!row) {
    await db.run("INSERT INTO settings (key, value) VALUES (?, ?)", key, value);
  }
}

export async function getSetting(db, key) {
  const row = await db.get("SELECT value FROM settings WHERE key = ?", key);
  return row?.value ?? null;
}

export async function setSetting(db, key, value) {
  await db.run(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
    key,
    value
  );
}

export async function listSettings(db) {
  return db.all("SELECT key, value FROM settings");
}

export async function createSite(db, site) {
  await db.run(
    "INSERT INTO sites (site_id, site_key, name, pixel_id, access_token, test_event_code) VALUES (?, ?, ?, ?, ?, ?)",
    site.site_id,
    site.site_key,
    site.name,
    site.pixel_id,
    site.access_token,
    site.test_event_code
  );
}

export async function updateSite(db, site) {
  await db.run(
    "UPDATE sites SET name = ?, pixel_id = ?, access_token = ?, test_event_code = ? WHERE site_id = ?",
    site.name,
    site.pixel_id,
    site.access_token,
    site.test_event_code,
    site.site_id
  );
}

export async function deleteSite(db, siteId) {
  await db.run("DELETE FROM sites WHERE site_id = ?", siteId);
}

export async function getSites(db) {
  return db.all("SELECT * FROM sites ORDER BY created_at DESC");
}

export async function getSiteById(db, siteId) {
  return db.get("SELECT * FROM sites WHERE site_id = ?", siteId);
}

export async function getSiteByKey(db, siteKey) {
  return db.get("SELECT * FROM sites WHERE site_key = ?", siteKey);
}

export async function addLog(db, entry, limit) {
  await db.run(
    "INSERT INTO logs (time, type, site_id, message, status, meta, error) VALUES (?, ?, ?, ?, ?, ?, ?)",
    entry.time,
    entry.type,
    entry.site_id ?? null,
    entry.message ?? null,
    entry.status ?? null,
    entry.meta ? JSON.stringify(entry.meta) : null,
    entry.error ?? null
  );
  await db.run(
    "DELETE FROM logs WHERE id NOT IN (SELECT id FROM logs ORDER BY id DESC LIMIT ?)",
    limit
  );
}

export async function getLogs(db, limit = 100) {
  const rows = await db.all(
    "SELECT * FROM logs ORDER BY id DESC LIMIT ?",
    limit
  );
  return rows.map(row => ({
    ...row,
    meta: row.meta ? JSON.parse(row.meta) : null
  }));
}

export async function hasRecentEventId(db, siteId, eventId) {
  const row = await db.get(
    "SELECT 1 FROM event_dedup WHERE site_id = ? AND event_id = ? AND created_at > datetime('now', '-2 days')",
    siteId,
    eventId
  );
  return Boolean(row);
}

export async function storeEventId(db, siteId, eventId) {
  await db.run(
    "INSERT INTO event_dedup (site_id, event_id) VALUES (?, ?)",
    siteId,
    eventId
  );
  await db.run(
    "DELETE FROM event_dedup WHERE created_at < datetime('now', '-2 days')"
  );
}
