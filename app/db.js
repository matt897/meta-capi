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
      send_to_meta INTEGER DEFAULT 0,
      dry_run INTEGER DEFAULT 1,
      log_full_payloads INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT,
      event_id TEXT,
      event_name TEXT,
      status TEXT,
      inbound_json TEXT,
      outbound_json TEXT,
      meta_status INTEGER,
      meta_body TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS errors (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT,
      event_db_id INTEGER,
      event_id TEXT,
      type TEXT,
      message TEXT,
      meta_status INTEGER,
      meta_body TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
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

  const columns = await db.all("PRAGMA table_info(sites)");
  const columnNames = new Set(columns.map(column => column.name));

  if (!columnNames.has("send_to_meta")) {
    await db.exec("ALTER TABLE sites ADD COLUMN send_to_meta INTEGER DEFAULT 0");
    await db.run(
      "UPDATE sites SET send_to_meta = CASE WHEN dry_run = 1 THEN 0 ELSE 1 END WHERE send_to_meta IS NULL"
    );
  }

  if (!columnNames.has("updated_at")) {
    await db.exec("ALTER TABLE sites ADD COLUMN updated_at TEXT");
    await db.run("UPDATE sites SET updated_at = created_at WHERE updated_at IS NULL");
  }

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
    "INSERT INTO sites (site_id, site_key, name, pixel_id, access_token, test_event_code, send_to_meta, dry_run, log_full_payloads, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
    site.site_id,
    site.site_key,
    site.name,
    site.pixel_id,
    site.access_token,
    site.test_event_code,
    site.send_to_meta ? 1 : 0,
    site.dry_run ? 1 : 0,
    site.log_full_payloads ? 1 : 0
  );
}

export async function updateSite(db, site) {
  await db.run(
    "UPDATE sites SET name = ?, pixel_id = ?, access_token = ?, test_event_code = ?, send_to_meta = ?, dry_run = ?, log_full_payloads = ?, updated_at = CURRENT_TIMESTAMP WHERE site_id = ?",
    site.name,
    site.pixel_id,
    site.access_token,
    site.test_event_code,
    site.send_to_meta ? 1 : 0,
    site.dry_run ? 1 : 0,
    site.log_full_payloads ? 1 : 0,
    site.site_id
  );
}

export async function rotateSiteKey(db, siteId, siteKey) {
  await db.run("UPDATE sites SET site_key = ? WHERE site_id = ?", siteKey, siteId);
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

export async function insertEvent(db, event) {
  const result = await db.run(
    "INSERT INTO events (site_id, event_id, event_name, status, inbound_json, outbound_json, meta_status, meta_body) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    event.site_id,
    event.event_id ?? null,
    event.event_name ?? null,
    event.status,
    event.inbound_json ?? null,
    event.outbound_json ?? null,
    event.meta_status ?? null,
    event.meta_body ?? null
  );
  return result.lastID;
}

export async function updateEventMeta(db, eventId, { status, outboundJson, metaStatus, metaBody }) {
  await db.run(
    "UPDATE events SET status = ?, outbound_json = ?, meta_status = ?, meta_body = ? WHERE id = ?",
    status,
    outboundJson ?? null,
    metaStatus ?? null,
    metaBody ?? null,
    eventId
  );
}

export async function listEvents(db, { limit = 50, siteId, status, eventName }) {
  const conditions = [];
  const params = [];

  if (siteId) {
    conditions.push("events.site_id = ?");
    params.push(siteId);
  }
  if (status) {
    conditions.push("events.status = ?");
    params.push(status);
  }
  if (eventName) {
    conditions.push("events.event_name LIKE ?");
    params.push(`%${eventName}%`);
  }

  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const rows = await db.all(
    `
      SELECT events.*, sites.name AS site_name, sites.pixel_id AS pixel_id
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      ${whereClause}
      ORDER BY events.id DESC
      LIMIT ?
    `,
    ...params,
    limit
  );

  return rows.map(row => ({
    ...row,
    inbound_json: row.inbound_json ? JSON.parse(row.inbound_json) : null,
    outbound_json: row.outbound_json ? JSON.parse(row.outbound_json) : null,
    meta_body: row.meta_body ? JSON.parse(row.meta_body) : null
  }));
}

export async function getEventById(db, eventId) {
  const row = await db.get(
    `
      SELECT events.*, sites.name AS site_name, sites.pixel_id AS pixel_id
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      WHERE events.id = ?
    `,
    eventId
  );
  if (!row) return null;
  return {
    ...row,
    inbound_json: row.inbound_json ? JSON.parse(row.inbound_json) : null,
    outbound_json: row.outbound_json ? JSON.parse(row.outbound_json) : null,
    meta_body: row.meta_body ? JSON.parse(row.meta_body) : null
  };
}

export async function insertError(db, error) {
  await db.run(
    "INSERT INTO errors (site_id, event_db_id, event_id, type, message, meta_status, meta_body) VALUES (?, ?, ?, ?, ?, ?, ?)",
    error.site_id ?? null,
    error.event_db_id ?? null,
    error.event_id ?? null,
    error.type,
    error.message ?? null,
    error.meta_status ?? null,
    error.meta_body ?? null
  );
}

export async function listErrorGroups(db) {
  return db.all(
    "SELECT type, COUNT(*) as count FROM errors GROUP BY type ORDER BY count DESC"
  );
}

export async function listErrors(db, { type, limit = 20 }) {
  const rows = await db.all(
    `
      SELECT errors.*, sites.name AS site_name, sites.pixel_id AS pixel_id
      FROM errors
      LEFT JOIN sites ON errors.site_id = sites.site_id
      WHERE errors.type = ?
      ORDER BY errors.id DESC
      LIMIT ?
    `,
    type,
    limit
  );

  return rows.map(row => ({
    ...row,
    meta_body: row.meta_body ? JSON.parse(row.meta_body) : null
  }));
}

export async function listRecentErrors(db, limit = 20) {
  const rows = await db.all(
    `
      SELECT errors.*, sites.name AS site_name, sites.pixel_id AS pixel_id
      FROM errors
      LEFT JOIN sites ON errors.site_id = sites.site_id
      ORDER BY errors.id DESC
      LIMIT ?
    `,
    limit
  );

  return rows.map(row => ({
    ...row,
    meta_body: row.meta_body ? JSON.parse(row.meta_body) : null
  }));
}

export async function listRecentEventsForError(db, errorType, limit = 5) {
  return db.all(
    `
      SELECT events.id, events.event_name, events.event_id, events.status, events.created_at,
        sites.name AS site_name, sites.pixel_id AS pixel_id
      FROM errors
      JOIN events ON errors.event_db_id = events.id
      LEFT JOIN sites ON events.site_id = sites.site_id
      WHERE errors.type = ?
      ORDER BY errors.id DESC
      LIMIT ?
    `,
    errorType,
    limit
  );
}

export async function countEventsSince(db, hours) {
  const row = await db.get(
    "SELECT COUNT(*) as count FROM events WHERE created_at > datetime('now', ?)",
    `-${hours} hours`
  );
  return row?.count ?? 0;
}

export async function countErrorsSince(db, hours) {
  const row = await db.get(
    "SELECT COUNT(*) as count FROM errors WHERE created_at > datetime('now', ?)",
    `-${hours} hours`
  );
  return row?.count ?? 0;
}

export async function countDedupedSince(db, hours) {
  const row = await db.get(
    "SELECT COUNT(*) as count FROM events WHERE status = 'deduped' AND created_at > datetime('now', ?)",
    `-${hours} hours`
  );
  return row?.count ?? 0;
}

export async function countEventsTodayBySite(db, siteId) {
  const row = await db.get(
    "SELECT COUNT(*) as count FROM events WHERE site_id = ? AND created_at > datetime('now', '-1 day')",
    siteId
  );
  return row?.count ?? 0;
}

export async function countErrorsTodayBySite(db, siteId) {
  const row = await db.get(
    "SELECT COUNT(*) as count FROM errors WHERE site_id = ? AND created_at > datetime('now', '-1 day')",
    siteId
  );
  return row?.count ?? 0;
}

export async function cleanupRetention(db, retentionHours) {
  await db.run(
    "DELETE FROM events WHERE created_at < datetime('now', ?)",
    `-${retentionHours} hours`
  );
  await db.run(
    "DELETE FROM errors WHERE created_at < datetime('now', ?)",
    `-${retentionHours} hours`
  );
}

export async function hasRecentEventId(db, siteId, eventId, ttlHours) {
  const row = await db.get(
    "SELECT 1 FROM event_dedup WHERE site_id = ? AND event_id = ? AND created_at > datetime('now', ?)",
    siteId,
    eventId,
    `-${ttlHours} hours`
  );
  return Boolean(row);
}

export async function storeEventId(db, siteId, eventId, ttlHours) {
  await db.run(
    "INSERT INTO event_dedup (site_id, event_id) VALUES (?, ?)",
    siteId,
    eventId
  );
  await db.run(
    "DELETE FROM event_dedup WHERE created_at < datetime('now', ?)",
    `-${ttlHours} hours`
  );
}
