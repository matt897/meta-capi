import sqlite3 from "sqlite3";
import { open } from "sqlite";
import fs from "fs";

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
      allowed_origins TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS datasets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      dataset_id TEXT NOT NULL UNIQUE,
      access_token TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT,
      type TEXT,
      event_id TEXT,
      event_name TEXT,
      test_event_code TEXT,
      video_id TEXT,
      percent INTEGER,
      event_source_url TEXT,
      status TEXT,
      inbound_json TEXT,
      outbound_json TEXT,
      meta_status INTEGER,
      meta_body TEXT,
      video_mode TEXT,
      user_agent TEXT,
      ip_address TEXT,
      trace_id TEXT,
      event_time_client INTEGER,
      received_at TEXT DEFAULT CURRENT_TIMESTAMP,
      received_at_utc_ms INTEGER,
      last_seen_at TEXT,
      duplicate_count INTEGER DEFAULT 0,
      outbound_result TEXT,
      outbound_reason TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS outbound_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      inbound_id INTEGER NOT NULL,
      attempted_at TEXT DEFAULT CURRENT_TIMESTAMP,
      dataset_fk INTEGER,
      dataset_id TEXT,
      mode_used TEXT,
      request_payload_json TEXT,
      http_status INTEGER,
      response_body_json TEXT,
      fbtrace_id TEXT,
      result TEXT,
      reason TEXT
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
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS event_dedup (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      site_id TEXT,
      event_id TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS videos (
      id TEXT PRIMARY KEY,
      site_id TEXT NOT NULL,
      video_id TEXT NOT NULL,
      name TEXT,
      page_url TEXT NOT NULL,
      video_source_url TEXT,
      provider TEXT,
      provider_video_id TEXT,
      selector TEXT DEFAULT 'video',
      enabled INTEGER DEFAULT 1,
      mode TEXT NOT NULL DEFAULT 'test',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(site_id, video_id)
    );
  `);

  async function addColumn(table, colDef) {
    try {
      await db.exec(`ALTER TABLE ${table} ADD COLUMN ${colDef}`);
    } catch (error) {
      if (!/duplicate column name/i.test(error?.message ?? "")) {
        throw error;
      }
    }
  }

  await addColumn("events", "trace_id TEXT");
  await addColumn("events", "event_time_client INTEGER");
  await addColumn("events", "test_event_code TEXT");
  await addColumn("sites", "dataset_fk INTEGER");
  await addColumn("sites", "allowed_origins TEXT");
  await addColumn("outbound_logs", "dataset_fk INTEGER");
  await addColumn("outbound_logs", "dataset_id TEXT");

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

  const datasetCountRow = await db.get("SELECT COUNT(*) as count FROM datasets");
  const datasetCount = datasetCountRow?.count ?? 0;
  let defaultDatasetId = null;

  if (datasetCount === 0) {
    const siteRow = await db.get(
      "SELECT pixel_id, access_token FROM sites ORDER BY created_at ASC LIMIT 1"
    );
    const datasetIdValue = siteRow?.pixel_id ?? "default";
    const accessTokenValue = siteRow?.access_token ?? "";
    const insertResult = await db.run(
      "INSERT INTO datasets (name, dataset_id, access_token, is_active) VALUES (?, ?, ?, 1)",
      "Default dataset",
      datasetIdValue,
      accessTokenValue
    );
    defaultDatasetId = insertResult.lastID;
  }

  if (defaultDatasetId === null) {
    const defaultRow = await db.get("SELECT id FROM datasets ORDER BY created_at ASC LIMIT 1");
    defaultDatasetId = defaultRow?.id ?? null;
  }

  if (defaultDatasetId !== null) {
    await db.run(
      "UPDATE sites SET dataset_fk = ? WHERE dataset_fk IS NULL",
      defaultDatasetId
    );
  }

  const eventColumns = await db.all("PRAGMA table_info(events)");
  const eventColumnNames = new Set(eventColumns.map(column => column.name));

  if (!eventColumnNames.has("video_id")) {
    await db.exec("ALTER TABLE events ADD COLUMN video_id TEXT");
  }

  if (!eventColumnNames.has("test_event_code")) {
    await db.exec("ALTER TABLE events ADD COLUMN test_event_code TEXT");
  }

  if (!eventColumnNames.has("percent")) {
    await db.exec("ALTER TABLE events ADD COLUMN percent INTEGER");
  }

  if (!eventColumnNames.has("event_source_url")) {
    await db.exec("ALTER TABLE events ADD COLUMN event_source_url TEXT");
  }

  if (!eventColumnNames.has("video_mode")) {
    await db.exec("ALTER TABLE events ADD COLUMN video_mode TEXT");
  }
  if (!eventColumnNames.has("type")) {
    await db.exec("ALTER TABLE events ADD COLUMN type TEXT");
  }
  if (!eventColumnNames.has("user_agent")) {
    await db.exec("ALTER TABLE events ADD COLUMN user_agent TEXT");
  }
  if (!eventColumnNames.has("ip_address")) {
    await db.exec("ALTER TABLE events ADD COLUMN ip_address TEXT");
  }
  if (!eventColumnNames.has("received_at")) {
    await db.exec("ALTER TABLE events ADD COLUMN received_at TEXT");
    await db.run("UPDATE events SET received_at = created_at WHERE received_at IS NULL");
  }
  if (!eventColumnNames.has("received_at_utc_ms")) {
    await db.exec("ALTER TABLE events ADD COLUMN received_at_utc_ms INTEGER");
  }
  if (!eventColumnNames.has("received_at_utc_ms")) {
    eventColumnNames.add("received_at_utc_ms");
  }
  if (eventColumnNames.has("received_at_utc_ms")) {
    const fallbackMs = (() => {
      try {
        if (fs.existsSync(dbPath)) {
          const stats = fs.statSync(dbPath);
          if (stats?.mtimeMs) {
            return Math.floor(stats.mtimeMs);
          }
        }
      } catch {
        return Date.now();
      }
      return Date.now();
    })();

    await db.run(
      `
        UPDATE events
        SET received_at_utc_ms = COALESCE(
          CAST(strftime('%s', received_at) AS INTEGER) * 1000,
          CAST(strftime('%s', created_at) AS INTEGER) * 1000
        )
        WHERE received_at_utc_ms IS NULL OR received_at_utc_ms = 0
      `
    );
    await db.run(
      "UPDATE events SET received_at_utc_ms = ? WHERE received_at_utc_ms IS NULL OR received_at_utc_ms = 0",
      fallbackMs
    );
  }
  if (!eventColumnNames.has("last_seen_at")) {
    await db.exec("ALTER TABLE events ADD COLUMN last_seen_at TEXT");
  }
  if (!eventColumnNames.has("duplicate_count")) {
    await db.exec("ALTER TABLE events ADD COLUMN duplicate_count INTEGER DEFAULT 0");
  }
  if (!eventColumnNames.has("outbound_result")) {
    await db.exec("ALTER TABLE events ADD COLUMN outbound_result TEXT");
  }
  if (!eventColumnNames.has("outbound_reason")) {
    await db.exec("ALTER TABLE events ADD COLUMN outbound_reason TEXT");
  }

  const videoColumns = await db.all("PRAGMA table_info(videos)");
  const videoColumnNames = new Set(videoColumns.map(column => column.name));

  if (videoColumns.length > 0 && !videoColumnNames.has("selector")) {
    await db.exec("ALTER TABLE videos ADD COLUMN selector TEXT DEFAULT 'video'");
  }

  if (videoColumns.length > 0 && !videoColumnNames.has("video_source_url")) {
    await db.exec("ALTER TABLE videos ADD COLUMN video_source_url TEXT");
  }

  if (videoColumns.length > 0 && !videoColumnNames.has("provider")) {
    await db.exec("ALTER TABLE videos ADD COLUMN provider TEXT");
  }

  if (videoColumns.length > 0 && !videoColumnNames.has("provider_video_id")) {
    await db.exec("ALTER TABLE videos ADD COLUMN provider_video_id TEXT");
  }

  if (videoColumns.length > 0 && !videoColumnNames.has("enabled")) {
    await db.exec("ALTER TABLE videos ADD COLUMN enabled INTEGER DEFAULT 1");
  }

  if (videoColumns.length > 0 && !videoColumnNames.has("mode")) {
    await db.exec("ALTER TABLE videos ADD COLUMN mode TEXT NOT NULL DEFAULT 'test'");
    await db.run("UPDATE videos SET mode = 'test' WHERE mode IS NULL");
  }

  if (videoColumns.length > 0 && !videoColumnNames.has("created_at")) {
    await db.exec("ALTER TABLE videos ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP");
  }

  if (videoColumns.length > 0 && !videoColumnNames.has("updated_at")) {
    await db.exec("ALTER TABLE videos ADD COLUMN updated_at TEXT");
    await db.run("UPDATE videos SET updated_at = created_at WHERE updated_at IS NULL");
  }

  console.log("[DB] migrations applied (safe/ignored if already present)");

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

export async function countUsers(db) {
  const row = await db.get("SELECT COUNT(*) as count FROM users");
  return row?.count ?? 0;
}

export async function createUser(db, user) {
  await db.run(
    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
    user.username,
    user.password_hash
  );
}

export async function getUserByUsername(db, username) {
  return db.get("SELECT * FROM users WHERE username = ?", username);
}

export async function getUserById(db, userId) {
  return db.get("SELECT * FROM users WHERE id = ?", userId);
}

export async function updateUserPassword(db, userId, passwordHash) {
  await db.run(
    "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    passwordHash,
    userId
  );
}

export async function createSite(db, site) {
  await db.run(
    "INSERT INTO sites (site_id, site_key, name, pixel_id, access_token, test_event_code, send_to_meta, dry_run, log_full_payloads, dataset_fk, allowed_origins, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
    site.site_id,
    site.site_key,
    site.name,
    site.pixel_id,
    site.access_token,
    site.test_event_code,
    site.send_to_meta ? 1 : 0,
    site.dry_run ? 1 : 0,
    site.log_full_payloads ? 1 : 0,
    site.dataset_fk ?? null,
    site.allowed_origins ?? null
  );
}

export async function updateSite(db, site) {
  await db.run(
    "UPDATE sites SET name = ?, pixel_id = ?, access_token = ?, test_event_code = ?, send_to_meta = ?, dry_run = ?, log_full_payloads = ?, dataset_fk = ?, allowed_origins = ?, updated_at = CURRENT_TIMESTAMP WHERE site_id = ?",
    site.name,
    site.pixel_id,
    site.access_token,
    site.test_event_code,
    site.send_to_meta ? 1 : 0,
    site.dry_run ? 1 : 0,
    site.log_full_payloads ? 1 : 0,
    site.dataset_fk ?? null,
    site.allowed_origins ?? null,
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
  return db.all(
    `
      SELECT sites.*,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id,
        datasets.access_token AS dataset_access_token,
        datasets.is_active AS dataset_is_active
      FROM sites
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      ORDER BY sites.created_at DESC
    `
  );
}

export async function getSiteById(db, siteId) {
  return db.get(
    `
      SELECT sites.*,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id,
        datasets.access_token AS dataset_access_token,
        datasets.is_active AS dataset_is_active
      FROM sites
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      WHERE sites.site_id = ?
    `,
    siteId
  );
}

export async function getSiteByKey(db, siteKey) {
  return db.get(
    `
      SELECT sites.*,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id,
        datasets.access_token AS dataset_access_token,
        datasets.is_active AS dataset_is_active
      FROM sites
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      WHERE sites.site_key = ?
    `,
    siteKey
  );
}

export async function listDatasets(db) {
  return db.all("SELECT * FROM datasets ORDER BY created_at DESC");
}

export async function getDatasetById(db, datasetId) {
  return db.get("SELECT * FROM datasets WHERE id = ?", datasetId);
}

export async function createDataset(db, dataset) {
  const result = await db.run(
    "INSERT INTO datasets (name, dataset_id, access_token, is_active) VALUES (?, ?, ?, ?)",
    dataset.name,
    dataset.dataset_id,
    dataset.access_token,
    dataset.is_active ? 1 : 0
  );
  return result.lastID;
}

export async function updateDataset(db, dataset) {
  await db.run(
    "UPDATE datasets SET name = ?, dataset_id = ?, access_token = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    dataset.name,
    dataset.dataset_id,
    dataset.access_token,
    dataset.is_active ? 1 : 0,
    dataset.id
  );
}

export async function deleteDataset(db, datasetId) {
  await db.run("DELETE FROM datasets WHERE id = ?", datasetId);
}

export async function listSitesByDataset(db, datasetId) {
  return db.all(
    `
      SELECT sites.*,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id,
        datasets.access_token AS dataset_access_token,
        datasets.is_active AS dataset_is_active
      FROM sites
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      WHERE sites.dataset_fk = ?
      ORDER BY sites.created_at DESC
    `,
    datasetId
  );
}

export async function listVideosByDataset(db, datasetId) {
  return db.all(
    `
      SELECT videos.*,
        sites.name AS site_name,
        sites.site_key AS site_key,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id
      FROM videos
      LEFT JOIN sites ON videos.site_id = sites.site_id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      WHERE sites.dataset_fk = ?
      ORDER BY videos.created_at DESC
    `,
    datasetId
  );
}

export async function insertEvent(db, event) {
  const receivedAtUtcMs = event.received_at_utc_ms ?? Date.now();
  const columns = [
    "site_id",
    "type",
    "event_id",
    "event_name",
    "test_event_code",
    "video_id",
    "percent",
    "event_source_url",
    "status",
    "inbound_json",
    "outbound_json",
    "meta_status",
    "meta_body",
    "video_mode",
    "user_agent",
    "ip_address",
    "received_at",
    "received_at_utc_ms",
    "trace_id",
    "event_time_client",
    "last_seen_at",
    "duplicate_count",
    "outbound_result",
    "outbound_reason"
  ];
  const values = columns.map((column) => (column === "received_at" ? "COALESCE(?, CURRENT_TIMESTAMP)" : "?"));
  const params = columns.map((column) => {
    switch (column) {
      case "received_at":
        return event.received_at ?? null;
      case "received_at_utc_ms":
        return receivedAtUtcMs;
      case "duplicate_count":
        return event.duplicate_count ?? 0;
      case "status":
        return event.status;
      default:
        return event[column] ?? null;
    }
  });
  if (process.env.NODE_ENV !== "production") {
    const placeholderCount = values.reduce((count, value) => count + (value.match(/\?/g) ?? []).length, 0);
    if (placeholderCount !== columns.length || params.length !== columns.length) {
      throw new Error(
        `insertEvent mismatch: columns=${columns.length} placeholders=${placeholderCount} params=${params.length}`
      );
    }
  }
  const result = await db.run(
    `INSERT INTO events (${columns.join(", ")}) VALUES (${values.join(", ")})`,
    ...params
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

export async function insertOutboundLog(db, outbound) {
  const result = await db.run(
    "INSERT INTO outbound_logs (inbound_id, dataset_fk, dataset_id, mode_used, request_payload_json, http_status, response_body_json, fbtrace_id, result, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    outbound.inbound_id,
    outbound.dataset_fk ?? null,
    outbound.dataset_id ?? null,
    outbound.mode_used ?? null,
    outbound.request_payload_json ?? null,
    outbound.http_status ?? null,
    outbound.response_body_json ?? null,
    outbound.fbtrace_id ?? null,
    outbound.result ?? null,
    outbound.reason ?? null
  );
  return result.lastID;
}

export async function updateInboundOutbound(db, inboundId, { outboundResult, outboundReason, status }) {
  await db.run(
    "UPDATE events SET outbound_result = ?, outbound_reason = ?, status = COALESCE(?, status) WHERE id = ?",
    outboundResult ?? null,
    outboundReason ?? null,
    status ?? null,
    inboundId
  );
}

export async function markInboundDuplicate(db, inboundId, duplicateCount = null) {
  if (duplicateCount === null || duplicateCount === undefined) {
    await db.run(
      "UPDATE events SET duplicate_count = COALESCE(duplicate_count, 0) + 1, last_seen_at = CURRENT_TIMESTAMP, status = 'duplicate' WHERE id = ?",
      inboundId
    );
    return;
  }
  await db.run(
    "UPDATE events SET duplicate_count = ?, last_seen_at = CURRENT_TIMESTAMP, status = 'duplicate' WHERE id = ?",
    duplicateCount,
    inboundId
  );
}

function safeJsonParse(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return { error: "invalid_json" };
  }
}

export async function listEvents(
  db,
  {
    limit = 50,
    siteId,
    datasetId,
    pixelId,
    status,
    eventName,
    videoId,
    eventType,
    receivedAtRange,
    videoMode
  }
) {
  const conditions = [];
  const params = [];

  if (siteId) {
    conditions.push("events.site_id = ?");
    params.push(siteId);
  }
  if (pixelId) {
    conditions.push("sites.pixel_id = ?");
    params.push(pixelId);
  }
  if (datasetId) {
    conditions.push("sites.dataset_fk = ?");
    params.push(datasetId);
  }
  if (status) {
    const normalizedStatus = String(status);
    if (normalizedStatus.startsWith("outbound_")) {
      const result = normalizedStatus.replace("outbound_", "");
      conditions.push("(events.status = ? OR COALESCE(outbound.result, events.outbound_result) = ?)");
      params.push(normalizedStatus, result);
    } else {
      conditions.push("events.status = ?");
      params.push(status);
    }
  }
  if (eventName) {
    conditions.push("events.event_name LIKE ?");
    params.push(`%${eventName}%`);
  }
  if (videoId) {
    conditions.push("events.video_id = ?");
    params.push(videoId);
  }
  if (eventType) {
    conditions.push("events.type = ?");
    params.push(eventType);
  }
  if (videoMode) {
    conditions.push("events.video_mode = ?");
    params.push(videoMode);
  }
  if (receivedAtRange?.startUtcMs !== undefined && receivedAtRange?.endUtcMs !== undefined) {
    conditions.push("events.received_at_utc_ms BETWEEN ? AND ?");
    params.push(receivedAtRange.startUtcMs, receivedAtRange.endUtcMs);
  }

  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const rows = await db.all(
    `
      SELECT events.*,
        sites.name AS site_name,
        sites.pixel_id AS pixel_id,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id,
        outbound.mode_used AS outbound_mode_used,
        outbound.request_payload_json AS outbound_request_json,
        outbound.http_status AS outbound_http_status,
        outbound.response_body_json AS outbound_response_json,
        outbound.fbtrace_id AS outbound_fbtrace_id,
        COALESCE(outbound.result, events.outbound_result) AS outbound_result,
        COALESCE(outbound.reason, events.outbound_reason) AS outbound_reason,
        COALESCE(outbound.http_status, events.meta_status) AS meta_status,
        COALESCE(outbound.response_body_json, events.meta_body) AS meta_body
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      LEFT JOIN (
        SELECT outbound_logs.*
        FROM outbound_logs
        INNER JOIN (
          SELECT inbound_id, MAX(id) AS max_id
          FROM outbound_logs
          GROUP BY inbound_id
        ) latest ON latest.inbound_id = outbound_logs.inbound_id AND latest.max_id = outbound_logs.id
      ) outbound ON outbound.inbound_id = events.id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      ${whereClause}
      ORDER BY events.received_at_utc_ms DESC, events.id DESC
      LIMIT ?
    `,
    ...params,
    limit
  );

  return rows.map(row => ({
    ...row,
    inbound_json: safeJsonParse(row.inbound_json),
    outbound_json: safeJsonParse(row.outbound_request_json || row.outbound_json),
    meta_body: safeJsonParse(row.meta_body),
    outbound_request_json: safeJsonParse(row.outbound_request_json),
    outbound_response_json: safeJsonParse(row.outbound_response_json)
  }));
}

export async function getEventById(db, eventId) {
  const row = await db.get(
    `
      SELECT events.*,
        sites.name AS site_name,
        sites.pixel_id AS pixel_id,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id,
        outbound.mode_used AS outbound_mode_used,
        outbound.request_payload_json AS outbound_request_json,
        outbound.http_status AS outbound_http_status,
        outbound.response_body_json AS outbound_response_json,
        outbound.fbtrace_id AS outbound_fbtrace_id,
        COALESCE(outbound.result, events.outbound_result) AS outbound_result,
        COALESCE(outbound.reason, events.outbound_reason) AS outbound_reason,
        COALESCE(outbound.http_status, events.meta_status) AS meta_status,
        COALESCE(outbound.response_body_json, events.meta_body) AS meta_body
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      LEFT JOIN (
        SELECT outbound_logs.*
        FROM outbound_logs
        INNER JOIN (
          SELECT inbound_id, MAX(id) AS max_id
          FROM outbound_logs
          GROUP BY inbound_id
        ) latest ON latest.inbound_id = outbound_logs.inbound_id AND latest.max_id = outbound_logs.id
      ) outbound ON outbound.inbound_id = events.id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      WHERE events.id = ?
    `,
    eventId
  );
  if (!row) return null;
  return {
    ...row,
    inbound_json: safeJsonParse(row.inbound_json),
    outbound_json: safeJsonParse(row.outbound_request_json || row.outbound_json),
    meta_body: safeJsonParse(row.meta_body),
    outbound_request_json: safeJsonParse(row.outbound_request_json),
    outbound_response_json: safeJsonParse(row.outbound_response_json)
  };
}

export async function createVideo(db, video) {
  await db.run(
    "INSERT INTO videos (id, site_id, video_id, name, page_url, video_source_url, provider, provider_video_id, selector, enabled, mode, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
    video.id,
    video.site_id,
    video.video_id,
    video.name ?? null,
    video.page_url ?? null,
    video.video_source_url ?? null,
    video.provider ?? null,
    video.provider_video_id ?? null,
    video.selector ?? "video",
    video.enabled ? 1 : 0,
    video.mode ?? "test"
  );
}

export async function updateVideo(db, video) {
  await db.run(
    "UPDATE videos SET site_id = ?, video_id = ?, name = ?, page_url = ?, video_source_url = ?, provider = ?, provider_video_id = ?, selector = ?, enabled = ?, mode = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
    video.site_id,
    video.video_id,
    video.name ?? null,
    video.page_url ?? null,
    video.video_source_url ?? null,
    video.provider ?? null,
    video.provider_video_id ?? null,
    video.selector ?? "video",
    video.enabled ? 1 : 0,
    video.mode ?? "test",
    video.id
  );
}

export async function deleteVideo(db, videoId) {
  await db.run("DELETE FROM videos WHERE id = ?", videoId);
}

export async function getVideoById(db, videoId) {
  return db.get(
    `
      SELECT videos.*,
        sites.name AS site_name,
        sites.site_key AS site_key,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id
      FROM videos
      LEFT JOIN sites ON videos.site_id = sites.site_id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      WHERE videos.id = ?
    `,
    videoId
  );
}

export async function getVideoBySiteAndVideoId(db, siteId, videoId) {
  return db.get(
    "SELECT * FROM videos WHERE site_id = ? AND video_id = ?",
    siteId,
    videoId
  );
}

export async function listVideos(db) {
  return db.all(
    `
      SELECT videos.*,
        sites.name AS site_name,
        sites.site_key AS site_key,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id
      FROM videos
      LEFT JOIN sites ON videos.site_id = sites.site_id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      ORDER BY videos.created_at DESC
    `
  );
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

export async function listErrorGroups(db, datasetId) {
  const conditions = [];
  const params = [];
  if (datasetId) {
    conditions.push("sites.dataset_fk = ?");
    params.push(datasetId);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  return db.all(
    `
      SELECT errors.type, COUNT(*) as count
      FROM errors
      LEFT JOIN sites ON errors.site_id = sites.site_id
      ${whereClause}
      GROUP BY errors.type
      ORDER BY count DESC
    `,
    ...params
  );
}

export async function listErrors(db, { type, limit = 20, datasetId, siteId, pixelId }) {
  const conditions = ["errors.type = ?"];
  const params = [type];
  if (datasetId) {
    conditions.push("sites.dataset_fk = ?");
    params.push(datasetId);
  }
  if (siteId) {
    conditions.push("errors.site_id = ?");
    params.push(siteId);
  }
  if (pixelId) {
    conditions.push("sites.pixel_id = ?");
    params.push(pixelId);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const rows = await db.all(
    `
      SELECT errors.*,
        sites.name AS site_name,
        sites.pixel_id AS pixel_id,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id
      FROM errors
      LEFT JOIN sites ON errors.site_id = sites.site_id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      ${whereClause}
      ORDER BY errors.id DESC
      LIMIT ?
    `,
    ...params,
    limit
  );

  return rows.map(row => ({
    ...row,
    meta_body: row.meta_body ? JSON.parse(row.meta_body) : null
  }));
}

export async function listRecentErrors(db, limit = 20, { datasetId, siteId, pixelId } = {}) {
  const conditions = [];
  const params = [];
  if (datasetId) {
    conditions.push("sites.dataset_fk = ?");
    params.push(datasetId);
  }
  if (siteId) {
    conditions.push("errors.site_id = ?");
    params.push(siteId);
  }
  if (pixelId) {
    conditions.push("sites.pixel_id = ?");
    params.push(pixelId);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  const rows = await db.all(
    `
      SELECT errors.*,
        sites.name AS site_name,
        sites.pixel_id AS pixel_id,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id
      FROM errors
      LEFT JOIN sites ON errors.site_id = sites.site_id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      ${whereClause}
      ORDER BY errors.id DESC
      LIMIT ?
    `,
    ...params,
    limit
  );

  return rows.map(row => ({
    ...row,
    meta_body: row.meta_body ? JSON.parse(row.meta_body) : null
  }));
}

export async function listRecentEventsForError(db, errorType, limit = 5, datasetId) {
  const conditions = ["errors.type = ?"];
  const params = [errorType];
  if (datasetId) {
    conditions.push("sites.dataset_fk = ?");
    params.push(datasetId);
  }
  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  return db.all(
    `
      SELECT events.id, events.event_name, events.event_id, events.status, events.created_at,
        sites.name AS site_name,
        sites.pixel_id AS pixel_id,
        datasets.name AS dataset_name,
        datasets.dataset_id AS dataset_id
      FROM errors
      JOIN events ON errors.event_db_id = events.id
      LEFT JOIN sites ON events.site_id = sites.site_id
      LEFT JOIN datasets ON sites.dataset_fk = datasets.id
      ${whereClause}
      ORDER BY errors.id DESC
      LIMIT ?
    `,
    ...params,
    limit
  );
}

export async function countEventsSince(db, hours, datasetId) {
  const params = [`-${hours} hours`];
  let whereClause = "WHERE events.created_at > datetime('now', ?)";
  if (datasetId) {
    whereClause += " AND sites.dataset_fk = ?";
    params.push(datasetId);
  }
  const row = await db.get(
    `
      SELECT COUNT(*) as count
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      ${whereClause}
    `,
    ...params
  );
  return row?.count ?? 0;
}

export async function countErrorsSince(db, hours, datasetId) {
  const params = [`-${hours} hours`];
  let whereClause = "WHERE errors.created_at > datetime('now', ?)";
  if (datasetId) {
    whereClause += " AND sites.dataset_fk = ?";
    params.push(datasetId);
  }
  const row = await db.get(
    `
      SELECT COUNT(*) as count
      FROM errors
      LEFT JOIN sites ON errors.site_id = sites.site_id
      ${whereClause}
    `,
    ...params
  );
  return row?.count ?? 0;
}

export async function countDedupedSince(db, hours, datasetId) {
  const params = [`-${hours} hours`];
  let whereClause = "WHERE events.status = 'deduped' AND events.created_at > datetime('now', ?)";
  if (datasetId) {
    whereClause += " AND sites.dataset_fk = ?";
    params.push(datasetId);
  }
  const row = await db.get(
    `
      SELECT COUNT(*) as count
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      ${whereClause}
    `,
    ...params
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
    "DELETE FROM outbound_logs WHERE inbound_id IN (SELECT id FROM events WHERE created_at < datetime('now', ?))",
    `-${retentionHours} hours`
  );
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
