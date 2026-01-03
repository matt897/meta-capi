import crypto from "crypto";
import express from "express";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import { v4 as uuid } from "uuid";
import path from "path";
import fs from "fs";
import {
  addLog,
  createSite,
  deleteSite,
  ensureSetting,
  getLogs,
  getSetting,
  getSiteById,
  getSiteByKey,
  getSites,
  initDb,
  listSettings,
  setSetting,
  storeEventId,
  updateSite,
  hasRecentEventId
} from "./db.js";

const app = express();
app.use(
  express.json({
    limit: "1mb",
    verify: (req, res, buf) => {
      req.rawBody = buf.toString("utf8");
    }
  })
);
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin";
const SESSION_SECRET = process.env.SESSION_SECRET || "meta-capi-session";
const DB_PATH = process.env.DB_PATH || "./data/meta-capi.sqlite";

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = await initDb(DB_PATH);

await ensureSetting(db, "admin_password", ADMIN_PASSWORD);
await ensureSetting(db, "hmac_required", process.env.HMAC_REQUIRED || "false");
await ensureSetting(db, "hmac_secret", process.env.HMAC_SECRET || "");
await ensureSetting(db, "rate_limit_per_min", process.env.RATE_LIMIT_PER_MIN || "60");
await ensureSetting(db, "log_limit", process.env.LOG_LIMIT || "200");

const SQLiteStore = SQLiteStoreFactory(session);

app.use(
  session({
    store: new SQLiteStore({ db: "sessions.sqlite", dir: dbDir }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax"
    }
  })
);

const rateLimitState = new Map();

async function getSettingValue(key, fallback = null) {
  const value = await getSetting(db, key);
  return value ?? fallback;
}

async function getSettingNumber(key, fallback) {
  const value = await getSettingValue(key);
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

async function getSettingBoolean(key, fallback = false) {
  const value = await getSettingValue(key);
  if (value === null) return fallback;
  return value === "true";
}

async function log(entry) {
  const logLimit = await getSettingNumber("log_limit", 200);
  const data = {
    time: new Date().toISOString(),
    ...entry
  };
  await addLog(db, data, logLimit);
  console.log(JSON.stringify(data));
}

function renderPage({ title, body, nav = true }) {
  const navHtml = nav
    ? `
    <nav class="nav">
      <a href="/dashboard/sites">Sites</a>
      <a href="/dashboard/logs">Event Console</a>
      <a href="/dashboard/settings">Settings</a>
      <a href="/logout">Logout</a>
    </nav>
  `
    : "";

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>${title}</title>
        <style>
          :root { color-scheme: light dark; }
          body { font-family: system-ui, sans-serif; margin: 0; padding: 0; background: #0f172a; color: #e2e8f0; }
          .container { max-width: 980px; margin: 0 auto; padding: 32px; }
          .nav { display: flex; gap: 16px; margin-bottom: 24px; }
          .nav a { color: #e2e8f0; text-decoration: none; font-weight: 600; }
          .card { background: #111827; border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: 0 10px 20px rgba(0,0,0,0.2); }
          label { display: block; font-weight: 600; margin-top: 12px; }
          input, textarea { width: 100%; padding: 10px; border-radius: 8px; border: 1px solid #334155; background: #0f172a; color: inherit; margin-top: 6px; }
          button { background: #38bdf8; border: none; padding: 10px 16px; border-radius: 8px; font-weight: 700; cursor: pointer; margin-top: 12px; }
          table { width: 100%; border-collapse: collapse; }
          th, td { text-align: left; padding: 10px; border-bottom: 1px solid #1f2937; }
          .muted { color: #94a3b8; font-size: 0.9rem; }
          .row { display: flex; gap: 16px; flex-wrap: wrap; }
          .row > div { flex: 1 1 280px; }
          code { background: #1f2937; padding: 2px 6px; border-radius: 4px; }
          .danger { background: #f97316; }
          .success { color: #4ade80; }
        </style>
      </head>
      <body>
        <div class="container">
          ${navHtml}
          ${body}
        </div>
      </body>
    </html>
  `;
}

function requireLogin(req, res, next) {
  if (!req.session?.isAdmin) {
    return res.redirect("/login");
  }
  next();
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/login", (req, res) => {
  const body = `
    <div class="card">
      <h1>Meta CAPI Gateway</h1>
      <p class="muted">Admin login</p>
      <form method="post" action="/login">
        <label>Password</label>
        <input type="password" name="password" required />
        <button type="submit">Login</button>
      </form>
    </div>
  `;
  res.send(renderPage({ title: "Login", body, nav: false }));
});

app.post("/login", async (req, res) => {
  const password = req.body.password ?? "";
  const adminPassword = await getSettingValue("admin_password", ADMIN_PASSWORD);

  if (password !== adminPassword) {
    await log({ type: "auth", message: "invalid admin login" });
    return res.status(401).send(renderPage({
      title: "Login",
      nav: false,
      body: `<div class="card"><h1>Login failed</h1><p>Invalid password.</p><a href="/login">Try again</a></div>`
    }));
  }

  req.session.isAdmin = true;
  await log({ type: "auth", message: "admin login" });
  res.redirect("/dashboard/sites");
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login");
  });
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.redirect("/dashboard/sites");
});

app.get("/dashboard/sites", requireLogin, async (req, res) => {
  const sites = await getSites(db);
  const body = `
    <div class="card">
      <h1>Sites</h1>
      <p class="muted">Manage site keys and Meta pixel credentials.</p>
    </div>
    <div class="card">
      <h2>Create site</h2>
      <form method="post" action="/dashboard/sites">
        <div class="row">
          <div>
            <label>Name</label>
            <input name="name" required />
          </div>
          <div>
            <label>Pixel ID</label>
            <input name="pixel_id" required />
          </div>
          <div>
            <label>Access Token</label>
            <input name="access_token" required />
          </div>
        </div>
        <label>Test Event Code</label>
        <input name="test_event_code" />
        <button type="submit">Create site</button>
      </form>
    </div>
    <div class="card">
      <h2>Existing sites</h2>
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Site ID</th>
            <th>Site Key</th>
            <th>Pixel ID</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${sites
            .map(
              site => `
            <tr>
              <td>${site.name ?? ""}</td>
              <td><code>${site.site_id}</code></td>
              <td><code>${site.site_key}</code></td>
              <td>${site.pixel_id ?? ""}</td>
              <td>
                <form method="post" action="/dashboard/sites/${site.site_id}" style="margin-bottom:8px;">
                  <label>Name</label>
                  <input name="name" value="${site.name ?? ""}" />
                  <label>Pixel ID</label>
                  <input name="pixel_id" value="${site.pixel_id ?? ""}" />
                  <label>Access Token</label>
                  <input name="access_token" value="${site.access_token ?? ""}" />
                  <label>Test Event Code</label>
                  <input name="test_event_code" value="${site.test_event_code ?? ""}" />
                  <button type="submit">Save</button>
                </form>
                <form method="post" action="/dashboard/sites/${site.site_id}/delete">
                  <button type="submit" class="danger">Delete</button>
                </form>
              </td>
            </tr>
          `
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;

  res.send(renderPage({ title: "Sites", body }));
});

app.post("/dashboard/sites", requireLogin, async (req, res) => {
  const site_id = uuid();
  const site_key = uuid();
  await createSite(db, {
    site_id,
    site_key,
    name: req.body.name,
    pixel_id: req.body.pixel_id,
    access_token: req.body.access_token,
    test_event_code: req.body.test_event_code
  });
  await log({ type: "admin", message: "site created", site_id });
  res.redirect("/dashboard/sites");
});

app.post("/dashboard/sites/:siteId", requireLogin, async (req, res) => {
  const site_id = req.params.siteId;
  await updateSite(db, {
    site_id,
    name: req.body.name,
    pixel_id: req.body.pixel_id,
    access_token: req.body.access_token,
    test_event_code: req.body.test_event_code
  });
  await log({ type: "admin", message: "site updated", site_id });
  res.redirect("/dashboard/sites");
});

app.post("/dashboard/sites/:siteId/delete", requireLogin, async (req, res) => {
  const site_id = req.params.siteId;
  await deleteSite(db, site_id);
  await log({ type: "admin", message: "site deleted", site_id });
  res.redirect("/dashboard/sites");
});

app.get("/dashboard/logs", requireLogin, async (req, res) => {
  const body = `
    <div class="card">
      <h1>Event Console</h1>
      <p class="muted">Polling every 2 seconds.</p>
    </div>
    <div class="card">
      <pre id="log-output" style="white-space: pre-wrap;"></pre>
    </div>
    <script>
      async function fetchLogs() {
        const response = await fetch('/admin/logs?limit=100');
        const data = await response.json();
        document.getElementById('log-output').textContent = data
          .map(entry => JSON.stringify(entry))
          .join('\n');
      }
      fetchLogs();
      setInterval(fetchLogs, 2000);
    </script>
  `;
  res.send(renderPage({ title: "Event Console", body }));
});

app.get("/dashboard/settings", requireLogin, async (req, res) => {
  const settings = Object.fromEntries((await listSettings(db)).map(s => [s.key, s.value]));
  const body = `
    <div class="card">
      <h1>Settings</h1>
      <p class="muted">Global configuration stored in SQLite.</p>
      <form method="post" action="/dashboard/settings">
        <label>Admin password</label>
        <input name="admin_password" type="password" value="${settings.admin_password ?? ""}" />
        <label>HMAC required (true/false)</label>
        <input name="hmac_required" value="${settings.hmac_required ?? "false"}" />
        <label>HMAC secret</label>
        <input name="hmac_secret" value="${settings.hmac_secret ?? ""}" />
        <label>Rate limit per minute</label>
        <input name="rate_limit_per_min" value="${settings.rate_limit_per_min ?? "60"}" />
        <label>Log limit</label>
        <input name="log_limit" value="${settings.log_limit ?? "200"}" />
        <button type="submit">Save settings</button>
      </form>
    </div>
  `;
  res.send(renderPage({ title: "Settings", body }));
});

app.post("/dashboard/settings", requireLogin, async (req, res) => {
  await setSetting(db, "admin_password", req.body.admin_password || ADMIN_PASSWORD);
  await setSetting(db, "hmac_required", req.body.hmac_required || "false");
  await setSetting(db, "hmac_secret", req.body.hmac_secret || "");
  await setSetting(db, "rate_limit_per_min", req.body.rate_limit_per_min || "60");
  await setSetting(db, "log_limit", req.body.log_limit || "200");
  await log({ type: "admin", message: "settings updated" });
  res.redirect("/dashboard/settings");
});

app.get("/admin/sites", requireLogin, async (req, res) => {
  const sites = await getSites(db);
  res.json(sites);
});

app.get("/admin/logs", requireLogin, async (req, res) => {
  const limit = Number.parseInt(req.query.limit ?? "100", 10);
  const logs = await getLogs(db, Number.isNaN(limit) ? 100 : limit);
  res.json(logs);
});

function generateEventId({ siteId, eventName, eventTime, identifiers }) {
  if (!eventName || !eventTime || identifiers.length === 0) {
    return null;
  }
  const raw = `${siteId}:${eventName}:${eventTime}:${identifiers.join("|")}`;
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function verifySignature({ secret, rawBody, signature }) {
  const expected = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("hex");
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
  } catch {
    return false;
  }
}

function checkRateLimit(siteId, limitPerMinute) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const current = rateLimitState.get(siteId) || { count: 0, windowStart: now };

  if (now - current.windowStart > windowMs) {
    current.count = 0;
    current.windowStart = now;
  }

  current.count += 1;
  rateLimitState.set(siteId, current);

  return current.count <= limitPerMinute;
}

app.post("/collect", async (req, res) => {
  const siteKey = req.headers["x-site-key"];
  const site = siteKey ? await getSiteByKey(db, siteKey) : null;

  if (!site) {
    await log({ type: "error", message: "invalid site key" });
    return res.status(401).json({ error: "invalid site key" });
  }

  const limitPerMinute = await getSettingNumber("rate_limit_per_min", 60);
  if (!checkRateLimit(site.site_id, limitPerMinute)) {
    await log({ type: "rate_limit", message: "rate limit exceeded", site_id: site.site_id });
    return res.status(429).json({ error: "rate limit exceeded" });
  }

  const hmacRequired = await getSettingBoolean("hmac_required", false);
  const hmacSecret = await getSettingValue("hmac_secret", "");
  const signature = req.headers["x-signature"];

  if (hmacRequired) {
    if (!hmacSecret) {
      await log({ type: "error", message: "hmac required but secret missing", site_id: site.site_id });
      return res.status(500).json({ error: "hmac secret not configured" });
    }
    if (!signature || !verifySignature({ secret: hmacSecret, rawBody: req.rawBody ?? "", signature })) {
      await log({ type: "error", message: "invalid signature", site_id: site.site_id });
      return res.status(401).json({ error: "invalid signature" });
    }
  } else if (signature && hmacSecret) {
    if (!verifySignature({ secret: hmacSecret, rawBody: req.rawBody ?? "", signature })) {
      await log({ type: "error", message: "invalid signature", site_id: site.site_id });
      return res.status(401).json({ error: "invalid signature" });
    }
  }

  const inboundEvent = { ...req.body };
  let eventId = inboundEvent.event_id;

  if (!eventId) {
    const identifiers = [];
    const userData = inboundEvent.user_data || {};
    if (userData.external_id) identifiers.push(userData.external_id);
    if (userData.em) identifiers.push(userData.em);
    if (userData.ph) identifiers.push(userData.ph);

    eventId = generateEventId({
      siteId: site.site_id,
      eventName: inboundEvent.event_name,
      eventTime: inboundEvent.event_time,
      identifiers
    });

    if (eventId) {
      inboundEvent.event_id = eventId;
    }
  }

  if (eventId) {
    const seen = await hasRecentEventId(db, site.site_id, eventId);
    if (seen) {
      await log({
        type: "dedup",
        message: "duplicate event suppressed",
        site_id: site.site_id,
        meta: { event_id: eventId, event_name: inboundEvent.event_name }
      });
      return res.json({ ok: true, deduped: true });
    }
    await storeEventId(db, site.site_id, eventId);
  }

  const payload = {
    data: [inboundEvent],
    test_event_code: site.test_event_code
  };

  const url = `https://graph.facebook.com/v19.0/${site.pixel_id}/events?access_token=${site.access_token}`;

  try {
    const response = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload)
    });
    const result = await response.json();

    await log({
      type: "event",
      site_id: site.site_id,
      message: inboundEvent.event_name,
      status: response.status,
      meta: { request: inboundEvent, response: result }
    });

    res.json({ ok: true, meta: result });
  } catch (err) {
    await log({ type: "error", error: err.toString(), site_id: site.site_id });
    res.status(500).json({ error: "failed to send to meta" });
  }
});

app.listen(PORT, () => {
  console.log(`Meta CAPI Gateway running on :${PORT}`);
});
