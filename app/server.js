import crypto from "crypto";
import express from "express";
import helmet from "helmet";
import session from "express-session";
import SQLiteStoreFactory from "connect-sqlite3";
import { v4 as uuid } from "uuid";
import bcrypt from "bcrypt";
import path from "path";
import fs from "fs";
import {
  cleanupRetention,
  countUsers,
  countDedupedSince,
  countErrorsSince,
  countErrorsTodayBySite,
  countEventsSince,
  countEventsTodayBySite,
  createSite,
  createVideo,
  createUser,
  deleteSite,
  deleteVideo,
  ensureSetting,
  getUserById,
  getUserByUsername,
  getEventById,
  getSiteById,
  getSiteByKey,
  getSites,
  getVideoById,
  getVideoBySiteAndVideoId,
  initDb,
  insertError,
  insertEvent,
  listErrorGroups,
  listErrors,
  listEvents,
  listVideos,
  listRecentErrors,
  listRecentEventsForError,
  listSettings,
  rotateSiteKey,
  setSetting,
  updateUserPassword,
  storeEventId,
  updateSite,
  updateVideo,
  getSetting,
  hasRecentEventId
} from "./db.js";

const app = express();
app.set("trust proxy", true);
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"],
        frameAncestors: ["'self'"]
      }
    }
  })
);
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
const DEFAULT_ADMIN_USER = process.env.DEFAULT_ADMIN_USER || "matt";
const DEFAULT_ADMIN_PASSWORD = process.env.DEFAULT_ADMIN_PASSWORD || "admin123";
const SESSION_SECRET = process.env.SESSION_SECRET || "meta-capi-session";
const DB_PATH = process.env.DB_PATH || "./data/meta-capi.sqlite";
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL?.replace(/\/+$/, "") || null;
const APP_ENCRYPTION_KEY = process.env.APP_ENCRYPTION_KEY || "";

const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = await initDb(DB_PATH);

await ensureSetting(db, "default_meta_api_version", "v24.0");
await ensureSetting(db, "retry_count", "1");
await ensureSetting(db, "dedup_ttl_hours", "48");
await ensureSetting(db, "log_retention_hours", "168");
await ensureSetting(db, "hmac_required", process.env.HMAC_REQUIRED || "false");
await ensureSetting(db, "hmac_secret", process.env.HMAC_SECRET || "");
await ensureSetting(db, "rate_limit_per_min", process.env.RATE_LIMIT_PER_MIN || "60");

if ((await countUsers(db)) === 0) {
  const passwordHash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 12);
  await createUser(db, { username: DEFAULT_ADMIN_USER, password_hash: passwordHash });
}

const SQLiteStore = SQLiteStoreFactory(session);
const encryptionKey = (() => {
  if (!APP_ENCRYPTION_KEY) return null;
  const trimmed = APP_ENCRYPTION_KEY.trim();
  let keyBuffer = null;
  if (/^[0-9a-f]{64}$/i.test(trimmed)) {
    keyBuffer = Buffer.from(trimmed, "hex");
  } else {
    try {
      keyBuffer = Buffer.from(trimmed, "base64");
    } catch {
      return null;
    }
  }
  return keyBuffer.length === 32 ? keyBuffer : null;
})();

app.use(
  session({
    store: new SQLiteStore({ db: path.basename(DB_PATH), dir: dbDir }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: "auto"
    }
  })
);

app.use("/assets", express.static(path.join(process.cwd(), "public")));

const rateLimitState = new Map();

const TEST_EVENT_TYPES = ["PageView", "ViewContent", "Lead", "AddToCart", "Purchase"];
const DEFAULT_TEST_EVENT_SOURCE_URL = "https://example.com/test";
const DEFAULT_TEST_EVENT_IP = "1.1.1.1";
const DEFAULT_TEST_EVENT_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

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
  const data = {
    time: new Date().toISOString(),
    ...entry
  };
  const redacted = JSON.stringify(data, (key, value) => {
    if (typeof value === "string" && key.toLowerCase().includes("access_token")) {
      return maskToken(value);
    }
    return value;
  });
  console.log(redacted);
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function encryptToken(value) {
  if (!value) return value;
  if (!encryptionKey) return value;
  if (value.startsWith("enc:")) return value;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encryptionKey, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `enc:${Buffer.concat([iv, tag, encrypted]).toString("base64")}`;
}

function decryptToken(value) {
  if (!value) return value;
  if (!value.startsWith("enc:")) return value;
  if (!encryptionKey) return null;
  try {
    const buffer = Buffer.from(value.slice(4), "base64");
    const iv = buffer.subarray(0, 12);
    const tag = buffer.subarray(12, 28);
    const encrypted = buffer.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", encryptionKey, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

function resolveAccessToken(site) {
  if (!site?.access_token) return null;
  return decryptToken(site.access_token);
}

function renderPage({ title, body, nav = true }) {
  const navHtml = nav
    ? `
    <nav class="nav">
      <a href="/dashboard">Dashboard</a>
      <a href="/dashboard/sites">Sites</a>
      <a href="/dashboard/videos">Videos</a>
      <a href="/dashboard/live">Logs</a>
      <a href="/admin/settings">Settings</a>
      <form method="post" action="/logout" class="nav-form">
        <button type="submit" class="nav-button">Logout</button>
      </form>
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
        <link rel="stylesheet" href="/assets/styles.css" />
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

function wantsJson(req) {
  if (req.path === "/admin") return false;
  const accept = req.headers.accept || "";
  if (accept.includes("text/html")) return false;
  return req.path.startsWith("/admin") || accept.includes("application/json") || req.xhr;
}

function requireAuth(req, res, next) {
  if (!req.session?.user) {
    if (wantsJson(req)) {
      return res.status(401).json({ ok: false, error: "unauthorized" });
    }
    return res.redirect("/login");
  }
  next();
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function renderStatusPill(status) {
  const normalized = status || "unknown";
  return `<span class="pill pill-${normalized}">${normalized.replace("_", " ")}</span>`;
}

function maskToken(token) {
  if (!token) return "—";
  const trimmed = token.trim();
  if (trimmed.length <= 8) return "••••";
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)}`;
}

function slugify(value) {
  if (!value) return "";
  return String(value)
    .toLowerCase()
    .replace(/https?:\/\//g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
}

const VIDEO_PROVIDER_LABELS = {
  html5: "HTML5",
  vimeo: "Vimeo",
  youtube: "YouTube",
  mux: "Mux",
  cloudflare: "Cloudflare",
  s3: "S3",
  r2: "R2",
  unknown: "Unknown"
};

function parseVideoSourceInfo(videoSourceUrl) {
  if (!videoSourceUrl) return { provider: null, providerVideoId: null };
  const trimmed = String(videoSourceUrl).trim();
  if (!trimmed) return { provider: null, providerVideoId: null };

  let parsedUrl;
  try {
    parsedUrl = new URL(trimmed);
  } catch (error) {
    return { provider: "unknown", providerVideoId: null };
  }

  const host = parsedUrl.hostname.toLowerCase();
  const path = parsedUrl.pathname || "";
  const segments = path.split("/").filter(Boolean);

  if (host.includes("youtube.com") || host === "youtu.be") {
    let providerVideoId = null;
    if (host === "youtu.be") {
      providerVideoId = segments[0] || null;
    } else if (path.startsWith("/watch")) {
      providerVideoId = parsedUrl.searchParams.get("v");
    } else if (path.startsWith("/embed/") || path.startsWith("/shorts/")) {
      providerVideoId = segments[1] || null;
    }
    return { provider: "youtube", providerVideoId: providerVideoId || null };
  }

  if (host.includes("vimeo.com")) {
    const match = path.match(/\/(\d+)/);
    return { provider: "vimeo", providerVideoId: match ? match[1] : null };
  }

  if (host.includes("mux.com")) {
    return { provider: "mux", providerVideoId: segments[0] || null };
  }

  if (host.includes("videodelivery.net")) {
    return { provider: "cloudflare", providerVideoId: segments[0] || null };
  }

  if (host.includes("r2.cloudflarestorage.com")) {
    return { provider: "r2", providerVideoId: null };
  }

  if (host.includes("amazonaws.com")) {
    return { provider: "s3", providerVideoId: null };
  }

  if (path.toLowerCase().endsWith(".mp4")) {
    return { provider: "html5", providerVideoId: null };
  }

  return { provider: "unknown", providerVideoId: null };
}

function formatVideoProvider(provider) {
  if (!provider) return "Unknown";
  return VIDEO_PROVIDER_LABELS[provider] || provider;
}

function buildVideoSnippet({ host, siteKey, videoId, selector }) {
  const safeSelector = selector || "video";
  return `<script
  src="${host}/sdk/video-tracker.js"
  data-site-key="${siteKey}"
  data-video-id="${videoId}"
  data-selector="${safeSelector}">
</script>`;
}

function resolveBaseUrl(req) {
  if (PUBLIC_BASE_URL) {
    return PUBLIC_BASE_URL;
  }
  return `${req.protocol}://${req.get("host")}`;
}

const VIDEO_MODE_LABELS = {
  off: "Off",
  test: "Test",
  live: "Live"
};

const VIDEO_MODE_HINTS = {
  off: "Not sending to Meta",
  test: "Using test_event_code",
  live: "Sending production events"
};

function normalizeVideoMode(value) {
  if (value === "off" || value === "test" || value === "live") {
    return value;
  }
  return "test";
}

function getSiteStatus(site) {
  const accessToken = resolveAccessToken(site);
  if (!site.pixel_id || !accessToken) {
    return "not_configured";
  }
  if (!site.send_to_meta || site.dry_run) {
    return "dry_run";
  }
  return "ready";
}

function renderSiteStatus(site) {
  const status = getSiteStatus(site);
  const label = status.replace("_", " ");
  return `<span class="pill pill-${status}">${label}</span>`;
}

function sanitizePayload(payload, logFullPayloads) {
  if (logFullPayloads) return payload;
  if (!payload) return null;
  return {
    note: "Payload logging disabled for this site.",
    event_name: payload.event_name,
    event_time: payload.event_time,
    event_id: payload.event_id,
    user_data_keys: Object.keys(payload.user_data || {}),
    custom_data_keys: Object.keys(payload.custom_data || {})
  };
}

function generateEventId({ siteId, eventName, eventTime, identifiers }) {
  if (!eventName || !eventTime || identifiers.length === 0) {
    return null;
  }
  const raw = `${siteId}:${eventName}:${eventTime}:${identifiers.join("|")}`;
  return crypto.createHash("sha256").update(raw).digest("hex");
}

function normalizeContentIds(value) {
  if (!value) return null;
  if (Array.isArray(value)) {
    const trimmed = value.map(item => String(item).trim()).filter(Boolean);
    return trimmed.length ? trimmed : null;
  }
  if (typeof value === "string") {
    const trimmed = value
      .split(",")
      .map(item => item.trim())
      .filter(Boolean);
    return trimmed.length ? trimmed : null;
  }
  return null;
}

function toNumber(value, fallback) {
  if (value === undefined || value === null || value === "") return fallback;
  const parsed = Number.parseFloat(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeEmail(value) {
  if (!value) return null;
  const trimmed = String(value).trim().toLowerCase();
  return trimmed.length ? trimmed : null;
}

function normalizePhone(value) {
  if (!value) return null;
  const digits = String(value).replace(/[^\d]/g, "");
  return digits.length ? digits : null;
}

function normalizeExternalId(value) {
  if (!value) return null;
  const trimmed = String(value).trim();
  return trimmed.length ? trimmed : null;
}

function sha256Hash(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function buildHashedUserData(overrides = {}) {
  const hashed = {};
  if (!overrides.em) {
    const normalizedEmail = normalizeEmail(overrides.email);
    if (normalizedEmail) hashed.em = sha256Hash(normalizedEmail);
  }
  if (!overrides.ph) {
    const normalizedPhone = normalizePhone(overrides.phone);
    if (normalizedPhone) hashed.ph = sha256Hash(normalizedPhone);
  }
  const normalizedExternalId = normalizeExternalId(overrides.external_id);
  if (normalizedExternalId) hashed.external_id = sha256Hash(normalizedExternalId);
  return hashed;
}

function parseCookies(header) {
  if (!header) return {};
  return header.split(";").reduce((acc, part) => {
    const trimmed = part.trim();
    if (!trimmed) return acc;
    const [key, ...rest] = trimmed.split("=");
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join("=") || "");
    return acc;
  }, {});
}

function getForwardedFor(req) {
  const header = req.headers["x-forwarded-for"];
  if (Array.isArray(header)) {
    return header[0]?.split(",")[0]?.trim() || null;
  }
  if (typeof header === "string") {
    return header.split(",")[0]?.trim() || null;
  }
  return null;
}

function getClientIp(req) {
  return getForwardedFor(req) || req.ip || null;
}

function resolveEventSourceUrl(event, req) {
  if (event.event_source_url) return event.event_source_url;
  const referer = req.get("referer");
  if (referer) return referer;
  const origin = req.get("origin");
  if (origin) return origin;
  return null;
}

function deriveFbcFromFbclid(fbclid) {
  if (!fbclid) return null;
  return `fb.1.${Math.floor(Date.now() / 1000)}.${fbclid}`;
}

function enrichUserData(event, req) {
  const existing = event.user_data && typeof event.user_data === "object" ? event.user_data : {};
  const userData = { ...existing };
  const userAgent = req.get("user-agent");
  const clientIp = getClientIp(req);

  if (!userData.client_user_agent && userAgent) {
    userData.client_user_agent = userAgent;
  }
  if (!userData.client_ip_address && clientIp) {
    userData.client_ip_address = clientIp;
  }

  const cookies = parseCookies(req.headers.cookie || "");
  const fbp = userData.fbp || event.fbp || cookies._fbp;
  const fbc = userData.fbc || event.fbc || cookies._fbc;

  if (!userData.fbp && fbp) {
    userData.fbp = fbp;
  }
  if (!userData.fbc && fbc) {
    userData.fbc = fbc;
  }

  event.user_data = userData;
  return userData;
}

function hasMinimumUserData(userData) {
  return Boolean(userData?.client_ip_address && userData?.client_user_agent);
}

function maskHash(value) {
  if (!value) return value;
  const text = String(value);
  if (text.length <= 10) return "••••";
  return `${text.slice(0, 6)}…${text.slice(-4)}`;
}

function maskUserDataHashes(userData) {
  if (!userData || typeof userData !== "object") return userData;
  const maskValue = value => {
    if (Array.isArray(value)) {
      return value.map(item => maskHash(item));
    }
    return maskHash(value);
  };
  return {
    ...userData,
    em: userData.em ? maskValue(userData.em) : userData.em,
    ph: userData.ph ? maskValue(userData.ph) : userData.ph,
    external_id: userData.external_id ? maskValue(userData.external_id) : userData.external_id
  };
}

function maskPayloadForDisplay(payload) {
  if (!payload || typeof payload !== "object") return payload;
  return {
    ...payload,
    user_data: maskUserDataHashes(payload.user_data)
  };
}

function maskEventForDisplay(event) {
  if (!event) return event;
  return {
    ...event,
    inbound_json: maskPayloadForDisplay(event.inbound_json),
    outbound_json: maskPayloadForDisplay(event.outbound_json)
  };
}

function buildTestEvent(eventType, overrides = {}, context = {}) {
  const now = context.now ?? Math.floor(Date.now() / 1000);
  const eventSourceUrl = overrides.event_source_url || context.event_source_url || DEFAULT_TEST_EVENT_SOURCE_URL;
  const eventId = `${eventType}-${uuid()}`;

  const userData = {
    client_user_agent: overrides.client_user_agent || DEFAULT_TEST_EVENT_UA,
    client_ip_address: overrides.client_ip_address || DEFAULT_TEST_EVENT_IP
  };

  if (overrides.user_data && typeof overrides.user_data === "object") {
    Object.assign(userData, overrides.user_data);
  }

  ["em", "ph", "external_id", "fbp", "fbc"].forEach(key => {
    if (overrides[key]) {
      userData[key] = overrides[key];
    }
  });

  const customData = {};

  switch (eventType) {
    case "ViewContent": {
      customData.content_name = overrides.content_name || "Test Content";
      customData.content_type = overrides.content_type || "product";
      const contentIds = normalizeContentIds(overrides.content_ids);
      if (contentIds) customData.content_ids = contentIds;
      break;
    }
    case "Lead": {
      customData.content_name = overrides.content_name || "Test Lead";
      break;
    }
    case "AddToCart": {
      customData.value = toNumber(overrides.value, 1.0);
      customData.currency = overrides.currency || "USD";
      customData.content_type = overrides.content_type || "product";
      customData.content_ids = normalizeContentIds(overrides.content_ids) || ["test_sku"];
      if (overrides.content_name) customData.content_name = overrides.content_name;
      break;
    }
    case "Purchase": {
      customData.value = toNumber(overrides.value, 1.0);
      customData.currency = overrides.currency || "USD";
      customData.content_type = overrides.content_type || "product";
      customData.content_ids = normalizeContentIds(overrides.content_ids) || ["test_sku"];
      if (overrides.content_name) customData.content_name = overrides.content_name;
      break;
    }
    default:
      break;
  }

  if (overrides.custom_data && typeof overrides.custom_data === "object") {
    Object.assign(customData, overrides.custom_data);
  }

  const event = {
    event_name: eventType,
    event_time: now,
    event_id: eventId,
    action_source: overrides.action_source || "website",
    event_source_url: eventSourceUrl,
    user_data: userData
  };

  if (Object.keys(customData).length) {
    event.custom_data = customData;
  }

  return event;
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

function checkRateLimit(key, limitPerMinute) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const current = rateLimitState.get(key) || { count: 0, windowStart: now };

  if (now - current.windowStart > windowMs) {
    current.count = 0;
    current.windowStart = now;
  }

  current.count += 1;
  rateLimitState.set(key, current);

  return current.count <= limitPerMinute;
}

async function sendToMeta({ url, payload, retryCount }) {
  let attempt = 0;
  let lastError = null;

  while (attempt <= retryCount) {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload)
      });
      const text = await response.text();
      let body = null;

      try {
        body = text ? JSON.parse(text) : null;
      } catch {
        body = { raw: text };
      }

      if (response.status >= 500 && attempt < retryCount) {
        attempt += 1;
        continue;
      }

      return { response, body };
    } catch (err) {
      lastError = err;
      if (attempt < retryCount) {
        attempt += 1;
        continue;
      }
      throw err;
    }
  }

  if (lastError) throw lastError;
  throw new Error("Unknown Meta API error");
}

function getErrorSuggestion(type) {
  const suggestions = {
    auth: "Check the site key or admin credentials and confirm access tokens are valid.",
    validation: "Ensure event_name, event_time, and user_data fields match Meta requirements.",
    meta_4xx: "Meta rejected the payload. Verify pixel ID, access token, and required fields.",
    meta_5xx: "Meta is responding with server errors. Retry later or reduce request volume.",
    network: "Gateway could not reach Meta. Check outbound connectivity and retry settings."
  };
  return suggestions[type] || "Review the error details and recent events for context.";
}

async function sendTestEvent({ site, eventType, overrides }) {
  const accessToken = resolveAccessToken(site);
  const hashedOverrides = buildHashedUserData(overrides);
  const preparedOverrides = {
    ...overrides,
    ...hashedOverrides
  };
  if (hashedOverrides.external_id) {
    preparedOverrides.external_id = hashedOverrides.external_id;
  }

  const event = buildTestEvent(eventType, preparedOverrides, {
    now: Math.floor(Date.now() / 1000),
    event_source_url: DEFAULT_TEST_EVENT_SOURCE_URL
  });

  const payload = {
    data: [event]
  };

  if (site.test_event_code) {
    payload.test_event_code = site.test_event_code;
  }

  const outboundLog = JSON.stringify({
    ...payload,
    data: [sanitizePayload(event, site.log_full_payloads === 1)]
  });
  const inboundLog = JSON.stringify(sanitizePayload(event, site.log_full_payloads === 1));

  const baseResponse = {
    ok: false,
    site_id: site.site_id,
    event_type: eventType,
    outbound_payload: payload,
    meta_status: 0,
    meta_response: null,
    note: ""
  };

  if (!site.pixel_id || !accessToken) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id: event.event_id,
      event_name: event.event_name,
      event_source_url: event.event_source_url,
      status: "test_event_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "missing_credentials" })
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "test_event",
      site_id: site.site_id,
      message: "missing credentials",
      event_type: eventType
    });
    return {
      ...baseResponse,
      ok: false,
      forwarded: false,
      reason: "missing_credentials",
      meta_response: { reason: "missing_credentials" },
      note: "Missing credentials"
    };
  }

  if (!site.test_event_code) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id: event.event_id,
      event_name: event.event_name,
      event_source_url: event.event_source_url,
      status: "test_event_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "missing_test_event_code" })
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "test_event",
      site_id: site.site_id,
      message: "missing test event code",
      event_type: eventType
    });
    return {
      ...baseResponse,
      ok: false,
      forwarded: false,
      reason: "missing_test_event_code",
      meta_response: { reason: "missing_test_event_code" },
      note: "Missing test event code"
    };
  }

  if (!site.send_to_meta || site.dry_run) {
    const reason = site.dry_run ? "dry_run" : "send_disabled";
    await insertEvent(db, {
      site_id: site.site_id,
      event_id: event.event_id,
      event_name: event.event_name,
      event_source_url: event.event_source_url,
      status: "test_event_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason })
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "test_event",
      site_id: site.site_id,
      message: "test event skipped",
      event_type: eventType,
      reason
    });
    return {
      ...baseResponse,
      ok: true,
      forwarded: false,
      reason,
      meta_response: { reason },
      note: reason === "dry_run" ? "Dry-run: not sent" : "Send to Meta disabled"
    };
  }

  const apiVersion = await getSettingValue("default_meta_api_version", "v24.0");
  const url = `https://graph.facebook.com/${apiVersion}/${site.pixel_id}/events?access_token=${accessToken}`;

  try {
    const retryCount = await getSettingNumber("retry_count", 1);
    const { response, body } = await sendToMeta({ url, payload, retryCount });
    const status = response.status;

    const eventDbId = await insertEvent(db, {
      site_id: site.site_id,
      event_id: event.event_id,
      event_name: event.event_name,
      event_source_url: event.event_source_url,
      status: response.ok ? "test_event_sent" : "test_event_failed",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: status,
      meta_body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorType = status >= 500 ? "meta_5xx" : "meta_4xx";
      await insertError(db, {
        type: errorType,
        site_id: site.site_id,
        event_db_id: eventDbId,
        event_id: event.event_id,
        message: "Meta API error",
        meta_status: status,
        meta_body: JSON.stringify(body)
      });
    }

    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "test_event",
      site_id: site.site_id,
      message: "test event sent",
      event_type: eventType,
      status
    });

    return {
      ...baseResponse,
      ok: response.ok,
      forwarded: true,
      meta_status: status,
      meta_response: body,
      note: "Sent with test_event_code"
    };
  } catch (err) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id: event.event_id,
      event_name: event.event_name,
      event_source_url: event.event_source_url,
      status: "test_event_error",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: null,
      meta_body: JSON.stringify({ error: err.toString() })
    });

    await insertError(db, {
      type: "network",
      site_id: site.site_id,
      event_id: event.event_id,
      message: err.toString()
    });

    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({ type: "test_event", error: err.toString(), site_id: site.site_id });

    return {
      ...baseResponse,
      ok: false,
      forwarded: false,
      reason: "network_error",
      meta_response: { error: err.toString() },
      note: "Network error"
    };
  }
}

app.get("/health", (req, res) => res.json({ ok: true }));

app.get("/sdk/config", async (req, res) => {
  res.set("access-control-allow-origin", "*");
  const siteKey = req.query.site_key;
  const videoId = req.query.video_id;
  if (!siteKey || !videoId) {
    return res.json({ enabled: false });
  }

  const site = await getSiteByKey(db, siteKey);
  if (!site) {
    return res.json({ enabled: false });
  }

  const video = await getVideoBySiteAndVideoId(db, site.site_id, videoId);
  if (!video || !video.enabled) {
    return res.json({ enabled: false });
  }

  const mode = normalizeVideoMode(video.mode);
  res.json({
    enabled: mode !== "off",
    mode,
    milestones: [25, 50, 75, 95]
  });
});

app.get("/sdk/video-tracker.js", (req, res) => {
  res.set("content-type", "application/javascript");
  res.set("access-control-allow-origin", "*");
  res.send(`
    (function() {
      function getCurrentScripts() {
        return Array.from(document.querySelectorAll('script[data-site-key][data-video-id]'));
      }

      function getCookieValue(name) {
        const match = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/([.$?*|{}()\\[\\]\\\\/+^])/g, '\\\\$1') + '=([^;]*)'));
        return match ? decodeURIComponent(match[1]) : '';
      }

      function getSessionId() {
        const storageKey = 'metaCapiVideoSession';
        try {
          const existing = sessionStorage.getItem(storageKey);
          if (existing) return existing;
          const generated = (crypto && crypto.randomUUID) ? crypto.randomUUID() : Math.random().toString(36).slice(2);
          sessionStorage.setItem(storageKey, generated);
          return generated;
        } catch (err) {
          return Math.random().toString(36).slice(2);
        }
      }

      async function sha256Hex(text) {
        if (!crypto || !crypto.subtle) {
          return text;
        }
        const data = new TextEncoder().encode(text);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      }

      async function setupTracker(script) {
        const siteKey = script.dataset.siteKey;
        const videoId = script.dataset.videoId;
        const selector = script.dataset.selector || 'video';
        if (!siteKey || !videoId) return;

        const baseUrl = new URL(script.src, window.location.href).origin;
        try {
          const configRes = await fetch(baseUrl + '/sdk/config?site_key=' + encodeURIComponent(siteKey) + '&video_id=' + encodeURIComponent(videoId));
          const config = await configRes.json();
          if (!config || !config.enabled) return;

          const milestones = (config.milestones || [25, 50, 75, 95]).slice().sort((a, b) => a - b);
          const video = document.querySelector(selector);
          if (!video) return;

          const sessionId = getSessionId();
          const fired = new Set();
          let watchedSeconds = 0;
          let lastTime = 0;

          function getDuration() {
            return Number.isFinite(video.duration) ? video.duration : 0;
          }

          function currentPercent() {
            const duration = getDuration();
            if (!duration) return 0;
            return Math.floor((watchedSeconds / duration) * 100);
          }

          async function sendMilestone(percent) {
            if (fired.has(percent)) return;
            fired.add(percent);
            const eventId = await sha256Hex(videoId + '|' + percent + '|' + sessionId);
            const payload = {
              video_id: videoId,
              percent: percent,
              event_id: eventId,
              event_source_url: window.location.href,
              watch_seconds: Math.round(watchedSeconds),
              duration: Math.round(getDuration())
            };
            const fbp = getCookieValue('_fbp');
            const fbc = getCookieValue('_fbc');
            if (fbp) payload.fbp = fbp;
            if (fbc) payload.fbc = fbc;
            const fbclid = new URLSearchParams(window.location.search).get('fbclid');
            if (fbclid) payload.fbclid = fbclid;

            try {
              await fetch(baseUrl + '/v/track', {
                method: 'POST',
                headers: {
                  'content-type': 'application/json',
                  'x-site-key': siteKey
                },
                body: JSON.stringify(payload),
                keepalive: true
              });
            } catch (err) {
              // fail silently
            }
          }

          function checkMilestones() {
            const percent = currentPercent();
            milestones.forEach(milestone => {
              if (percent >= milestone) {
                sendMilestone(milestone);
              }
            });
          }

          video.addEventListener('timeupdate', () => {
            if (video.paused || video.seeking) {
              lastTime = video.currentTime;
              return;
            }
            const delta = video.currentTime - lastTime;
            if (delta > 0 && delta < 2) {
              watchedSeconds += delta;
            }
            lastTime = video.currentTime;
            checkMilestones();
          });

          video.addEventListener('ended', () => {
            watchedSeconds = Math.max(watchedSeconds, getDuration());
            checkMilestones();
          });
        } catch (err) {
          // fail silently
        }
      }

      const scripts = getCurrentScripts();
      scripts.forEach(script => {
        setupTracker(script);
      });
    })();
  `);
});

app.get("/", (req, res) => {
  if (req.session?.user) {
    return res.redirect("/admin");
  }
  res.redirect("/login");
});

app.get("/admin", requireAuth, (req, res) => {
  res.redirect("/dashboard");
});

app.get("/admin/sites", requireAuth, async (req, res) => {
  const sites = await getSites(db);
  res.json(
    sites.map(site => ({
      site_id: site.site_id,
      name: site.name,
      pixel_id: site.pixel_id,
      site_key: site.site_key,
      test_event_code: site.test_event_code,
      send_to_meta: Boolean(site.send_to_meta),
      dry_run: Boolean(site.dry_run),
      status: getSiteStatus(site),
      created_at: site.created_at,
      updated_at: site.updated_at
    }))
  );
});

app.post("/admin/sites/:siteId/test-event", requireAuth, async (req, res) => {
  const site = await getSiteById(db, req.params.siteId);
  if (!site) {
    return res.status(404).json({ ok: false, error: "site_not_found" });
  }

  const eventType = req.body.event_type;
  if (!eventType || !TEST_EVENT_TYPES.includes(eventType)) {
    return res.status(400).json({
      ok: false,
      reason: "invalid_event_type",
      allowed_types: TEST_EVENT_TYPES
    });
  }

  const overrides = req.body.overrides && typeof req.body.overrides === "object"
    ? req.body.overrides
    : {};
  const result = await sendTestEvent({ site, eventType, overrides });
  res.json(result);
});

app.post("/admin/sites", requireAuth, async (req, res) => {
  const {
    name,
    pixel_id,
    access_token,
    test_event_code,
    send_to_meta,
    dry_run,
    log_full_payloads
  } = req.body;

  const site_id = uuid();
  const site_key = uuid();

  await createSite(db, {
    site_id,
    site_key,
    name: name || "Untitled site",
    pixel_id: pixel_id || null,
    access_token: encryptToken(access_token || null),
    test_event_code: test_event_code || null,
    send_to_meta: Boolean(send_to_meta),
    dry_run: dry_run === undefined ? true : Boolean(dry_run),
    log_full_payloads: log_full_payloads !== false
  });

  await log({ type: "admin", message: "site created", site_id });

  res.status(201).json({
    site_id,
    site_key,
    name,
    pixel_id
  });
});

app.get("/admin/logs", requireAuth, async (req, res) => {
  const limit = Number.parseInt(req.query.limit ?? "20", 10);
  const safeLimit = Number.isNaN(limit) ? 20 : limit;
  const events = await listEvents(db, { limit: safeLimit });
  const errors = await listRecentErrors(db, safeLimit);
  res.json({ events, errors });
});

function renderLoginPage({ errorMessage = "" } = {}) {
  const errorHtml = errorMessage ? `<div class="banner warning">${errorMessage}</div>` : "";
  const body = `
    <div class="card">
      <h1>Meta CAPI Gateway</h1>
      <p class="muted">Admin login</p>
      ${errorHtml}
      <form method="post" action="/login">
        <label>Username</label>
        <input type="text" name="username" required />
        <label>Password</label>
        <input type="password" name="password" required />
        <button type="submit">Log in</button>
      </form>
    </div>
  `;
  return renderPage({ title: "Login", body, nav: false });
}

app.get("/login", (req, res) => {
  if (req.session?.user) {
    return res.redirect("/admin");
  }
  res.send(renderLoginPage());
});

app.post("/login", async (req, res) => {
  const username = req.body.username ?? "";
  const password = req.body.password ?? "";
  const user = await getUserByUsername(db, username);
  const isValid = user ? await bcrypt.compare(password, user.password_hash) : false;

  if (!isValid) {
    await log({ type: "auth", message: "invalid admin login" });
    return res.status(401).send(renderLoginPage({ errorMessage: "Invalid username or password." }));
  }

  const usesDefaultCreds =
    user.username === DEFAULT_ADMIN_USER &&
    (await bcrypt.compare(DEFAULT_ADMIN_PASSWORD, user.password_hash));

  req.session.regenerate(async err => {
    if (err) {
      await log({ type: "auth", message: "session regeneration failed", error: err.toString() });
      return res.status(500).send(renderLoginPage({ errorMessage: "Login failed. Try again." }));
    }
    req.session.user = { id: user.id, username: user.username };
    req.session.mustChangePassword = usesDefaultCreds;
    await log({ type: "auth", message: "admin login", user: user.username });
    res.redirect("/admin");
  });
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

app.get("/dashboard", requireAuth, async (req, res) => {
  const events24h = await countEventsSince(db, 24);
  const errors24h = await countErrorsSince(db, 24);
  const deduped24h = await countDedupedSince(db, 24);
  const dedupRate = events24h ? Math.round((deduped24h / events24h) * 100) : 0;
  const recentEvents = await listEvents(db, { limit: 10 });
  const sites = await getSites(db);
  const skippedCount = await db.get(
    "SELECT COUNT(*) as count FROM events WHERE status = 'outbound_skipped' AND created_at > datetime('now', '-24 hours')"
  );
  const banners = [];
  if (req.session.mustChangePassword) {
    banners.push(`<div class="banner warning">Default credentials in use. Update your password in Settings.</div>`);
  }
  if (sites.length === 0) {
    banners.push(`<div class="banner info">No sites configured — add one to begin.</div>`);
  }
  if ((skippedCount?.count ?? 0) > 0) {
    banners.push(`<div class="banner info">Events are being logged but not forwarded.</div>`);
  }

  const body = `
    <div class="card">
      <h1>Dashboard</h1>
      <p class="muted">Gateway status and recent activity snapshot.</p>
    </div>
    ${banners.join("")}
    <div class="grid">
      <div class="card">
        <h3>Gateway</h3>
        <p class="status online">● Online</p>
      </div>
      <div class="card">
        <h3>Events (24h)</h3>
        <p class="metric">${events24h}</p>
      </div>
      <div class="card">
        <h3>Errors (24h)</h3>
        <p class="metric">${errors24h}</p>
      </div>
      <div class="card">
        <h3>Approx Dedup Rate</h3>
        <p class="metric">${dedupRate}%</p>
      </div>
    </div>
    <div class="card">
      <h2>Recent activity</h2>
      <table>
        <thead>
          <tr>
            <th>Time</th>
            <th>Site</th>
            <th>Event</th>
            <th>Pixel</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          ${recentEvents
            .map(
              event => `
            <tr>
              <td>${formatDate(event.created_at)}</td>
              <td>${event.site_name ?? "—"}</td>
              <td><a href="/dashboard/events/${event.id}">${event.event_name ?? "—"}</a></td>
              <td>${event.pixel_id ?? "—"}</td>
              <td>${renderStatusPill(event.status)}</td>
            </tr>
          `
            )
            .join("")}
        </tbody>
      </table>
    </div>
  `;

  res.send(renderPage({ title: "Dashboard", body }));
});

app.get("/dashboard/sites", requireAuth, async (req, res) => {
  const sites = await getSites(db);
  const skippedCount = await db.get(
    "SELECT COUNT(*) as count FROM events WHERE status = 'outbound_skipped' AND created_at > datetime('now', '-24 hours')"
  );
  const banners = [];
  if (req.session.mustChangePassword) {
    banners.push(`<div class="banner warning">Default credentials in use. Update your password in Settings.</div>`);
  }
  if (sites.length === 0) {
    banners.push(`<div class="banner info">No sites configured — add one to begin.</div>`);
  }
  if ((skippedCount?.count ?? 0) > 0) {
    banners.push(`<div class="banner info">Events are being logged but not forwarded.</div>`);
  }

  const siteCards = await Promise.all(
    sites.map(async site => {
      const eventsToday = await countEventsTodayBySite(db, site.site_id);
      const errorsToday = await countErrorsTodayBySite(db, site.site_id);
      const status = renderSiteStatus(site);
      return `
        <div class="card site-card">
          <div class="site-header">
            <div class="site-title">
              <h3>${site.name ?? "Untitled site"}</h3>
              ${status}
            </div>
            <span class="muted">Pixel ${site.pixel_id ?? "—"}</span>
          </div>
          <p class="muted">Site ID: <code>${site.site_id}</code></p>
          <p class="muted">Site Key: <code>${site.site_key}</code></p>
          <div class="site-metrics">
            <div>
              <span class="metric">${eventsToday}</span>
              <span class="muted">events today</span>
            </div>
            <div>
              <span class="metric">${errorsToday}</span>
              <span class="muted">errors today</span>
            </div>
          </div>
          <div class="actions">
            <a class="button" href="/dashboard/live?site=${site.site_id}">View Events</a>
            <a class="button secondary" href="/dashboard/sites/${site.site_id}">Edit Settings</a>
            <a class="button secondary" href="/dashboard/sites/${site.site_id}#test-event">Send Test Event</a>
          </div>
        </div>
      `;
    })
  );

  const notice = req.query.notice ? `<div class="banner info">${req.query.notice}</div>` : "";

  const body = `
    <div class="card">
      <h1>Sites</h1>
      <p class="muted">Manage site keys, Meta pixel credentials, and debug toggles.</p>
    </div>
    ${banners.join("")}
    ${notice}
    <div class="card">
      <h2>Create site</h2>
      <form method="post" action="/dashboard/sites" class="form-grid">
        <label>Name
          <input name="name" required />
        </label>
        <label>Pixel ID
          <input name="pixel_id" />
        </label>
        <label>Access Token
          <input name="access_token" />
        </label>
        <label>Test Event Code
          <input name="test_event_code" />
        </label>
        <label class="checkbox">
          <input type="checkbox" name="send_to_meta" />
          Send to Meta when credentials are ready
        </label>
        <label class="checkbox">
          <input type="checkbox" name="dry_run" checked />
          Dry-run mode (log only, do not send to Meta)
        </label>
        <label class="checkbox">
          <input type="checkbox" name="log_full_payloads" checked />
          Log full payloads (dev only)
        </label>
        <button type="submit">Create site</button>
      </form>
    </div>
    <div class="card">
      <h2>Existing sites</h2>
      <div class="card-grid">
        ${siteCards.join("") || "<p class=\"muted\">No sites yet.</p>"}
      </div>
    </div>
  `;

  res.send(renderPage({ title: "Sites", body }));
});

app.get("/dashboard/sites/:siteId", requireAuth, async (req, res) => {
  const site = await getSiteById(db, req.params.siteId);
  if (!site) {
    return res.status(404).send(renderPage({
      title: "Site not found",
      body: `<div class="card"><h1>Site not found</h1></div>`
    }));
  }

  const status = renderSiteStatus(site);
  const accessToken = resolveAccessToken(site);
  const maskedToken = accessToken ? maskToken(accessToken) : site.access_token ? "Encrypted" : "—";
  const testEventOptions = TEST_EVENT_TYPES.map(
    type => `<option value="${type}">${type}</option>`
  ).join("");

  const body = `
    <div class="card">
      <h1>${site.name ?? "Site settings"}</h1>
      <p class="muted">Manage ingest auth, Meta config, and debug toggles.</p>
      <div class="inline">${status}</div>
    </div>
    <div class="card">
      <h2>Ingest auth</h2>
      <p class="muted">Site Key (used in <code>x-site-key</code> header).</p>
      <div class="inline">
        <code>${site.site_key}</code>
        <form method="post" action="/dashboard/sites/${site.site_id}/rotate">
          <button type="submit" class="danger">Rotate key</button>
        </form>
      </div>
    </div>
    <div class="card">
      <h2>Meta config</h2>
      <form method="post" action="/dashboard/sites/${site.site_id}" class="form-grid">
        <label>Name
          <input name="name" value="${site.name ?? ""}" />
        </label>
        <label>Pixel ID
          <input name="pixel_id" value="${site.pixel_id ?? ""}" />
        </label>
        <label>Access Token
          <input name="access_token" placeholder="Enter new access token" />
          <span class="muted">Stored token: ${maskedToken}</span>
        </label>
        <label class="checkbox">
          <input type="checkbox" name="clear_access_token" />
          Clear access token
        </label>
        <label>Test Event Code
          <input name="test_event_code" value="${site.test_event_code ?? ""}" />
        </label>
        <label class="checkbox">
          <input type="checkbox" name="send_to_meta" ${site.send_to_meta ? "checked" : ""} />
          Send to Meta when credentials are ready
        </label>
        <label class="checkbox">
          <input type="checkbox" name="dry_run" ${site.dry_run ? "checked" : ""} />
          Dry-run mode (log only, do not send to Meta)
        </label>
        <label class="checkbox">
          <input type="checkbox" name="log_full_payloads" ${site.log_full_payloads ? "checked" : ""} />
          Log full payloads (dev warning)
        </label>
        <button type="button" class="secondary" id="reveal-token">Reveal token</button>
        <button type="submit">Save settings</button>
      </form>
    </div>
    <div class="card" id="test-event">
      <h2>Send Test Event</h2>
      <p class="muted">Generate a Meta test event using this site's credentials. Test events always include the site's test event code.</p>
      <p class="muted">Meta requires customer info parameters (IP/UA + identifiers) for matching.</p>
      <div id="test-event-warning" class="banner warning hidden"></div>
      <form id="test-event-form" class="form-grid"
        data-site-id="${site.site_id}"
        data-has-credentials="${Boolean(site.pixel_id && accessToken)}"
        data-has-test-event-code="${Boolean(site.test_event_code)}"
        data-send-to-meta="${Boolean(site.send_to_meta)}"
        data-dry-run="${Boolean(site.dry_run)}">
        <label>Event Type
          <select name="event_type" id="test-event-type">
            ${testEventOptions}
          </select>
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">Event Source URL
          <input name="event_source_url" value="${DEFAULT_TEST_EVENT_SOURCE_URL}" />
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">Client IP
          <input name="client_ip_address" value="${DEFAULT_TEST_EVENT_IP}" />
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">Client User Agent
          <input name="client_user_agent" value="${DEFAULT_TEST_EVENT_UA}" />
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">Email (optional)
          <input name="email" placeholder="person@example.com" />
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">Phone (optional)
          <input name="phone" placeholder="+15551234567" />
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">External ID (optional)
          <input name="external_id" placeholder="customer-123" />
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">FBP (optional)
          <input name="fbp" placeholder="fb.1.1717000000.1234567890" />
        </label>
        <label data-event-types="PageView,ViewContent,Lead,AddToCart,Purchase">FBC (optional)
          <input name="fbc" placeholder="fb.1.1717000000.AbCdEfGhIj" />
        </label>
        <label data-event-types="ViewContent,Lead,AddToCart,Purchase">Content Name
          <input name="content_name" placeholder="Test Content" />
        </label>
        <label data-event-types="ViewContent,AddToCart,Purchase">Content IDs (comma separated)
          <input name="content_ids" placeholder="test_sku" />
        </label>
        <label data-event-types="AddToCart,Purchase">Value
          <input name="value" type="number" step="0.01" placeholder="1.00" />
        </label>
        <label data-event-types="AddToCart,Purchase">Currency
          <input name="currency" placeholder="USD" />
        </label>
        <button type="submit" id="test-event-submit">Send Test Event</button>
      </form>
      <div id="test-event-result" class="test-event-result hidden">
        <div class="inline">
          <span id="test-event-status" class="pill">Pending</span>
          <span id="test-event-note" class="muted"></span>
        </div>
        <details open>
          <summary>Outbound payload</summary>
          <pre id="test-event-payload">—</pre>
        </details>
        <details>
          <summary>Meta response</summary>
          <pre id="test-event-response">—</pre>
        </details>
      </div>
    </div>
    <script>
      const revealButton = document.getElementById('reveal-token');
      const tokenInput = document.querySelector('input[name="access_token"]');
      revealButton.addEventListener('click', async () => {
        const response = await fetch('/dashboard/sites/${site.site_id}/token');
        if (!response.ok) {
          alert('Unable to reveal token.');
          return;
        }
        const data = await response.json();
        if (data.access_token) {
          tokenInput.value = data.access_token;
        } else {
          alert('No access token stored yet.');
        }
      });
    </script>
    <script>
      const testForm = document.getElementById('test-event-form');
      const testType = document.getElementById('test-event-type');
      const testWarning = document.getElementById('test-event-warning');
      const testResult = document.getElementById('test-event-result');
      const testStatus = document.getElementById('test-event-status');
      const testNote = document.getElementById('test-event-note');
      const testPayload = document.getElementById('test-event-payload');
      const testResponse = document.getElementById('test-event-response');
      const testSubmit = document.getElementById('test-event-submit');
      const testFields = testForm.querySelectorAll('[data-event-types]');

      function updateTestFieldVisibility() {
        const selected = testType.value;
        testFields.forEach(field => {
          const types = field.dataset.eventTypes.split(',').map(item => item.trim());
          field.classList.toggle('hidden', !types.includes(selected));
        });
      }

      function setWarning(message) {
        if (message) {
          testWarning.textContent = message;
          testWarning.classList.remove('hidden');
        } else {
          testWarning.textContent = '';
          testWarning.classList.add('hidden');
        }
      }

      function applyStatus(label, className) {
        testStatus.textContent = label;
        testStatus.className = 'pill ' + className;
      }

      function inferStatus(result) {
        if (result.forwarded === false) {
          return { label: 'Skipped', className: 'pill-outbound_skipped' };
        }
        if (result.meta_status >= 200 && result.meta_status < 300) {
          if (result.meta_response && result.meta_response.events_received > 0) {
            return { label: 'Processed', className: 'pill-success' };
          }
          return { label: 'Sent', className: 'pill-ready' };
        }
        return { label: 'Rejected', className: 'pill-error' };
      }

      function renderResult(result) {
        testResult.classList.remove('hidden');
        testPayload.textContent = JSON.stringify(result.outbound_payload || {}, null, 2);
        testResponse.textContent = JSON.stringify({
          status: result.meta_status,
          body: result.meta_response
        }, null, 2);
        testNote.textContent = result.note || '';
        const status = inferStatus(result);
        applyStatus(status.label, status.className);
      }

      function renderHint() {
        const hasCredentials = testForm.dataset.hasCredentials === 'true';
        const hasTestEventCode = testForm.dataset.hasTestEventCode === 'true';
        if (!hasCredentials) {
          setWarning('Missing credentials. Add a Pixel ID and Access Token above to send test events.');
          return;
        }
        if (!hasTestEventCode) {
          setWarning('Missing test event code. Find it in Events Manager → Test Events.');
          return;
        }
        setWarning('');
      }

      testType.addEventListener('change', updateTestFieldVisibility);
      updateTestFieldVisibility();
      renderHint();

      testForm.addEventListener('submit', async (event) => {
        event.preventDefault();
        setWarning('');
        testSubmit.disabled = true;
        testSubmit.textContent = 'Sending…';

        const formData = new FormData(testForm);
        const overrides = {};
        const eventSourceUrl = formData.get('event_source_url');
        if (eventSourceUrl) overrides.event_source_url = eventSourceUrl;
        const clientIp = formData.get('client_ip_address');
        if (clientIp) overrides.client_ip_address = clientIp;
        const clientUserAgent = formData.get('client_user_agent');
        if (clientUserAgent) overrides.client_user_agent = clientUserAgent;
        const email = formData.get('email');
        if (email) overrides.email = email;
        const phone = formData.get('phone');
        if (phone) overrides.phone = phone;
        const externalId = formData.get('external_id');
        if (externalId) overrides.external_id = externalId;
        const fbp = formData.get('fbp');
        if (fbp) overrides.fbp = fbp;
        const fbc = formData.get('fbc');
        if (fbc) overrides.fbc = fbc;
        const contentName = formData.get('content_name');
        if (contentName) overrides.content_name = contentName;
        const contentIds = formData.get('content_ids');
        if (contentIds) {
          overrides.content_ids = contentIds.split(',').map(item => item.trim()).filter(Boolean);
        }
        const value = formData.get('value');
        if (value) overrides.value = value;
        const currency = formData.get('currency');
        if (currency) overrides.currency = currency;

        try {
          const response = await fetch('/dashboard/sites/${site.site_id}/test-event', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
              event_type: formData.get('event_type'),
              overrides
            })
          });
          const result = await response.json();
          if (!response.ok) {
            setWarning(result.error || 'Failed to send test event.');
            return;
          }

          renderResult(result);

          if (result.reason === 'missing_credentials') {
            setWarning('Missing credentials. Add a Pixel ID and Access Token above to send test events.');
          } else if (result.reason === 'missing_test_event_code') {
            setWarning('Missing test event code. Find it in Events Manager → Test Events.');
          } else if (result.reason === 'dry_run') {
            setWarning('Dry-run is enabled. Disable dry-run to send test events.');
          } else if (result.reason === 'send_disabled') {
            setWarning('Send to Meta is disabled for this site.');
          }
        } catch {
          setWarning('Request failed. Check connectivity and try again.');
        } finally {
          testSubmit.disabled = false;
          testSubmit.textContent = 'Send Test Event';
        }
      });
    </script>
    <div class="card">
      <h2>Delete site</h2>
      <form method="post" action="/dashboard/sites/${site.site_id}/delete">
        <button type="submit" class="danger">Delete site</button>
      </form>
    </div>
  `;

  res.send(renderPage({ title: "Site settings", body }));
});

app.post("/dashboard/sites", requireAuth, async (req, res) => {
  const site_id = uuid();
  const site_key = uuid();
  await createSite(db, {
    site_id,
    site_key,
    name: req.body.name || "Untitled site",
    pixel_id: req.body.pixel_id || null,
    access_token: encryptToken(req.body.access_token || null),
    test_event_code: req.body.test_event_code || null,
    send_to_meta: Boolean(req.body.send_to_meta),
    dry_run: req.body.dry_run === undefined ? true : Boolean(req.body.dry_run),
    log_full_payloads: req.body.log_full_payloads !== undefined
  });
  await log({ type: "admin", message: "site created", site_id });
  res.redirect("/dashboard/sites");
});

app.post("/dashboard/sites/:siteId", requireAuth, async (req, res) => {
  const site_id = req.params.siteId;
  const existing = await getSiteById(db, site_id);
  if (!existing) {
    return res.status(404).send(renderPage({
      title: "Site not found",
      body: `<div class="card"><h1>Site not found</h1></div>`
    }));
  }
  const accessToken = req.body.clear_access_token
    ? null
    : req.body.access_token || existing.access_token;
  await updateSite(db, {
    site_id,
    name: req.body.name,
    pixel_id: req.body.pixel_id || null,
    access_token: encryptToken(accessToken),
    test_event_code: req.body.test_event_code || null,
    send_to_meta: Boolean(req.body.send_to_meta),
    dry_run: Boolean(req.body.dry_run),
    log_full_payloads: req.body.log_full_payloads !== undefined
  });
  await log({ type: "admin", message: "site updated", site_id });
  res.redirect(`/dashboard/sites/${site_id}`);
});

app.get("/dashboard/sites/:siteId/token", requireAuth, async (req, res) => {
  const site = await getSiteById(db, req.params.siteId);
  if (!site) return res.status(404).json({ error: "not found" });
  res.json({ access_token: resolveAccessToken(site) });
});

app.post("/dashboard/sites/:siteId/test-event", requireAuth, async (req, res) => {
  const site = await getSiteById(db, req.params.siteId);
  if (!site) {
    return res.status(404).json({ ok: false, error: "site_not_found" });
  }

  const eventType = req.body.event_type;
  if (!eventType || !TEST_EVENT_TYPES.includes(eventType)) {
    return res.status(400).json({
      ok: false,
      reason: "invalid_event_type",
      allowed_types: TEST_EVENT_TYPES
    });
  }

  const overrides = req.body.overrides && typeof req.body.overrides === "object"
    ? req.body.overrides
    : {};
  const result = await sendTestEvent({ site, eventType, overrides });
  res.json(result);
});

app.post("/dashboard/sites/:siteId/rotate", requireAuth, async (req, res) => {
  const site_id = req.params.siteId;
  const site_key = uuid();
  await rotateSiteKey(db, site_id, site_key);
  await log({ type: "admin", message: "site key rotated", site_id });
  res.redirect(`/dashboard/sites/${site_id}`);
});

app.post("/dashboard/sites/:siteId/delete", requireAuth, async (req, res) => {
  const site_id = req.params.siteId;
  await deleteSite(db, site_id);
  await log({ type: "admin", message: "site deleted", site_id });
  res.redirect("/dashboard/sites");
});

app.get("/dashboard/videos", requireAuth, async (req, res) => {
  const videos = await listVideos(db);
  const host = resolveBaseUrl(req);

  const rows = videos.map(video => {
    const snippet = buildVideoSnippet({
      host,
      siteKey: video.site_key,
      videoId: video.video_id,
      selector: video.selector
    });
    const encodedSnippet = encodeURIComponent(snippet);
    const mode = normalizeVideoMode(video.mode);
    const providerLabel = formatVideoProvider(video.provider);
    const providerDetails = video.provider_video_id ? `${providerLabel} (${video.provider_video_id})` : providerLabel;
    const sourceUrl = video.video_source_url || "";
    return `
      <tr>
        <td>
          <strong>${video.video_id}</strong><br />
          <span class="muted">${video.name ?? "—"}</span>
        </td>
        <td>${video.site_name ?? "—"}</td>
        <td>${video.page_url ?? "—"}</td>
        <td>
          <span class="pill pill-provider">${providerDetails || "Unknown"}</span>
        </td>
        <td>
          ${sourceUrl
            ? `<div class="truncate" title="${sourceUrl}">${sourceUrl}</div>
               <button class="button secondary copy-button" data-copy="${encodeURIComponent(sourceUrl)}">Copy</button>`
            : "—"}
        </td>
        <td>${video.enabled ? renderStatusPill("enabled") : renderStatusPill("disabled")}</td>
        <td>
          ${renderStatusPill(mode)}
          <div class="table-hint">${VIDEO_MODE_HINTS[mode]}</div>
        </td>
        <td>
          <div class="actions">
            <a class="button secondary" href="/dashboard/videos/${video.id}">Edit</a>
            <a class="button secondary" href="/dashboard/live?site=${video.site_id}&video_id=${video.video_id}">View Events</a>
            <button class="button secondary copy-snippet" data-snippet="${encodedSnippet}">Copy Snippet</button>
            <form method="post" action="/dashboard/videos/${video.id}/toggle">
              <button type="submit" class="${video.enabled ? "danger" : ""}">${video.enabled ? "Disable" : "Enable"}</button>
            </form>
          </div>
        </td>
      </tr>
    `;
  });

  const notice = req.query.notice ? `<div class="banner info">${req.query.notice}</div>` : "";

  const body = `
    <div class="card">
      <h1>Videos</h1>
      <p class="muted">Manage tracked videos, snippets, and revocation.</p>
      <div class="actions">
        <a class="button" href="/dashboard/videos/new">Add Video</a>
      </div>
    </div>
    ${notice}
    <div class="card">
      <h2>Tracked videos</h2>
      <table>
        <thead>
          <tr>
            <th>Video</th>
            <th>Site</th>
            <th>Page URL</th>
            <th>Provider</th>
            <th>Video Source URL</th>
            <th>Status</th>
            <th>Mode</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          ${rows.join("") || "<tr><td colspan=\"8\" class=\"muted\">No videos yet.</td></tr>"}
        </tbody>
      </table>
    </div>
    <script>
      async function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
          try {
            await navigator.clipboard.writeText(text);
            return true;
          } catch {
            // fallback below
          }
        }
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
      }

      function attachCopy(button, getText, label) {
        button.addEventListener('click', async () => {
          const text = getText();
          const ok = await copyText(text);
          button.textContent = ok ? 'Copied!' : 'Copy failed';
          setTimeout(() => { button.textContent = label; }, 1500);
        });
      }

      document.querySelectorAll('.copy-snippet').forEach(button => {
        attachCopy(button, () => decodeURIComponent(button.dataset.snippet || ''), 'Copy Snippet');
      });

      document.querySelectorAll('.copy-button').forEach(button => {
        attachCopy(button, () => decodeURIComponent(button.dataset.copy || ''), 'Copy');
      });
    </script>
  `;

  res.send(renderPage({ title: "Videos", body }));
});

app.get("/dashboard/videos/new", requireAuth, async (req, res) => {
  const sites = await getSites(db);
  const siteOptions = sites
    .map(site => `<option value="${site.site_id}">${site.name ?? site.site_id}</option>`)
    .join("");
  const warning = req.query.warning ? `<div class="banner warning">${req.query.warning}</div>` : "";

  const body = `
    <div class="card">
      <h1>Add Video</h1>
      <p class="muted">Register a video page and generate a snippet for tracking.</p>
    </div>
    ${warning}
    <div class="card">
      <form method="post" action="/dashboard/videos" class="form-grid">
        <label>Site
          <select name="site_id" required>
            <option value="">Select a site</option>
            ${siteOptions}
          </select>
        </label>
        <label>Page URL
          <input name="page_url" required placeholder="https://example.com/video-page" />
        </label>
        <label>Video source URL (optional)
          <input name="video_source_url" placeholder="https://player.vimeo.com/video/12345" />
          <span class="muted">The actual video file or provider URL (mp4, Vimeo, YouTube, etc.). Used for identification and management.</span>
        </label>
        <label>Video name (optional)
          <input name="name" placeholder="Homepage hero video" />
        </label>
        <label>Video ID slug
          <input name="video_id" placeholder="homepage-hero" />
          <span class="muted">Auto-generated from name or URL if blank.</span>
        </label>
        <label>CSS selector
          <input name="selector" value="video" />
        </label>
        <label>Mode
          <select name="mode">
            <option value="off">Off (log only)</option>
            <option value="test" selected>Test (send to Meta Test Events)</option>
            <option value="live">Live (send to Meta Production)</option>
          </select>
          <span class="muted">Test mode requires a site test_event_code. Live mode impacts optimization/reporting.</span>
        </label>
        <label class="checkbox">
          <input type="checkbox" name="enabled" checked />
          Enabled
        </label>
        <button type="submit">Save video</button>
      </form>
    </div>
  `;

  res.send(renderPage({ title: "Add video", body }));
});

app.post("/dashboard/videos", requireAuth, async (req, res) => {
  const site = await getSiteById(db, req.body.site_id);
  if (!site) {
    return res.status(400).send(renderPage({
      title: "Invalid site",
      body: `<div class="card"><h1>Invalid site</h1><p class="muted">Select a valid site.</p></div>`
    }));
  }

  if (!req.body.page_url?.trim()) {
    return res.status(400).send(renderPage({
      title: "Missing page URL",
      body: `<div class="card"><h1>Page URL required</h1><p class="muted">Add the page URL where the video is embedded.</p></div>`
    }));
  }

  const rawSlug = req.body.video_id || req.body.name || req.body.page_url;
  const videoSlug = slugify(rawSlug) || uuid();
  const existing = await getVideoBySiteAndVideoId(db, site.site_id, videoSlug);

  if (existing) {
    return res.status(400).send(renderPage({
      title: "Video ID exists",
      body: `<div class="card"><h1>Video ID already exists</h1><p class="muted">Choose a different slug for this site.</p></div>`
    }));
  }

  const mode = normalizeVideoMode(req.body.mode);
  let warningParam = "";
  if (mode === "test" && !site.test_event_code) {
    warningParam = "&warning=" + encodeURIComponent("Test mode selected, but this site has no test_event_code. Events will be logged but not forwarded.");
  }

  const { provider, providerVideoId } = parseVideoSourceInfo(req.body.video_source_url);
  const id = uuid();
  await createVideo(db, {
    id,
    site_id: site.site_id,
    video_id: videoSlug,
    name: req.body.name || null,
    page_url: req.body.page_url || null,
    video_source_url: req.body.video_source_url || null,
    provider,
    provider_video_id: providerVideoId,
    selector: req.body.selector || "video",
    enabled: req.body.enabled !== undefined,
    mode
  });
  await log({ type: "admin", message: "video created", site_id: site.site_id, video_id: videoSlug });
  res.redirect(`/dashboard/videos/${id}?notice=Video%20created${warningParam}`);
});

app.get("/dashboard/videos/:videoDbId", requireAuth, async (req, res) => {
  const video = await getVideoById(db, req.params.videoDbId);
  if (!video) {
    return res.status(404).send(renderPage({
      title: "Video not found",
      body: `<div class="card"><h1>Video not found</h1></div>`
    }));
  }
  const activeSite = await getSiteById(db, video.site_id);
  const sites = await getSites(db);
  const siteOptions = sites
    .map(site => `<option value="${site.site_id}" ${site.site_id === video.site_id ? "selected" : ""}>${site.name ?? site.site_id}</option>`)
    .join("");
  const host = resolveBaseUrl(req);
  const snippet = buildVideoSnippet({
    host,
    siteKey: video.site_key,
    videoId: video.video_id,
    selector: video.selector
  });
  const notice = req.query.notice ? `<div class="banner info">${req.query.notice}</div>` : "";
  const warning = req.query.warning ? `<div class="banner warning">${req.query.warning}</div>` : "";
  const mode = normalizeVideoMode(video.mode);
  const warnings = [];
  if (mode === "test" && !activeSite?.test_event_code) {
    warnings.push("Test mode is selected, but this site has no test_event_code. Events will be logged but not forwarded.");
  }
  if (mode === "live") {
    warnings.push("Live mode sends production events and impacts optimization/reporting.");
  }
  const modeWarning = warnings.length ? `<div class="banner warning">${warnings.join(" ")}</div>` : "";

  const body = `
    <div class="card">
      <h1>Edit Video</h1>
      <p class="muted">Update tracking settings or revoke tracking instantly.</p>
    </div>
    ${notice}
    ${warning}
    ${modeWarning}
    <div class="card">
      <form method="post" action="/dashboard/videos/${video.id}" class="form-grid">
        <label>Site
          <select name="site_id" required>
            ${siteOptions}
          </select>
        </label>
        <label>Page URL
          <input name="page_url" value="${video.page_url ?? ""}" required />
        </label>
        <label>Video source URL (optional)
          <input name="video_source_url" value="${video.video_source_url ?? ""}" />
          <span class="muted">The actual video file or provider URL (mp4, Vimeo, YouTube, etc.). Used for identification and management.</span>
        </label>
        <label>Video name (optional)
          <input name="name" value="${video.name ?? ""}" />
        </label>
        <label>Video ID slug
          <input name="video_id" value="${video.video_id}" required />
        </label>
        <label>CSS selector
          <input name="selector" value="${video.selector ?? "video"}" />
        </label>
        <label>Mode
          <select name="mode">
            <option value="off" ${mode === "off" ? "selected" : ""}>Off (log only)</option>
            <option value="test" ${mode === "test" ? "selected" : ""}>Test (send to Meta Test Events)</option>
            <option value="live" ${mode === "live" ? "selected" : ""}>Live (send to Meta Production)</option>
          </select>
          <span class="muted">${VIDEO_MODE_HINTS[mode]}</span>
        </label>
        <label class="checkbox">
          <input type="checkbox" name="enabled" ${video.enabled ? "checked" : ""} />
          Enabled
        </label>
        <button type="submit">Save changes</button>
      </form>
    </div>
    <div class="card">
      <h2>Snippet</h2>
      <p class="muted">Milestones sent: Video25/50/75/95. <code>video_id</code> is passed in <code>custom_data</code>.</p>
      <p class="muted">Detected provider: <strong>${formatVideoProvider(video.provider)}</strong>${video.provider_video_id ? ` (ID: ${video.provider_video_id})` : ""}</p>
      <pre><code id="snippet">${escapeHtml(snippet)}</code></pre>
      <button id="copy-snippet">Copy Snippet</button>
    </div>
    <div class="card">
      <h2>Actions</h2>
      <div class="actions">
        <a class="button secondary" href="/dashboard/live?site=${video.site_id}&video_id=${video.video_id}">View Events</a>
        <form method="post" action="/dashboard/videos/${video.id}/toggle">
          <button type="submit" class="${video.enabled ? "danger" : ""}">${video.enabled ? "Disable" : "Enable"}</button>
        </form>
        <form method="post" action="/dashboard/videos/${video.id}/delete">
          <button type="submit" class="danger">Delete</button>
        </form>
      </div>
    </div>
    <script>
      async function copyText(text) {
        if (navigator.clipboard && window.isSecureContext) {
          try {
            await navigator.clipboard.writeText(text);
            return true;
          } catch {
            // fallback below
          }
        }
        const textarea = document.createElement('textarea');
        textarea.value = text;
        textarea.setAttribute('readonly', '');
        textarea.style.position = 'absolute';
        textarea.style.left = '-9999px';
        document.body.appendChild(textarea);
        textarea.select();
        const success = document.execCommand('copy');
        document.body.removeChild(textarea);
        return success;
      }

      const copyButton = document.getElementById('copy-snippet');
      const snippetEl = document.getElementById('snippet');
      copyButton.addEventListener('click', async () => {
        const ok = await copyText(snippetEl.textContent || '');
        copyButton.textContent = ok ? 'Copied!' : 'Copy failed';
        setTimeout(() => { copyButton.textContent = 'Copy Snippet'; }, 1500);
      });
    </script>
  `;

  res.send(renderPage({ title: "Edit video", body }));
});

app.post("/dashboard/videos/:videoDbId", requireAuth, async (req, res) => {
  const video = await getVideoById(db, req.params.videoDbId);
  if (!video) {
    return res.status(404).send(renderPage({
      title: "Video not found",
      body: `<div class="card"><h1>Video not found</h1></div>`
    }));
  }

  const site = await getSiteById(db, req.body.site_id);
  if (!site) {
    return res.status(400).send(renderPage({
      title: "Invalid site",
      body: `<div class="card"><h1>Invalid site</h1><p class="muted">Select a valid site.</p></div>`
    }));
  }

  if (!req.body.page_url?.trim()) {
    return res.status(400).send(renderPage({
      title: "Missing page URL",
      body: `<div class="card"><h1>Page URL required</h1><p class="muted">Add the page URL where the video is embedded.</p></div>`
    }));
  }

  const videoSlug = slugify(req.body.video_id) || video.video_id;
  const existing = await getVideoBySiteAndVideoId(db, site.site_id, videoSlug);
  if (existing && existing.id !== video.id) {
    return res.status(400).send(renderPage({
      title: "Video ID exists",
      body: `<div class="card"><h1>Video ID already exists</h1><p class="muted">Choose a different slug for this site.</p></div>`
    }));
  }

  const mode = normalizeVideoMode(req.body.mode);
  let warningParam = "";
  if (mode === "test" && !site.test_event_code) {
    warningParam = "&warning=" + encodeURIComponent("Test mode selected, but this site has no test_event_code. Events will be logged but not forwarded.");
  } else if (mode === "live") {
    warningParam = "&warning=" + encodeURIComponent("Live mode sends production events and impacts optimization/reporting.");
  }

  const { provider, providerVideoId } = parseVideoSourceInfo(req.body.video_source_url);
  await updateVideo(db, {
    id: video.id,
    site_id: site.site_id,
    video_id: videoSlug,
    name: req.body.name || null,
    page_url: req.body.page_url || null,
    video_source_url: req.body.video_source_url || null,
    provider,
    provider_video_id: providerVideoId,
    selector: req.body.selector || "video",
    enabled: req.body.enabled !== undefined,
    mode
  });
  await log({ type: "admin", message: "video updated", site_id: site.site_id, video_id: videoSlug });
  res.redirect(`/dashboard/videos/${video.id}?notice=Video%20updated${warningParam}`);
});

app.post("/dashboard/videos/:videoDbId/toggle", requireAuth, async (req, res) => {
  const video = await getVideoById(db, req.params.videoDbId);
  if (!video) {
    return res.status(404).send(renderPage({
      title: "Video not found",
      body: `<div class="card"><h1>Video not found</h1></div>`
    }));
  }
  await updateVideo(db, {
    id: video.id,
    site_id: video.site_id,
    video_id: video.video_id,
    name: video.name,
    page_url: video.page_url,
    video_source_url: video.video_source_url,
    provider: video.provider,
    provider_video_id: video.provider_video_id,
    selector: video.selector,
    enabled: !video.enabled,
    mode: video.mode
  });
  await log({
    type: "admin",
    message: "video toggled",
    site_id: video.site_id,
    video_id: video.video_id,
    enabled: !video.enabled
  });
  res.redirect(req.get("referer") || "/dashboard/videos");
});

app.post("/dashboard/videos/:videoDbId/delete", requireAuth, async (req, res) => {
  const video = await getVideoById(db, req.params.videoDbId);
  if (video) {
    await deleteVideo(db, video.id);
    await log({ type: "admin", message: "video deleted", site_id: video.site_id, video_id: video.video_id });
  }
  res.redirect("/dashboard/videos?notice=Video%20deleted");
});

app.get("/dashboard/live", requireAuth, async (req, res) => {
  const sites = await getSites(db);
  const siteOptions = sites
    .map(site => `<option value="${site.site_id}">${site.name ?? site.site_id}</option>`)
    .join("");

  const body = `
    <div class="card">
      <h1>Live Events</h1>
      <p class="muted">Auto-refreshing stream (every 2 seconds).</p>
    </div>
    <div class="split-pane">
      <section class="pane pane-list">
        <div class="filters">
          <label>Site
            <select id="filter-site">
              <option value="">All sites</option>
              ${siteOptions}
            </select>
          </label>
          <label>Video ID
            <input id="filter-video" placeholder="video-123" />
          </label>
          <label>Status
            <select id="filter-status">
              <option value="">All</option>
              <option value="outbound_sent">Outbound sent</option>
              <option value="outbound_skipped">Outbound skipped</option>
              <option value="deduped">Deduped</option>
              <option value="error">Error</option>
            </select>
          </label>
          <label>Event name
            <input id="filter-name" placeholder="Purchase" />
          </label>
        </div>
        <div id="event-stream" class="event-stream"></div>
      </section>
      <section class="pane pane-detail">
        <div class="card" id="event-detail">
          <h2>Event detail</h2>
          <p class="muted">Select an event to inspect payloads.</p>
        </div>
      </section>
    </div>
    <script>
      const streamEl = document.getElementById('event-stream');
      const detailEl = document.getElementById('event-detail');
      const filterSite = document.getElementById('filter-site');
      const filterVideo = document.getElementById('filter-video');
      const filterStatus = document.getElementById('filter-status');
      const filterName = document.getElementById('filter-name');

      function buildQuery() {
        const params = new URLSearchParams();
        if (filterSite.value) params.set('site', filterSite.value);
        if (filterVideo.value) params.set('video_id', filterVideo.value);
        if (filterStatus.value) params.set('status', filterStatus.value);
        if (filterName.value) params.set('event_name', filterName.value);
        return params.toString();
      }

      function renderRow(event) {
        const row = document.createElement('div');
        row.className = 'event-row ' + event.status;
        row.dataset.id = event.id;
        row.innerHTML =
          '<div>' +
            '<strong>' + (event.event_name || '—') + '</strong>' +
            '<div class="muted">' + (event.site_name || 'Unknown site') + '</div>' +
          '</div>' +
          '<div class="muted">' + new Date(event.created_at).toLocaleTimeString() + '</div>' +
          '<div>' + (event.status || '').replace('_', ' ') + '</div>';
        row.addEventListener('click', () => loadDetail(event.id));
        return row;
      }

      async function loadStream() {
        const response = await fetch('/admin/events?limit=50&' + buildQuery());
        const events = await response.json();
        streamEl.innerHTML = '';
        events.forEach(event => streamEl.appendChild(renderRow(event)));
      }

      function renderJsonBlock(title, content) {
        const text = content ? JSON.stringify(content, null, 2) : '—';
        return '<details open>' +
          '<summary>' + title + '</summary>' +
          '<pre>' + text + '</pre>' +
          '</details>';
      }

      async function loadDetail(eventId) {
        const response = await fetch('/admin/events/' + eventId);
        const event = await response.json();
        if (!event || !event.id) return;
        const outboundReason = event.meta_body && event.meta_body.reason ? event.meta_body.reason : null;
        const videoModeLine = event.video_mode ? '<p class="muted">Video mode: <strong>' + event.video_mode + '</strong></p>' : '';
        detailEl.innerHTML =
          '<div class="detail-header">' +
            '<div>' +
              '<h2>' + (event.event_name || 'Event detail') + '</h2>' +
              '<p class="muted">' + (event.site_name || 'Unknown site') + ' · ' + (event.pixel_id || 'No pixel') + ' · ' + new Date(event.created_at).toLocaleString() + '</p>' +
              videoModeLine +
            '</div>' +
            '<div class="copy-group">' +
              '<button onclick=\'navigator.clipboard.writeText(' + JSON.stringify(event.event_id || '') + ')\'>Copy event_id</button>' +
            '</div>' +
          '</div>' +
          '<div class="tabs">' +
            '<button class="tab-button active" data-tab="inbound">Inbound</button>' +
            '<button class="tab-button" data-tab="outbound">Outbound → Meta</button>' +
            '<button class="tab-button" data-tab="meta">Meta Response</button>' +
          '</div>' +
          '<div class="tab-content" data-content="inbound">' +
            renderJsonBlock('Inbound payload', event.inbound_json) +
            '<button onclick=\'navigator.clipboard.writeText(' + JSON.stringify(JSON.stringify(event.inbound_json || {}, null, 2)) + ')\'>Copy inbound</button>' +
          '</div>' +
          '<div class="tab-content hidden" data-content="outbound">' +
            renderJsonBlock('Outbound payload', event.outbound_json) +
            (outboundReason ? '<p class="muted">Outbound skipped reason: ' + outboundReason + '</p>' : '') +
            '<button onclick=\'navigator.clipboard.writeText(' + JSON.stringify(JSON.stringify(event.outbound_json || {}, null, 2)) + ')\'>Copy outbound</button>' +
          '</div>' +
          '<div class="tab-content hidden" data-content="meta">' +
            renderJsonBlock('Meta response', { status: event.meta_status, body: event.meta_body }) +
            '<button onclick=\'navigator.clipboard.writeText(' + JSON.stringify(JSON.stringify({ status: event.meta_status, body: event.meta_body }, null, 2)) + ')\'>Copy response</button>' +
          '</div>';

        detailEl.querySelectorAll('.tab-button').forEach(button => {
          button.addEventListener('click', () => {
            detailEl.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
            detailEl.querySelectorAll('.tab-content').forEach(content => content.classList.add('hidden'));
            button.classList.add('active');
            detailEl.querySelector('.tab-content[data-content="' + button.dataset.tab + '"]').classList.remove('hidden');
          });
        });
      }

      [filterSite, filterStatus].forEach(el => el.addEventListener('change', loadStream));
      filterVideo.addEventListener('input', () => {
        if (filterVideo.value.length === 0 || filterVideo.value.length > 2) {
          loadStream();
        }
      });
      filterName.addEventListener('input', () => {
        if (filterName.value.length === 0 || filterName.value.length > 2) {
          loadStream();
        }
      });

      const urlParams = new URLSearchParams(window.location.search);
      if (urlParams.get('site')) filterSite.value = urlParams.get('site');
      if (urlParams.get('video_id')) filterVideo.value = urlParams.get('video_id');

      loadStream();
      setInterval(loadStream, 2000);
    </script>
  `;
  res.send(renderPage({ title: "Live Events", body }));
});

app.get("/dashboard/events/:eventId", requireAuth, async (req, res) => {
  const event = await getEventById(db, req.params.eventId);
  if (!event) {
    return res.status(404).send(renderPage({
      title: "Event not found",
      body: `<div class="card"><h1>Event not found</h1></div>`
    }));
  }
  const maskedEvent = maskEventForDisplay(event);

  const body = `
    <div class="card">
      <h1>${maskedEvent.event_name ?? "Event detail"}</h1>
      <p class="muted">${maskedEvent.site_name ?? "Unknown site"} · ${maskedEvent.pixel_id ?? "No pixel"} · ${formatDate(maskedEvent.created_at)}</p>
      <p class="muted">Event ID: <code>${maskedEvent.event_id ?? "—"}</code></p>
      ${maskedEvent.video_id ? `<p class="muted">Video ID: <code>${maskedEvent.video_id}</code> · ${maskedEvent.percent ?? "—"}%</p>` : ""}
      ${maskedEvent.video_mode ? `<p class="muted">Video mode: <strong>${maskedEvent.video_mode}</strong></p>` : ""}
    </div>
    <div class="card">
      <h2>Inbound payload</h2>
      <pre>${JSON.stringify(maskedEvent.inbound_json ?? {}, null, 2)}</pre>
    </div>
    <div class="card">
      <h2>Outbound payload</h2>
      <pre>${JSON.stringify(maskedEvent.outbound_json ?? {}, null, 2)}</pre>
    </div>
    <div class="card">
      <h2>Meta response</h2>
      <pre>${JSON.stringify({ status: maskedEvent.meta_status, body: maskedEvent.meta_body }, null, 2)}</pre>
    </div>
  `;

  res.send(renderPage({ title: "Event detail", body }));
});

app.get("/dashboard/errors", requireAuth, async (req, res) => {
  const selectedType = req.query.type;
  const groups = await listErrorGroups(db);
  let detailHtml = "<p class=\"muted\">Select an error type to inspect details.</p>";

  if (selectedType) {
    const errors = await listErrors(db, { type: selectedType, limit: 10 });
    const relatedEvents = await listRecentEventsForError(db, selectedType, 5);
    const latest = errors[0];

    detailHtml = `
      <div class="card">
        <h2>${selectedType} errors</h2>
        <p class="muted">${getErrorSuggestion(selectedType)}</p>
        <h3>Latest response</h3>
        <pre>${JSON.stringify({ status: latest?.meta_status, body: latest?.meta_body }, null, 2)}</pre>
        <h3>Recent events</h3>
        <ul>
          ${relatedEvents
            .map(
              event => `
            <li>
              <strong>${event.event_name ?? "—"}</strong> (${event.status}) – ${event.site_name ?? "Unknown site"} – ${formatDate(event.created_at)}
            </li>
          `
            )
            .join("")}
        </ul>
      </div>
    `;
  }

  const body = `
    <div class="card">
      <h1>Errors</h1>
      <p class="muted">Grouped by type with suggested resolution.</p>
    </div>
    <div class="grid">
      ${groups
        .map(
          group => `
        <a class="card link-card" href="/dashboard/errors?type=${group.type}">
          <h3>${group.type}</h3>
          <p class="metric">${group.count}</p>
        </a>
      `
        )
        .join("")}
    </div>
    ${detailHtml}
  `;

  res.send(renderPage({ title: "Errors", body }));
});

app.get("/dashboard/settings", requireAuth, (req, res) => {
  res.redirect("/admin/settings");
});

app.get("/admin/settings", requireAuth, async (req, res) => {
  const settings = Object.fromEntries((await listSettings(db)).map(s => [s.key, s.value]));
  const notice = req.query.notice ? `<div class="banner info">${escapeHtml(req.query.notice)}</div>` : "";
  const error = req.query.error ? `<div class="banner warning">${escapeHtml(req.query.error)}</div>` : "";
  const body = `
    <div class="card">
      <h1>Settings</h1>
      <p class="muted">Manage credentials and gateway defaults.</p>
    </div>
    ${notice}
    ${error}
    <div class="card">
      <h2>Change password</h2>
      <form method="post" action="/admin/settings/password" class="form-grid">
        <label>Current password
          <input name="current_password" type="password" required />
        </label>
        <label>New password
          <input name="new_password" type="password" required />
        </label>
        <label>Confirm new password
          <input name="confirm_password" type="password" required />
        </label>
        <button type="submit">Update password</button>
      </form>
    </div>
    <div class="card">
      <h2>Gateway settings</h2>
      <form method="post" action="/admin/settings" class="form-grid">
        <label>Default Meta API version
          <input name="default_meta_api_version" value="${settings.default_meta_api_version ?? "v24.0"}" />
        </label>
        <label>Retry count
          <input name="retry_count" value="${settings.retry_count ?? "1"}" />
        </label>
        <label>Dedup TTL (hours)
          <input name="dedup_ttl_hours" value="${settings.dedup_ttl_hours ?? "48"}" />
        </label>
        <label>Log retention (hours)
          <input name="log_retention_hours" value="${settings.log_retention_hours ?? "168"}" />
        </label>
        <label>Rate limit per minute
          <input name="rate_limit_per_min" value="${settings.rate_limit_per_min ?? "60"}" />
        </label>
        <label>Require HMAC (true/false)
          <input name="hmac_required" value="${settings.hmac_required ?? "false"}" />
        </label>
        <label>HMAC secret
          <input name="hmac_secret" value="${settings.hmac_secret ?? ""}" />
        </label>
        <button type="submit">Save settings</button>
      </form>
    </div>
  `;
  res.send(renderPage({ title: "Settings", body }));
});

app.post("/admin/settings", requireAuth, async (req, res) => {
  await setSetting(db, "default_meta_api_version", req.body.default_meta_api_version || "v24.0");
  await setSetting(db, "retry_count", req.body.retry_count || "1");
  await setSetting(db, "dedup_ttl_hours", req.body.dedup_ttl_hours || "48");
  await setSetting(db, "log_retention_hours", req.body.log_retention_hours || "168");
  await setSetting(db, "rate_limit_per_min", req.body.rate_limit_per_min || "60");
  await setSetting(db, "hmac_required", req.body.hmac_required || "false");
  await setSetting(db, "hmac_secret", req.body.hmac_secret || "");
  await log({ type: "admin", message: "settings updated" });
  res.redirect("/admin/settings?notice=Settings%20updated");
});

app.post("/admin/settings/password", requireAuth, async (req, res) => {
  const currentPassword = req.body.current_password ?? "";
  const newPassword = req.body.new_password ?? "";
  const confirmPassword = req.body.confirm_password ?? "";
  const user = await getUserById(db, req.session.user.id);

  if (!user) {
    return res.redirect("/admin/settings?error=User%20not%20found");
  }

  const currentMatches = await bcrypt.compare(currentPassword, user.password_hash);
  if (!currentMatches) {
    return res.redirect("/admin/settings?error=Current%20password%20is%20incorrect");
  }

  if (newPassword.length < 10) {
    return res.redirect("/admin/settings?error=New%20password%20must%20be%20at%20least%2010%20characters");
  }

  if (newPassword !== confirmPassword) {
    return res.redirect("/admin/settings?error=New%20passwords%20do%20not%20match");
  }

  const newHash = await bcrypt.hash(newPassword, 12);
  await updateUserPassword(db, user.id, newHash);
  await log({ type: "auth", message: "password updated", user: user.username });

  req.session.regenerate(err => {
    if (err) {
      return res.redirect("/admin/settings?error=Unable%20to%20refresh%20session");
    }
    req.session.user = { id: user.id, username: user.username };
    req.session.mustChangePassword = false;
    res.redirect("/admin/settings?notice=Password%20updated");
  });
});

app.get("/admin/events", requireAuth, async (req, res) => {
  const limit = Number.parseInt(req.query.limit ?? "50", 10);
  const events = await listEvents(db, {
    limit: Number.isNaN(limit) ? 50 : limit,
    siteId: req.query.site || undefined,
    status: req.query.status || undefined,
    eventName: req.query.event_name || undefined,
    videoId: req.query.video_id || undefined
  });
  res.json(events.map(event => maskEventForDisplay(event)));
});

app.get("/admin/events/:eventId", requireAuth, async (req, res) => {
  const event = await getEventById(db, req.params.eventId);
  if (!event) return res.status(404).json({ error: "not found" });
  res.json(maskEventForDisplay(event));
});

app.options("/v/track", (req, res) => {
  res.set("access-control-allow-origin", "*");
  res.set("access-control-allow-headers", "content-type,x-site-key");
  res.set("access-control-allow-methods", "POST,OPTIONS");
  res.status(204).send();
});

app.post("/v/track", async (req, res) => {
  res.set("access-control-allow-origin", "*");
  const siteKey = req.headers["x-site-key"] || req.body?.site_key;
  const site = siteKey ? await getSiteByKey(db, siteKey) : null;

  if (!site) {
    await insertError(db, { type: "auth", message: "invalid site key" });
    await log({ type: "auth", message: "invalid site key" });
    return res.status(401).json({ ok: false, error: "invalid site key" });
  }

  const limitPerMinute = await getSettingNumber("rate_limit_per_min", 60);
  const rateKey = `${site.site_key}:${getClientIp(req) || "unknown"}`;
  if (!checkRateLimit(rateKey, limitPerMinute)) {
    await insertError(db, { type: "validation", site_id: site.site_id, message: "rate limit exceeded" });
    await log({ type: "rate_limit", message: "rate limit exceeded", site_id: site.site_id });
    return res.status(429).json({ ok: false, error: "rate limit exceeded" });
  }

  const { video_id, percent, event_id, event_source_url, watch_seconds, duration, fbp, fbc, fbclid } = req.body || {};
  if (!video_id || percent === undefined || percent === null || !event_id) {
    return res.status(400).json({ ok: false, error: "missing required fields" });
  }

  const video = await getVideoBySiteAndVideoId(db, site.site_id, video_id);
  if (!video || !video.enabled) {
    await log({
      type: "video_event_skipped",
      message: "video disabled",
      site_id: site.site_id,
      video_id,
      percent
    });
    return res.json({ ok: false, reason: "video_disabled" });
  }

  const mode = normalizeVideoMode(video.mode);
  const percentValue = Number.parseInt(percent, 10);
  const eventName = Number.isFinite(percentValue) ? `Video${percentValue}` : "Video";
  const resolvedSourceUrl = event_source_url || video.page_url || resolveEventSourceUrl({}, req) || "";
  const userData = {
    client_ip_address: getClientIp(req),
    client_user_agent: req.get("user-agent")
  };
  if (fbp) userData.fbp = fbp;
  if (fbc) {
    userData.fbc = fbc;
  } else if (fbclid) {
    userData.fbc = deriveFbcFromFbclid(fbclid);
  }

  const inboundEvent = {
    event_name: eventName,
    event_time: Math.floor(Date.now() / 1000),
    event_id,
    action_source: "website",
    event_source_url: resolvedSourceUrl,
    user_data: userData,
    custom_data: {
      video_id,
      percent: percentValue,
      watch_seconds,
      duration,
      page_url: video.page_url
    }
  };
  const inboundLogPayload = {
    ...inboundEvent,
    custom_data: {
      ...inboundEvent.custom_data,
      provider: video.provider ?? null,
      provider_video_id: video.provider_video_id ?? null
    }
  };

  await log({
    type: "video_event_inbound",
    site_id: site.site_id,
    video_id,
    percent: percentValue,
    mode
  });

  const dedupTtlHours = await getSettingNumber("dedup_ttl_hours", 48);
  const seen = await hasRecentEventId(db, site.site_id, event_id, dedupTtlHours);
  if (seen) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "deduped",
      inbound_json: JSON.stringify(sanitizePayload(inboundLogPayload, site.log_full_payloads === 1)),
      video_mode: mode
    });
    await log({
      type: "dedup",
      message: "duplicate video event suppressed",
      site_id: site.site_id,
      meta: { event_id, event_name: inboundEvent.event_name }
    });
    return res.json({ ok: true, deduped: true });
  }
  await storeEventId(db, site.site_id, event_id, dedupTtlHours);

  const payload = { data: [inboundEvent] };
  const outboundLog = JSON.stringify({
    ...payload,
    data: [sanitizePayload(inboundEvent, site.log_full_payloads === 1)]
  });
  const inboundLog = JSON.stringify(sanitizePayload(inboundLogPayload, site.log_full_payloads === 1));

  if (mode === "off") {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "video_mode_off" }),
      video_mode: mode
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "video_event_skipped",
      reason: "video_mode_off",
      site_id: site.site_id,
      video_id,
      percent: percentValue,
      mode
    });
    return res.json({ ok: true, forwarded: false, reason: "video_mode_off" });
  }

  if (mode === "test" && !site.test_event_code) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "missing_test_event_code" }),
      video_mode: mode
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "video_event_skipped",
      reason: "missing_test_event_code",
      site_id: site.site_id,
      video_id,
      percent: percentValue,
      mode
    });
    return res.json({ ok: true, forwarded: false, reason: "missing_test_event_code" });
  }

  const accessToken = resolveAccessToken(site);
  if (!site.pixel_id || !accessToken) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "missing_credentials" }),
      video_mode: mode
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "video_event_skipped",
      reason: "missing_credentials",
      site_id: site.site_id,
      video_id,
      percent: percentValue,
      mode
    });
    return res.json({ ok: true, forwarded: false, reason: "missing_credentials" });
  }

  if (!site.send_to_meta || site.dry_run) {
    const reason = site.dry_run ? "dry_run" : "send_to_meta_off";
    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason }),
      video_mode: mode
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "video_event_skipped",
      reason,
      site_id: site.site_id,
      video_id,
      percent: percentValue,
      mode
    });
    return res.json({ ok: true, forwarded: false, reason });
  }

  if (!hasMinimumUserData(userData)) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "insufficient_user_data" }),
      video_mode: mode
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "video_event_skipped",
      reason: "insufficient_user_data",
      site_id: site.site_id,
      video_id,
      percent: percentValue,
      mode
    });
    return res.json({ ok: true, forwarded: false, reason: "insufficient_user_data" });
  }

  const apiVersion = await getSettingValue("default_meta_api_version", "v24.0");
  const url = `https://graph.facebook.com/${apiVersion}/${site.pixel_id}/events?access_token=${accessToken}`;
  if (mode === "test") {
    payload.test_event_code = site.test_event_code;
  }

  try {
    const retryCount = await getSettingNumber("retry_count", 1);
    const { response, body } = await sendToMeta({ url, payload, retryCount });
    const status = response.status;

    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "outbound_sent",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: status,
      meta_body: JSON.stringify(body),
      video_mode: mode
    });

    if (!response.ok) {
      const errorType = status >= 500 ? "meta_5xx" : "meta_4xx";
      await insertError(db, {
        type: errorType,
        site_id: site.site_id,
        event_id,
        message: "Meta API error",
        meta_status: status,
        meta_body: JSON.stringify(body)
      });
    }

    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "video_event_sent",
      site_id: site.site_id,
      video_id,
      percent: percentValue,
      mode,
      meta_status: status,
      meta_response: body
    });
    res.status(response.ok ? 200 : status).json({
      ok: response.ok,
      forwarded: true,
      meta_status: status,
      meta_response: body
    });
  } catch (err) {
    await insertEvent(db, {
      site_id: site.site_id,
      event_id,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "error",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: null,
      meta_body: JSON.stringify({ error: err.toString() }),
      video_mode: mode
    });

    await insertError(db, {
      type: "network",
      site_id: site.site_id,
      event_id,
      message: err.toString()
    });

    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    res.status(500).json({ ok: false, error: "failed to send to meta" });
  }
});

app.post("/collect", async (req, res) => {
  const siteKey = req.headers["x-site-key"];
  const site = siteKey ? await getSiteByKey(db, siteKey) : null;

  if (!site) {
    await insertError(db, { type: "auth", message: "invalid site key" });
    await log({ type: "auth", message: "invalid site key" });
    return res.status(401).json({ error: "invalid site key" });
  }

  const limitPerMinute = await getSettingNumber("rate_limit_per_min", 60);
  const rateKey = `${site.site_key}:${getClientIp(req) || "unknown"}`;
  if (!checkRateLimit(rateKey, limitPerMinute)) {
    await insertError(db, { type: "validation", site_id: site.site_id, message: "rate limit exceeded" });
    await log({ type: "rate_limit", message: "rate limit exceeded", site_id: site.site_id });
    return res.status(429).json({ error: "rate limit exceeded" });
  }

  const hmacRequired = await getSettingBoolean("hmac_required", false);
  const hmacSecret = await getSettingValue("hmac_secret", "");
  const signature = req.headers["x-signature"];

  if (hmacRequired) {
    if (!hmacSecret) {
      await insertError(db, { type: "validation", site_id: site.site_id, message: "hmac secret missing" });
      await log({ type: "error", message: "hmac required but secret missing", site_id: site.site_id });
      return res.status(500).json({ error: "hmac secret not configured" });
    }
    if (!signature || !verifySignature({ secret: hmacSecret, rawBody: req.rawBody ?? "", signature })) {
      await insertError(db, { type: "auth", site_id: site.site_id, message: "invalid signature" });
      await log({ type: "error", message: "invalid signature", site_id: site.site_id });
      return res.status(401).json({ error: "invalid signature" });
    }
  } else if (signature && hmacSecret) {
    if (!verifySignature({ secret: hmacSecret, rawBody: req.rawBody ?? "", signature })) {
      await insertError(db, { type: "auth", site_id: site.site_id, message: "invalid signature" });
      await log({ type: "error", message: "invalid signature", site_id: site.site_id });
      return res.status(401).json({ error: "invalid signature" });
    }
  }

  const inboundEvent = { ...req.body };

  if (!inboundEvent.event_name || !inboundEvent.event_time) {
    await insertError(db, { type: "validation", site_id: site.site_id, message: "missing event_name or event_time" });
    return res.status(400).json({ error: "event_name and event_time are required" });
  }

  if (!inboundEvent.action_source) {
    inboundEvent.action_source = "website";
  }

  if (inboundEvent.action_source === "website") {
    inboundEvent.event_source_url = resolveEventSourceUrl(inboundEvent, req);
    if (!inboundEvent.event_source_url) {
      await insertError(db, { type: "validation", site_id: site.site_id, message: "missing event_source_url" });
      return res.status(400).json({ error: "event_source_url is required for website events" });
    }
  }

  const userData = enrichUserData(inboundEvent, req);
  const minimumUserDataPresent = hasMinimumUserData(userData);

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

  const dedupTtlHours = await getSettingNumber("dedup_ttl_hours", 48);

  if (eventId) {
    const seen = await hasRecentEventId(db, site.site_id, eventId, dedupTtlHours);
    if (seen) {
      await insertEvent(db, {
        site_id: site.site_id,
        event_id: eventId,
        event_name: inboundEvent.event_name,
        event_source_url: inboundEvent.event_source_url,
        status: "deduped",
        inbound_json: JSON.stringify(sanitizePayload(inboundEvent, site.log_full_payloads === 1))
      });
      await log({
        type: "dedup",
        message: "duplicate event suppressed",
        site_id: site.site_id,
        meta: { event_id: eventId, event_name: inboundEvent.event_name }
      });
      return res.json({ ok: true, deduped: true });
    }
    await storeEventId(db, site.site_id, eventId, dedupTtlHours);
  }

  const payload = {
    data: [inboundEvent],
    test_event_code: site.test_event_code
  };

  const accessToken = resolveAccessToken(site);
  const apiVersion = await getSettingValue("default_meta_api_version", "v24.0");
  const url = `https://graph.facebook.com/${apiVersion}/${site.pixel_id}/events?access_token=${accessToken}`;

  const outboundLog = JSON.stringify({
    ...payload,
    data: [sanitizePayload(inboundEvent, site.log_full_payloads === 1)]
  });
  const inboundLog = JSON.stringify(sanitizePayload(inboundEvent, site.log_full_payloads === 1));

  if (!site.pixel_id || !accessToken) {
    const eventDbId = await insertEvent(db, {
      site_id: site.site_id,
      event_id: eventId,
      event_name: inboundEvent.event_name,
      event_source_url: inboundEvent.event_source_url,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "missing_credentials" })
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({ type: "event", site_id: site.site_id, message: "missing credentials", event_db_id: eventDbId });
    return res.json({ ok: true, forwarded: false, reason: "missing_credentials" });
  }

  if (!site.send_to_meta || site.dry_run) {
    const eventDbId = await insertEvent(db, {
      site_id: site.site_id,
      event_id: eventId,
      event_name: inboundEvent.event_name,
      event_source_url: inboundEvent.event_source_url,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "dry_run" })
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({ type: "event", site_id: site.site_id, message: "dry run", event_db_id: eventDbId });
    return res.json({ ok: true, forwarded: false, reason: "dry_run" });
  }

  if (!minimumUserDataPresent) {
    const eventDbId = await insertEvent(db, {
      site_id: site.site_id,
      event_id: eventId,
      event_name: inboundEvent.event_name,
      event_source_url: inboundEvent.event_source_url,
      status: "outbound_skipped",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: 0,
      meta_body: JSON.stringify({ reason: "insufficient_user_data" })
    });
    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "event",
      site_id: site.site_id,
      message: "insufficient user data",
      event_db_id: eventDbId
    });
    return res.json({ ok: true, forwarded: false, reason: "insufficient_user_data" });
  }

  try {
    const retryCount = await getSettingNumber("retry_count", 1);
    const { response, body } = await sendToMeta({ url, payload, retryCount });
    const status = response.status;

    const eventDbId = await insertEvent(db, {
      site_id: site.site_id,
      event_id: eventId,
      event_name: inboundEvent.event_name,
      event_source_url: inboundEvent.event_source_url,
      status: "outbound_sent",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: status,
      meta_body: JSON.stringify(body)
    });

    if (!response.ok) {
      const errorType = status >= 500 ? "meta_5xx" : "meta_4xx";
      await insertError(db, {
        type: errorType,
        site_id: site.site_id,
        event_db_id: eventDbId,
        event_id: eventId,
        message: "Meta API error",
        meta_status: status,
        meta_body: JSON.stringify(body)
      });
    }

    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({
      type: "event",
      site_id: site.site_id,
      message: inboundEvent.event_name,
      status: status,
      meta: { response: body }
    });

    res.status(response.ok ? 200 : status).json({ ok: response.ok, meta: body });
  } catch (err) {
    const eventDbId = await insertEvent(db, {
      site_id: site.site_id,
      event_id: eventId,
      event_name: inboundEvent.event_name,
      event_source_url: inboundEvent.event_source_url,
      status: "error",
      inbound_json: inboundLog,
      outbound_json: outboundLog,
      meta_status: null,
      meta_body: JSON.stringify({ error: err.toString() })
    });

    await insertError(db, {
      type: "network",
      site_id: site.site_id,
      event_db_id: eventDbId,
      event_id: eventId,
      message: err.toString()
    });

    await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
    await log({ type: "error", error: err.toString(), site_id: site.site_id });
    res.status(500).json({ error: "failed to send to meta" });
  }
});

app.listen(PORT, () => {
  console.log(`Meta CAPI Gateway running on :${PORT}`);
});
