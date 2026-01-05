import crypto from "crypto";
import express from "express";
import helmet from "helmet";
import cors from "cors";
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
  insertOutboundLog,
  listErrorGroups,
  listErrors,
  listEvents,
  listVideos,
  listRecentErrors,
  listRecentEventsForError,
  listSettings,
  markInboundDuplicate,
  rotateSiteKey,
  setSetting,
  updateUserPassword,
  storeEventId,
  updateSite,
  updateVideo,
  getSetting,
  hasRecentEventId,
  updateInboundOutbound
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
const REQUEST_LOG_PATHS = new Set(["/sdk/config", "/sdk/ping", "/v/track"]);
app.use((req, res, next) => {
  if (!REQUEST_LOG_PATHS.has(req.path)) {
    next();
    return;
  }
  res.on("finish", () => {
    const body = req.body && typeof req.body === "object" ? req.body : {};
    console.log("[REQ]", req.method, req.path, res.statusCode, {
      origin: req.get("origin") || null,
      referer: req.get("referer") || null,
      userAgent: req.get("user-agent") || null,
      hasSiteKey: Boolean(req.headers["x-site-key"]),
      bodyKeys: Object.keys(body || {})
    });
  });
  next();
});

const PORT = process.env.PORT || 3000;
const DEFAULT_ADMIN_USER = process.env.ADMIN_USER || process.env.DEFAULT_ADMIN_USER || "admin";
const DEFAULT_ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || process.env.DEFAULT_ADMIN_PASSWORD || "admin123";
const SESSION_SECRET = process.env.SESSION_SECRET || "meta-capi-session";
const DB_PATH = process.env.DB_PATH || "./data/meta-capi.sqlite";
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL?.replace(/\/+$/, "") || null;
const APP_ENCRYPTION_KEY = process.env.APP_ENCRYPTION_KEY || "";
const DEFAULT_TIME_ZONE = process.env.DEFAULT_TIME_ZONE || "UTC";
const CORS_ALLOWED_ORIGINS = (process.env.CORS_ALLOWED_ORIGINS || "https://mattmakesmoney.com")
  .split(",")
  .map(origin => origin.trim())
  .filter(Boolean);

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
await ensureSetting(db, "time_zone", DEFAULT_TIME_ZONE);

function normalizeTimeZone(value) {
  if (!value) return null;
  const trimmed = String(value).trim();
  if (!trimmed) return null;
  try {
    Intl.DateTimeFormat("en-US", { timeZone: trimmed }).format(new Date());
    return trimmed;
  } catch {
    return null;
  }
}

let cachedTimeZone = normalizeTimeZone(await getSetting(db, "time_zone")) || DEFAULT_TIME_ZONE;

function getTimeZoneParts(date, timeZone) {
  const formatter = new Intl.DateTimeFormat("en-US", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false
  });
  const parts = formatter.formatToParts(date);
  const map = Object.fromEntries(parts.map(part => [part.type, part.value]));
  return {
    year: Number.parseInt(map.year, 10),
    month: Number.parseInt(map.month, 10),
    day: Number.parseInt(map.day, 10),
    hour: Number.parseInt(map.hour, 10),
    minute: Number.parseInt(map.minute, 10),
    second: Number.parseInt(map.second, 10)
  };
}

function getTimeZoneOffsetMs(date, timeZone) {
  const parts = getTimeZoneParts(date, timeZone);
  const utcMs = Date.UTC(
    parts.year,
    parts.month - 1,
    parts.day,
    parts.hour,
    parts.minute,
    parts.second
  );
  return utcMs - date.getTime();
}

function getStartOfDayUtcMs(timeZone, referenceDate = new Date()) {
  const parts = getTimeZoneParts(referenceDate, timeZone);
  const baseUtcMs = Date.UTC(parts.year, parts.month - 1, parts.day, 0, 0, 0);
  const offsetMs = getTimeZoneOffsetMs(new Date(baseUtcMs), timeZone);
  let candidate = baseUtcMs - offsetMs;
  const candidateParts = getTimeZoneParts(new Date(candidate), timeZone);
  if (candidateParts.hour !== 0 || candidateParts.minute !== 0 || candidateParts.second !== 0) {
    const diffMs =
      (candidateParts.hour * 3600 + candidateParts.minute * 60 + candidateParts.second) * 1000;
    candidate -= diffMs;
  }
  return candidate;
}

function getNextStartOfDayUtcMs(timeZone, startUtcMs) {
  const nextReference = new Date(startUtcMs + 36 * 60 * 60 * 1000);
  return getStartOfDayUtcMs(timeZone, nextReference);
}

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
const publicCors = cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, false);
    if (CORS_ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, origin);
    }
    return callback(null, false);
  },
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "X-Site-Key"],
  credentials: false,
  optionsSuccessStatus: 204
});

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

function maskPixelId(pixelId) {
  if (!pixelId) return null;
  const text = String(pixelId);
  return text.slice(-4);
}

async function logMetaSend({ site, mode, testEventCode, status, responseBody }) {
  await log({
    type: "meta_send",
    site_id: site?.site_id ?? null,
    mode,
    pixel_id: maskPixelId(site?.pixel_id),
    test_event_code: Boolean(testEventCode),
    fbtrace_id: responseBody?.fbtrace_id ?? null,
    events_received: responseBody?.events_received ?? null,
    meta_status: status
  });
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

function resolveOrigin(value) {
  if (!value) return null;
  try {
    return new URL(String(value)).origin;
  } catch {
    return null;
  }
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
  if (Number.isNaN(date.getTime())) return value;
  if (cachedTimeZone) {
    return date.toLocaleString("en-US", { timeZone: cachedTimeZone });
  }
  return date.toLocaleString();
}

function renderStatusPill(status) {
  const normalized = status || "unknown";
  return `<span class="pill pill-${normalized}">${normalized.replace("_", " ")}</span>`;
}

function resolveOutboundStatus(result) {
  if (!result) return null;
  if (result === "sent") return "outbound_sent";
  if (result === "skipped") return "outbound_skipped";
  if (result === "failed") return "outbound_failed";
  return result;
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

function formatForwardReason(reason) {
  return reason ? String(reason) : "null";
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

const HTML5_VIDEO_EXTENSIONS = [".mp4", ".webm", ".ogg"];

function isPlayableHtml5Source(videoSourceUrl) {
  if (!videoSourceUrl) return false;
  try {
    const parsedUrl = new URL(String(videoSourceUrl).trim());
    const path = parsedUrl.pathname.toLowerCase();
    return HTML5_VIDEO_EXTENSIONS.some(ext => path.endsWith(ext));
  } catch (error) {
    return false;
  }
}

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
  const lowerPath = path.toLowerCase();
  const segments = path.split("/").filter(Boolean);

  if (HTML5_VIDEO_EXTENSIONS.some(ext => lowerPath.endsWith(ext))) {
    return { provider: "html5", providerVideoId: null };
  }

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

function buildVideoTestSnippet({ host, siteKey, videoId, videoSourceUrl, includeSource, showSourceWarning }) {
  const videoDomId = `capi-video-${videoId}`;
  const sourceAttribute = includeSource && videoSourceUrl ? `\n    src="${videoSourceUrl}"` : "";
  const sourceComment = showSourceWarning
    ? "\n  <!-- Video Source URL is not a direct HTML5 video file. Insert a source or embed manually. -->"
    : "";
  return `<div style="max-width: 900px; margin: 0 auto; text-align: center;">
  <video
    id="${videoDomId}"
    controls
    playsinline
    preload="metadata"
    style="width: 100%; max-width: 900px; border-radius: 12px;"${sourceAttribute}>
  </video>${sourceComment}

  <script
    src="${host}/sdk/video-tracker.js"
    data-site-key="${siteKey}"
    data-video-id="${videoId}"
    data-selector="#${videoDomId}">
  </script>
</div>`;
}

function resolveSnippetBaseUrl(req) {
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
    outbound_json: maskPayloadForDisplay(event.outbound_json),
    outbound_request_json: maskPayloadForDisplay(event.outbound_request_json),
    outbound_response_json: event.outbound_response_json
  };
}

function safeJsonParse(value) {
  if (!value) return null;
  try {
    return JSON.parse(value);
  } catch {
    return { error: "invalid_json" };
  }
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
    await logMetaSend({
      site,
      mode: "test",
      testEventCode: site.test_event_code,
      status,
      responseBody: body
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

app.get("/sdk/config", publicCors, async (req, res) => {
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

app.get("/sdk/ping", publicCors, async (req, res) => {
  const siteKey = req.query.site_key ?? null;
  const videoId = req.query.video_id ?? null;
  console.log("[PING]", {
    site_key: siteKey,
    video_id: videoId,
    origin: req.get("origin") || null,
    referer: req.get("referer") || null,
    ua: req.get("user-agent") || null
  });
  await log({
    type: "sdk_ping",
    site_key: siteKey,
    video_id: videoId,
    origin: req.get("origin") || null,
    referer: req.get("referer") || null,
    ua: req.get("user-agent") || null
  });
  res.json({ ok: true });
});

app.get("/sdk/video-tracker.js", async (req, res) => {
  res.set("content-type", "application/javascript; charset=utf-8");
  res.set("cross-origin-resource-policy", "cross-origin");
  res.set("cache-control", "public, max-age=300");
  res.removeHeader("cross-origin-embedder-policy");
  res.removeHeader("cross-origin-opener-policy");
  await log({
    type: "sdk_script_request",
    origin: req.get("origin") || null,
    referer: req.get("referer") || null,
    headers: req.headers
  });
  res.send(`
    (function() {
      window.__CAPI_VT_EXEC__ = (window.__CAPI_VT_EXEC__ || 0) + 1;
      const SDK_VERSION = "0.1.0";
      const DEBUG_QUERY_VALUE = new URLSearchParams(window.location.search).get('capi_debug');
      const RESET_QUERY_VALUE = new URLSearchParams(window.location.search).get('capi_reset');
      const SCRIPT = document.currentScript;

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

      function mask(value) {
        if (!value) return '';
        if (value.length <= 4) return '…';
        if (value.length <= 10) return value.slice(0, 2) + '…' + value.slice(-2);
        return value.slice(0, 6) + '…' + value.slice(-4);
      }

      function createLogger(debug) {
        const prefix = '[CAPI VideoTracker]';
        return {
          log: (...args) => {
            if (debug) console.log(prefix, ...args);
          },
          warn: (...args) => {
            if (debug) console.warn(prefix, ...args);
          },
          error: (...args) => {
            if (debug) console.error(prefix, ...args);
          }
        };
      }

      function createWarnOnce() {
        const seen = new Set();
        const prefix = '[CAPI VideoTracker]';
        return (key, message, data) => {
          if (seen.has(key)) return;
          seen.add(key);
          if (data !== undefined) {
            console.warn(prefix, message, data);
          } else {
            console.warn(prefix, message);
          }
        };
      }

      async function sha256Hex(text) {
        if (!crypto || !crypto.subtle) {
          return text;
        }
        const data = new TextEncoder().encode(text);
        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
      }

      function parseDebugValue(value) {
        if (!value) return false;
        const normalized = String(value).toLowerCase();
        return normalized === '1' || normalized === 'true';
      }

      function getPersistedMilestones(storageKey) {
        try {
          const raw = localStorage.getItem(storageKey);
          if (!raw) return [];
          const parsed = JSON.parse(raw);
          return Array.isArray(parsed) ? parsed : [];
        } catch (err) {
          return [];
        }
      }

      function persistMilestones(storageKey, milestones) {
        try {
          localStorage.setItem(storageKey, JSON.stringify(milestones));
        } catch (err) {
          // ignore storage errors
        }
      }

      function findVideoElement(selector, log, warn, error, warnOnce) {
        return new Promise(resolve => {
          const start = Date.now();
          const interval = 250;
          const maxWait = 5000;
          let attempt = 0;

          function check() {
            attempt += 1;
            const element = document.querySelector(selector);
            if (element) {
              log('video element found', { selector, attempt });
              resolve(element);
              return;
            }
            if (Date.now() - start >= maxWait) {
              error('video element not found; aborting', { selector });
              warnOnce('video-not-found', 'video element not found; tracker disabled', { selector });
              resolve(null);
              return;
            }
            warn('video element not found yet', { selector, attempt });
            setTimeout(check, interval);
          }

          check();
        });
      }

      async function setupTracker(script) {
        const siteKey = script.dataset.siteKey;
        const videoId = script.dataset.videoId;
        const selector = script.dataset.selector || 'video';
        const datasetLog = {
          videoId,
          selector,
          hasSiteKey: Boolean(siteKey)
        };
        if (!videoId) {
          console.warn('[CAPI VideoTracker] missing data-video-id; tracker disabled');
          return;
        }
        if (!siteKey) {
          console.warn('[CAPI VideoTracker] missing data-site-key; tracker disabled');
          return;
        }

        const debug = parseDebugValue(script.dataset.debug)
          || parseDebugValue(DEBUG_QUERY_VALUE)
          || parseDebugValue(window.CAPI_VIDEO_DEBUG);
        const { log, warn, error } = createLogger(debug);
        const warnOnce = createWarnOnce();

        if (debug) {
          console.log('[CAPI VT] init', { version: SDK_VERSION });
          console.log('[CAPI VT] dataset', datasetLog);
        }

        log('script loaded', {
          version: SDK_VERSION,
          videoId,
          selector,
          siteKeyMasked: mask(siteKey),
          pageUrl: window.location.href
        });

        const baseUrl = new URL(script.src, window.location.href).origin;
        try {
          const defaultConfig = {
            enabled: true,
            mode: 'live',
            milestones: [25, 50, 75, 95]
          };
          let config = defaultConfig;
          try {
            log('fetching config', { videoId });
            const configRes = await fetch(
              baseUrl + '/sdk/config?site_key=' + encodeURIComponent(siteKey) + '&video_id=' + encodeURIComponent(videoId)
            );
            if (!configRes.ok) {
              throw new Error('config status ' + configRes.status);
            }
            const configJson = await configRes.json();
            config = { ...defaultConfig, ...configJson };
            log('config fetched', config);
          } catch (configErr) {
            error('config fetch failed; using defaults', configErr);
            config = defaultConfig;
          }

          if (!config || config.enabled === false || config.mode === 'off') {
            warnOnce('tracking-disabled', 'tracking disabled by config', config);
            return;
          }
          if (debug) {
            console.log('[CAPI VT] config', {
              enabled: config.enabled,
              mode: config.mode,
              milestones: config.milestones
            });
          }

          const milestones = (config.milestones || defaultConfig.milestones).slice().sort((a, b) => a - b);
          const video = await findVideoElement(selector, log, warn, error, warnOnce);
          if (!video) return;
          if (debug) {
            console.log('[CAPI VT] video_found', {
              paused: video.paused,
              currentTime: video.currentTime,
              duration: video.duration,
              visibilityState: document.visibilityState
            });
          }

          try {
            log('pinging sdk', { videoId });
            const pingResponse = await fetch(
              baseUrl + '/sdk/ping?site_key=' + encodeURIComponent(siteKey) + '&video_id=' + encodeURIComponent(videoId),
              { method: 'GET', keepalive: true }
            );
            if (debug) {
              console.log('[CAPI VT] ping', { status: pingResponse.status });
            }
          } catch (pingErr) {
            warn('sdk ping failed', pingErr);
          }

          const sessionId = getSessionId();
          const firedStorageKey = 'metaCapiVideoMilestones:' + videoId;
          const fired = new Set(getPersistedMilestones(firedStorageKey));
          const tickIntervalMs = 250;
          let watchedSeconds = 0;
          let lastTime = video.currentTime || 0;
          let lastProgressLog = 0;
          let timerId = null;

          if (RESET_QUERY_VALUE === '1') {
            try {
              localStorage.removeItem(firedStorageKey);
              fired.clear();
              log('reset milestones via capi_reset=1', { storageKey: firedStorageKey });
            } catch (resetErr) {
              warn('failed to reset milestones', resetErr);
            }
          }

          function updateFiredStorage() {
            const entries = Array.from(fired.values());
            persistMilestones(firedStorageKey, entries);
            log('fired set updated', entries);
          }

          function duration() {
            return Number.isFinite(video.duration) ? video.duration : 0;
          }

          function percentWatched() {
            const currentDuration = duration();
            if (!currentDuration) return 0;
            return Math.floor((watchedSeconds / currentDuration) * 100);
          }

          function logProgress() {
            const now = Date.now();
            if (now - lastProgressLog < 2000) return;
            lastProgressLog = now;
            if (debug) {
              console.log('[CAPI VT] progress_heartbeat', {
                watchedSeconds,
                currentTime: video.currentTime,
                duration: duration(),
                percent: percentWatched(),
                visibilityState: document.visibilityState,
                paused: video.paused,
                seeking: video.seeking
              });
            }
            log('progress heartbeat', {
              watchedSeconds,
              currentTime: video.currentTime,
              duration: duration(),
              percent: percentWatched(),
              paused: video.paused
            });
          }

          async function sendMilestone(percent) {
            if (fired.has(percent)) return;
            fired.add(percent);
            updateFiredStorage();
            const eventId = await sha256Hex(videoId + '|' + percent + '|' + sessionId);
            if (debug) {
              console.log('[CAPI VT] milestone', {
                milestone: percent,
                percent: percentWatched(),
                event_id: eventId
              });
            }
            log('milestone fired', {
              milestone: percent,
              event_id: eventId,
              watchedSeconds,
              duration: duration()
            });
            const payload = {
              video_id: videoId,
              percent: percent,
              event_id: eventId,
              event_source_url: window.location.href,
              watch_seconds: Math.round(watchedSeconds),
              duration: Math.round(duration())
            };
            const fbp = getCookieValue('_fbp');
            const fbc = getCookieValue('_fbc');
            if (fbp) payload.fbp = fbp;
            if (fbc) payload.fbc = fbc;
            const fbclid = new URLSearchParams(window.location.search).get('fbclid');
            if (fbclid) payload.fbclid = fbclid;

            try {
              const trackUrl = baseUrl + '/v/track';
              console.log('[CAPI VT] POST /v/track milestone=' + percent + ' pct=' + percentWatched() + ' ws=' + Math.round(watchedSeconds));
              log('send attempt', { milestone: percent, event_id: eventId, url: trackUrl });
              const response = await fetch(trackUrl, {
                method: 'POST',
                headers: {
                  'content-type': 'application/json',
                  'x-site-key': siteKey
                },
                body: JSON.stringify(payload),
                keepalive: true
              });
              let responseBody = null;
              try {
                responseBody = await response.clone().json();
              } catch (parseErr) {
                responseBody = await response.text();
              }
              const inboundId = responseBody && typeof responseBody === 'object' ? responseBody.inbound_id : null;
              const traceId = responseBody && typeof responseBody === 'object' ? responseBody.trace_id : null;
              console.log('[CAPI VT] post_result status=' + response.status + ' inbound_id=' + (inboundId || 'null') + ' trace_id=' + (traceId || 'null'));
              log('/v/track response', { url: trackUrl, status: response.status, body: responseBody });
            } catch (err) {
              error('send failed', err);
            }
          }

          function checkMilestones() {
            const percent = percentWatched();
            milestones.forEach(milestone => {
              if (percent >= milestone) {
                sendMilestone(milestone);
              }
            });
          }

          function sampleTick(source) {
            if (!video) return;
            const currentDuration = duration();
            const currentTime = video.currentTime || 0;
            if (!currentDuration) {
              lastTime = currentTime;
              return;
            }
            const isVisible = document.visibilityState ? document.visibilityState === 'visible' : !document.hidden;
            if (video.paused || video.seeking || !isVisible) {
              lastTime = currentTime;
              return;
            }
            const delta = currentTime - lastTime;
            if (delta > 0 && delta <= 5) {
              watchedSeconds += delta;
            } else if (delta > 5 && debug) {
              warn('large jump ignored', { delta, currentTime, lastTime, source });
            }
            lastTime = currentTime;
            logProgress();
            checkMilestones();
          }

          function startLoop() {
            if (timerId) return;
            lastTime = video.currentTime || lastTime || 0;
            if (debug) {
              console.log('[CAPI VT] loop_start');
            }
            log('loop started', { currentTime: lastTime, duration: duration() });
            timerId = setInterval(() => {
              sampleTick('interval');
            }, tickIntervalMs);
          }

          function stopLoop() {
            if (!timerId) return;
            clearInterval(timerId);
            timerId = null;
            if (debug) {
              console.log('[CAPI VT] loop_stop');
            }
            log('loop stop', {});
          }

          video.addEventListener('loadedmetadata', () => {
            log('loadedmetadata', { duration: video.duration });
            if (!video.paused && !video.ended) {
              startLoop();
            }
          });

          setTimeout(() => {
            if (!duration()) {
              warnOnce('duration-invalid', 'duration still invalid; milestones may not fire', { duration: duration() });
            }
          }, 5000);

          video.addEventListener('playing', () => {
            startLoop();
          });

          video.addEventListener('play', () => {
            startLoop();
          });

          video.addEventListener('pause', () => {
            stopLoop();
          });

          video.addEventListener('ended', () => {
            const currentDuration = duration();
            if (currentDuration) {
              watchedSeconds = Math.max(watchedSeconds, currentDuration);
            }
            checkMilestones();
            stopLoop();
          });

          if (!video.paused && !video.ended) {
            startLoop();
          }
        } catch (err) {
          error('tracker setup failed', err);
        }
      }

      if (!SCRIPT || !SCRIPT.dataset) {
        console.warn('[CAPI VideoTracker] no currentScript found; aborting');
        return;
      }
      setupTracker(SCRIPT);
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
  const todayFilter =
    req.query.today === "1" || req.query.today === "true" || req.query.today === "yes";
  let receivedAtRange = null;
  if (todayFilter) {
    const timeZone =
      normalizeTimeZone(req.query.time_zone) || cachedTimeZone || DEFAULT_TIME_ZONE;
    const startUtcMs = getStartOfDayUtcMs(timeZone, new Date());
    const endUtcMs = getNextStartOfDayUtcMs(timeZone, startUtcMs) - 1;
    receivedAtRange = { startUtcMs, endUtcMs };
  }
  const events = await listEvents(db, { limit: safeLimit, receivedAtRange });
  const errors = await listRecentErrors(db, safeLimit);
  res.json({ events, errors });
});

app.get("/api/inbound/recent", requireAuth, async (req, res) => {
  const limit = Number.parseInt(req.query.limit ?? "50", 10);
  const safeLimit = Number.isNaN(limit) ? 50 : Math.min(Math.max(limit, 1), 200);
  const siteKey = req.query.site_key ?? null;
  const videoId = req.query.video_id ?? null;
  const sinceId = Number.parseInt(req.query.since_id ?? "", 10);
  const conditions = [];
  const params = [];

  if (siteKey) {
    conditions.push("sites.site_key = ?");
    params.push(siteKey);
  }
  if (videoId) {
    conditions.push("events.video_id = ?");
    params.push(videoId);
  }
  if (!Number.isNaN(sinceId)) {
    conditions.push("events.id > ?");
    params.push(sinceId);
  }

  const whereClause = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  // Ordered newest -> oldest for consistent rendering.
  const rows = await db.all(
    `
      SELECT events.id,
        events.received_at_utc_ms,
        events.received_at,
        events.ip_address,
        events.event_source_url,
        events.video_id,
        events.event_name,
        events.percent,
        events.trace_id,
        events.user_agent,
        events.inbound_json,
        sites.site_key
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      ${whereClause}
      ORDER BY events.id DESC
      LIMIT ?
    `,
    ...params,
    safeLimit
  );

  const mappedRows = rows.map(row => {
    const inbound = safeJsonParse(row.inbound_json);
    const customData = inbound?.custom_data || {};
    return {
      id: row.id,
      ts: row.received_at_utc_ms ?? row.received_at ?? null,
      ip: row.ip_address ?? null,
      origin: resolveOrigin(row.event_source_url),
      site_key: row.site_key ?? null,
      video_id: row.video_id ?? null,
      event_name: row.event_name ?? null,
      percent: row.percent ?? null,
      watched_seconds: customData.watch_seconds ?? null,
      duration: customData.duration ?? null,
      trace_id: row.trace_id ?? null,
      user_agent: row.user_agent ?? null
    };
  });

  res.json({ ok: true, rows: mappedRows });
});

app.get("/admin/debug/db-info", requireAuth, async (req, res) => {
  const inboundCount = await db.get("SELECT COUNT(*) as count FROM events");
  const outboundCount = await db.get("SELECT COUNT(*) as count FROM outbound_logs");
  const range = await db.get(
    "SELECT MIN(received_at_utc_ms) as min, MAX(received_at_utc_ms) as max FROM events"
  );
  res.json({
    db_path: DB_PATH,
    inbound_count: inboundCount?.count ?? 0,
    outbound_count: outboundCount?.count ?? 0,
    received_at_utc_ms: {
      min: range?.min ?? null,
      max: range?.max ?? null
    }
  });
});

app.get("/admin/debug/last-inbound", requireAuth, async (req, res) => {
  const limit = Number.parseInt(req.query.limit ?? "50", 10);
  const safeLimit = Number.isNaN(limit) ? 50 : Math.min(Math.max(limit, 1), 200);
  const rows = await db.all(
    `
      SELECT events.id,
        events.received_at_utc_ms,
        events.received_at,
        events.video_id,
        events.event_name,
        events.percent,
        events.trace_id,
        events.event_source_url,
        events.inbound_json,
        sites.site_key
      FROM events
      LEFT JOIN sites ON events.site_id = sites.site_id
      ORDER BY events.received_at_utc_ms DESC, events.id DESC
      LIMIT ?
    `,
    safeLimit
  );
  const tableRows = rows
    .map(row => {
      const inbound = safeJsonParse(row.inbound_json);
      const customData = inbound?.custom_data || {};
      return `
        <tr>
          <td>${escapeHtml(row.id)}</td>
          <td>${escapeHtml(formatDate(row.received_at_utc_ms ?? row.received_at))}</td>
          <td>${escapeHtml(row.site_key ?? "—")}</td>
          <td>${escapeHtml(row.video_id ?? "—")}</td>
          <td>${escapeHtml(row.event_name ?? "—")}</td>
          <td>${escapeHtml(row.percent ?? "—")}</td>
          <td>${escapeHtml(customData.watch_seconds ?? "—")}</td>
          <td>${escapeHtml(row.trace_id ?? "—")}</td>
          <td>${escapeHtml(resolveOrigin(row.event_source_url) ?? "—")}</td>
        </tr>
      `;
    })
    .join("");
  const body = `
    <div class="card">
      <h1>Last inbound events</h1>
      <p class="muted">Auto-refreshes every 2 seconds.</p>
    </div>
    <div class="card">
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Site</th>
            <th>Video</th>
            <th>Event</th>
            <th>%</th>
            <th>Watched Seconds</th>
            <th>Trace</th>
            <th>Origin</th>
          </tr>
        </thead>
        <tbody>
          ${tableRows}
        </tbody>
      </table>
    </div>
    <script>
      setTimeout(() => window.location.reload(), 2000);
    </script>
  `;
  res.send(renderPage({ title: "Last inbound events", body }));
});

app.get("/admin/debug/trace/:trace_id", requireAuth, async (req, res) => {
  const inbound = await db.get("SELECT * FROM events WHERE trace_id = ? LIMIT 1", req.params.trace_id);
  if (!inbound) {
    return res.status(404).json({ error: "not found" });
  }
  const outboundRows = await db.all(
    "SELECT * FROM outbound_logs WHERE inbound_id = ? ORDER BY id ASC",
    inbound.id
  );
  res.json({
    inbound: {
      ...inbound,
      inbound_json: safeJsonParse(inbound.inbound_json),
      outbound_json: safeJsonParse(inbound.outbound_json),
      meta_body: safeJsonParse(inbound.meta_body)
    },
    outbound: outboundRows.map(row => ({
      ...row,
      request_payload_json: safeJsonParse(row.request_payload_json),
      response_body_json: safeJsonParse(row.response_body_json)
    }))
  });
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
    "SELECT COUNT(*) as count FROM events WHERE outbound_result = 'skipped' AND created_at > datetime('now', '-24 hours')"
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
              <td>${formatDate(event.received_at_utc_ms ?? event.received_at ?? event.created_at)}</td>
              <td>${event.site_name ?? "—"}</td>
              <td><a href="/dashboard/events/${event.id}">${event.event_name ?? "—"}</a></td>
              <td>${event.pixel_id ?? "—"}</td>
              <td>${renderStatusPill(resolveOutboundStatus(event.outbound_result) || event.status)}</td>
            </tr>
          `
            )
            .join("")}
        </tbody>
      </table>
    </div>
    <div class="card">
      <div class="inline">
        <div>
          <h2>Live Inbound</h2>
          <p class="muted">Newest inbound tracking events (auto-refresh every 2 seconds).</p>
        </div>
        <div class="muted">
          <div id="live-inbound-updated">Last updated: —</div>
          <div>Total rows: <span id="live-inbound-count">0</span></div>
        </div>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Time</th>
            <th>Site Key</th>
            <th>Video</th>
            <th>Event</th>
            <th>%</th>
            <th>Watched</th>
            <th>Duration</th>
            <th>Trace</th>
            <th>Origin</th>
            <th>IP</th>
            <th>User Agent</th>
          </tr>
        </thead>
        <tbody id="live-inbound-body"></tbody>
      </table>
    </div>
    <script>
      const liveInboundBody = document.getElementById('live-inbound-body');
      const liveInboundUpdated = document.getElementById('live-inbound-updated');
      const liveInboundCount = document.getElementById('live-inbound-count');
      const liveTimeZone = ${JSON.stringify(cachedTimeZone)};
      let lastRenderedId = null;

      function formatInboundTime(value) {
        if (!value) return '—';
        const date = new Date(value);
        if (Number.isNaN(date.getTime())) return value;
        if (liveTimeZone) {
          return date.toLocaleString('en-US', { timeZone: liveTimeZone });
        }
        return date.toLocaleString();
      }

      function createCell(text, className) {
        const cell = document.createElement('td');
        if (className) cell.className = className;
        cell.textContent = text === null || text === undefined || text === '' ? '—' : String(text);
        return cell;
      }

      function renderInboundRow(row) {
        const tr = document.createElement('tr');
        tr.appendChild(createCell(row.id));
        tr.appendChild(createCell(formatInboundTime(row.ts)));
        tr.appendChild(createCell(row.site_key));
        tr.appendChild(createCell(row.video_id));
        tr.appendChild(createCell(row.event_name));
        tr.appendChild(createCell(row.percent));
        tr.appendChild(createCell(row.watched_seconds));
        tr.appendChild(createCell(row.duration));
        tr.appendChild(createCell(row.trace_id));
        tr.appendChild(createCell(row.origin));
        tr.appendChild(createCell(row.ip));
        const uaCell = createCell(row.user_agent);
        uaCell.classList.add('truncate');
        tr.appendChild(uaCell);
        return tr;
      }

      function updateCounts() {
        liveInboundCount.textContent = String(liveInboundBody.children.length);
      }

      async function loadInbound() {
        const params = new URLSearchParams({ limit: '50' });
        if (lastRenderedId) params.set('since_id', lastRenderedId);
        const response = await fetch('/api/inbound/recent?' + params.toString());
        const payload = await response.json();
        if (!payload || !payload.ok) return;
        const rows = payload.rows || [];
        if (rows.length) {
          for (let i = rows.length - 1; i >= 0; i -= 1) {
            const row = rows[i];
            const tr = renderInboundRow(row);
            liveInboundBody.prepend(tr);
            if (!lastRenderedId || row.id > lastRenderedId) {
              lastRenderedId = row.id;
            }
          }
          updateCounts();
        }
        liveInboundUpdated.textContent = 'Last updated: ' + new Date().toLocaleTimeString();
      }

      loadInbound();
      setInterval(loadInbound, 2000);
    </script>
  `;

  res.send(renderPage({ title: "Dashboard", body }));
});

app.get("/dashboard/sites", requireAuth, async (req, res) => {
  const sites = await getSites(db);
  const skippedCount = await db.get(
    "SELECT COUNT(*) as count FROM events WHERE outbound_result = 'skipped' AND created_at > datetime('now', '-24 hours')"
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
      <div class="inline">
        <button type="button" class="secondary" id="test-ping-button">Send test ping</button>
        <span id="test-ping-status" class="muted"></span>
      </div>
      <div id="test-ping-trace" class="muted"></div>
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
        <div id="test-event-fbtrace" class="muted"></div>
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
      const testFbtrace = document.getElementById('test-event-fbtrace');
      const testPayload = document.getElementById('test-event-payload');
      const testResponse = document.getElementById('test-event-response');
      const testSubmit = document.getElementById('test-event-submit');
      const testFields = testForm.querySelectorAll('[data-event-types]');
      const testPingButton = document.getElementById('test-ping-button');
      const testPingStatus = document.getElementById('test-ping-status');
      const testPingTrace = document.getElementById('test-ping-trace');

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
        const fbtraceId = result.meta_response && result.meta_response.fbtrace_id
          ? result.meta_response.fbtrace_id
          : null;
        testFbtrace.textContent = fbtraceId ? 'fbtrace_id: ' + fbtraceId : '';
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

      testPingButton.addEventListener('click', async () => {
        testPingStatus.textContent = 'Sending...';
        testPingTrace.textContent = '';
        testPingButton.disabled = true;
        try {
          const response = await fetch('/dashboard/sites/${site.site_id}/test-ping', {
            method: 'POST',
            headers: { 'content-type': 'application/json' }
          });
          const result = await response.json();
          if (!response.ok) {
            setWarning(result.error || 'Failed to send test ping.');
            testPingStatus.textContent = 'Failed';
            return;
          }
          renderResult(result);
          const fbtraceId = result.meta_response && result.meta_response.fbtrace_id
            ? result.meta_response.fbtrace_id
            : null;
          testPingStatus.textContent = result.forwarded === false ? 'Skipped' : 'Sent';
          testPingTrace.textContent = fbtraceId ? 'fbtrace_id: ' + fbtraceId : '';
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
          testPingStatus.textContent = 'Failed';
        } finally {
          testPingButton.disabled = false;
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

app.post("/dashboard/sites/:siteId/test-ping", requireAuth, async (req, res) => {
  const site = await getSiteById(db, req.params.siteId);
  if (!site) {
    return res.status(404).json({ ok: false, error: "site_not_found" });
  }

  const result = await sendTestEvent({ site, eventType: "PageView", overrides: {} });
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
  const host = resolveSnippetBaseUrl(req);

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
  const host = resolveSnippetBaseUrl(req);
  const snippet = buildVideoSnippet({
    host,
    siteKey: video.site_key,
    videoId: video.video_id,
    selector: video.selector
  });
  const isPlayableSource = isPlayableHtml5Source(video.video_source_url);
  const needsSourceWarning = Boolean(video.video_source_url) && (video.provider !== "html5" || !isPlayableSource);
  const testSnippet = buildVideoTestSnippet({
    host,
    siteKey: video.site_key,
    videoId: video.video_id,
    videoSourceUrl: video.video_source_url,
    includeSource: isPlayableSource,
    showSourceWarning: needsSourceWarning
  });
  const encodedSnippet = encodeURIComponent(snippet);
  const encodedTestSnippet = encodeURIComponent(testSnippet);
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
      <h2>Snippets</h2>
      <p class="muted">Milestones sent: Video25/50/75/95. <code>video_id</code> is passed in <code>custom_data</code>.</p>
      <p class="muted">Detected provider: <strong>${formatVideoProvider(video.provider)}</strong>${video.provider_video_id ? ` (ID: ${video.provider_video_id})` : ""}</p>
      ${needsSourceWarning ? `<div class="banner warning">Video Source URL is not a direct HTML5 video file. Self-contained test snippet will omit src.</div>` : ""}
      <h3>Self-contained test snippet</h3>
      <p class="muted">Paste into a blank HTML file to test tracking immediately.</p>
      <pre><code>${escapeHtml(testSnippet)}</code></pre>
      <button class="button secondary copy-snippet" data-snippet="${encodedTestSnippet}">Copy Test Snippet</button>
      <h3>Minimal production snippet</h3>
      <p class="muted">Use when embedding on your existing page.</p>
      <pre><code>${escapeHtml(snippet)}</code></pre>
      <button class="button secondary copy-snippet" data-snippet="${encodedSnippet}">Copy Production Snippet</button>
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

      document.querySelectorAll('.copy-snippet').forEach(button => {
        button.addEventListener('click', async () => {
          const text = decodeURIComponent(button.dataset.snippet || '');
          const ok = await copyText(text);
          const label = button.textContent;
          button.textContent = ok ? 'Copied!' : 'Copy failed';
          setTimeout(() => { button.textContent = label; }, 1500);
        });
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
  const dateFilterActive =
    req.query.today === "1" || req.query.today === "true" || req.query.today === "yes";
  const timeZoneLabel = cachedTimeZone || DEFAULT_TIME_ZONE;
  const logFiltersBanner = `
    <div class="banner info">
      <strong>Log Filters:</strong>
      Time zone <code>${escapeHtml(timeZoneLabel)}</code> ·
      Date filter <strong>${dateFilterActive ? "Today" : "None"}</strong>
    </div>
  `;

  const body = `
    <div class="card">
      <h1>Live Events</h1>
      <p class="muted">Auto-refreshing stream (every 2 seconds).</p>
    </div>
    ${logFiltersBanner}
    <div class="split-pane">
      <section class="pane pane-list">
        <div class="filters">
          <label>Site
            <select id="filter-site">
              <option value="">All sites</option>
              ${siteOptions}
            </select>
          </label>
          <label>Event type
            <select id="filter-type">
              <option value="">All</option>
              <option value="video_milestone">Video milestone</option>
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
              <option value="outbound_failed">Outbound failed</option>
              <option value="duplicate">Duplicate</option>
              <option value="deduped">Deduped</option>
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
      const timeZone = ${JSON.stringify(cachedTimeZone)};
      const streamEl = document.getElementById('event-stream');
      const detailEl = document.getElementById('event-detail');
      const filterSite = document.getElementById('filter-site');
      const filterType = document.getElementById('filter-type');
      const filterVideo = document.getElementById('filter-video');
      const filterStatus = document.getElementById('filter-status');
      const filterName = document.getElementById('filter-name');

      function buildQuery() {
        const params = new URLSearchParams();
        if (filterSite.value) params.set('site', filterSite.value);
        if (filterType.value) params.set('event_type', filterType.value);
        if (filterVideo.value) params.set('video_id', filterVideo.value);
        if (filterStatus.value) params.set('status', filterStatus.value);
        if (filterName.value) params.set('event_name', filterName.value);
        return params.toString();
      }

      function formatEventTime(value) {
        const date = new Date(value);
        if (timeZone) {
          return date.toLocaleTimeString('en-US', { timeZone });
        }
        return date.toLocaleTimeString();
      }

      function formatEventDate(value) {
        const date = new Date(value);
        if (timeZone) {
          return date.toLocaleString('en-US', { timeZone });
        }
        return date.toLocaleString();
      }

      function resolveEventTimestamp(event) {
        if (event.received_at_utc_ms) return event.received_at_utc_ms;
        if (event.received_at) {
          const parsed = Date.parse(event.received_at);
          if (!Number.isNaN(parsed)) return parsed;
        }
        if (event.created_at) {
          const parsed = Date.parse(event.created_at);
          if (!Number.isNaN(parsed)) return parsed;
        }
        return Date.now();
      }

      function renderRow(event) {
        const row = document.createElement('div');
        const outboundStatus = event.outbound_result ? 'outbound_' + event.outbound_result : (event.status || '');
        row.className = 'event-row ' + outboundStatus;
        row.dataset.id = event.id;
        const inboundBits = [];
        if (event.video_id) {
          inboundBits.push('Video ' + event.video_id);
        }
        if (event.percent !== null && event.percent !== undefined) {
          inboundBits.push(event.percent + '%');
        }
        const inboundLine = inboundBits.length ? '<div class="muted">' + inboundBits.join(' · ') + '</div>' : '';
        const sourceLine = event.event_source_url
          ? '<div class="muted truncate" title="' + event.event_source_url + '">' + event.event_source_url + '</div>'
          : '';
        const duplicateLine = event.duplicate_count > 0
          ? '<div><span class="pill pill-duplicate" title="Duplicate received">Duplicate x' + event.duplicate_count + '</span></div>'
          : '';
        const outboundLabel = event.outbound_result
          ? event.outbound_result
          : (event.status || 'received');
        const isOutboundStatus = ['sent', 'skipped', 'failed'].includes(outboundLabel) || outboundLabel.startsWith('outbound_');
        const outboundClass = isOutboundStatus
          ? (outboundLabel.startsWith('outbound_') ? outboundLabel : 'outbound_' + outboundLabel)
          : outboundLabel;
        const outboundDisplay = outboundLabel.replace('outbound_', '').replace('_', ' ');
        const outboundReason = event.outbound_reason ? ' title="' + event.outbound_reason + '"' : '';
        const outboundBadge = '<span class="pill pill-' + outboundClass + '"' + outboundReason + '>' + outboundDisplay + '</span>';
        const timestamp = resolveEventTimestamp(event);
        row.innerHTML =
          '<div>' +
            '<strong>' + (event.event_name || '—') + '</strong>' +
            '<div class="muted">' + (event.site_name || 'Unknown site') + '</div>' +
            inboundLine +
            sourceLine +
            duplicateLine +
          '</div>' +
          '<div class="muted">' + formatEventTime(timestamp) + '</div>' +
          '<div>' + outboundBadge + '</div>';
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
        const outboundReason = event.outbound_reason || (event.meta_body && event.meta_body.reason ? event.meta_body.reason : null);
        const videoModeLine = event.video_mode ? '<p class="muted">Video mode: <strong>' + event.video_mode + '</strong></p>' : '';
        const outboundStatusLabel = event.outbound_result ? event.outbound_result : (event.status || 'received');
        const isOutboundStatus = ['sent', 'skipped', 'failed'].includes(outboundStatusLabel) || outboundStatusLabel.startsWith('outbound_');
        const outboundStatusClass = isOutboundStatus
          ? (outboundStatusLabel.startsWith('outbound_') ? outboundStatusLabel : 'outbound_' + outboundStatusLabel)
          : outboundStatusLabel;
        const outboundStatusDisplay = outboundStatusLabel.replace('outbound_', '').replace('_', ' ');
        const outboundBadge = '<span class="pill pill-' + outboundStatusClass + '"' +
          (outboundReason ? ' title="' + outboundReason + '"' : '') +
          '>' + outboundStatusDisplay + '</span>';
        const inboundMeta = [
          event.video_id ? 'Video ID: <strong>' + event.video_id + '</strong>' : null,
          event.percent !== null && event.percent !== undefined ? 'Percent: <strong>' + event.percent + '%</strong>' : null,
          event.event_source_url ? 'Source: <span class="truncate" title="' + event.event_source_url + '">' + event.event_source_url + '</span>' : null
        ].filter(Boolean).join(' · ');
        const duplicateSummary = event.duplicate_count > 0
          ? '<p class="muted">Duplicate count: <strong>' + event.duplicate_count + '</strong></p>'
          : '';
        const timestamp = resolveEventTimestamp(event);
        detailEl.innerHTML =
          '<div class="detail-header">' +
            '<div>' +
              '<h2>' + (event.event_name || 'Event detail') + '</h2>' +
              '<p class="muted">' + (event.site_name || 'Unknown site') + ' · ' + (event.pixel_id || 'No pixel') + ' · ' + formatEventDate(timestamp) + '</p>' +
              videoModeLine +
              (inboundMeta ? '<p class="muted">' + inboundMeta + '</p>' : '') +
              duplicateSummary +
            '</div>' +
            '<div class="copy-group">' +
              '<button onclick=\'navigator.clipboard.writeText(' + JSON.stringify(event.event_id || '') + ')\'>Copy event_id</button>' +
            '</div>' +
          '</div>' +
          '<div class="card inline-card">' +
            '<div><strong>Outbound status:</strong> ' + outboundBadge + '</div>' +
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
            renderJsonBlock('Outbound payload', event.outbound_request_json || event.outbound_json) +
            (outboundReason ? '<p class="muted">Outbound reason: ' + outboundReason + '</p>' : '') +
            '<button onclick=\'navigator.clipboard.writeText(' + JSON.stringify(JSON.stringify(event.outbound_request_json || event.outbound_json || {}, null, 2)) + ')\'>Copy outbound</button>' +
          '</div>' +
          '<div class="tab-content hidden" data-content="meta">' +
            renderJsonBlock('Meta response', { status: event.meta_status, body: event.outbound_response_json || event.meta_body }) +
            '<button onclick=\'navigator.clipboard.writeText(' + JSON.stringify(JSON.stringify({ status: event.meta_status, body: event.outbound_response_json || event.meta_body }, null, 2)) + ')\'>Copy response</button>' +
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

      [filterSite, filterType, filterStatus].forEach(el => el.addEventListener('change', loadStream));
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
      if (urlParams.get('event_type')) filterType.value = urlParams.get('event_type');
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
      <p class="muted">${maskedEvent.site_name ?? "Unknown site"} · ${maskedEvent.pixel_id ?? "No pixel"} · ${formatDate(maskedEvent.received_at_utc_ms ?? maskedEvent.received_at ?? maskedEvent.created_at)}</p>
      <p class="muted">Event ID: <code>${maskedEvent.event_id ?? "—"}</code></p>
      ${maskedEvent.video_id ? `<p class="muted">Video ID: <code>${maskedEvent.video_id}</code> · ${maskedEvent.percent ?? "—"}%</p>` : ""}
      ${maskedEvent.video_mode ? `<p class="muted">Video mode: <strong>${maskedEvent.video_mode}</strong></p>` : ""}
      ${maskedEvent.event_source_url ? `<p class="muted">Source: <span class="truncate" title="${maskedEvent.event_source_url}">${maskedEvent.event_source_url}</span></p>` : ""}
      ${maskedEvent.outbound_result ? `<p class="muted">Outbound: <strong>${maskedEvent.outbound_result}</strong>${maskedEvent.outbound_reason ? ` (reason: ${maskedEvent.outbound_reason})` : ""}</p>` : ""}
    </div>
    <div class="card">
      <h2>Inbound payload</h2>
      <pre>${JSON.stringify(maskedEvent.inbound_json ?? {}, null, 2)}</pre>
    </div>
    <div class="card">
      <h2>Outbound payload</h2>
      <pre>${JSON.stringify(maskedEvent.outbound_request_json ?? maskedEvent.outbound_json ?? {}, null, 2)}</pre>
    </div>
    <div class="card">
      <h2>Meta response</h2>
      <pre>${JSON.stringify({ status: maskedEvent.meta_status, body: maskedEvent.outbound_response_json ?? maskedEvent.meta_body }, null, 2)}</pre>
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
        <label>Time zone
          <input name="time_zone" value="${settings.time_zone ?? DEFAULT_TIME_ZONE}" />
          <span class="muted">Use an IANA time zone like America/New_York.</span>
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
  const normalizedTimeZone = normalizeTimeZone(req.body.time_zone) || DEFAULT_TIME_ZONE;
  await setSetting(db, "time_zone", normalizedTimeZone);
  cachedTimeZone = normalizedTimeZone;
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
    videoId: req.query.video_id || undefined,
    eventType: req.query.event_type || undefined
  });
  res.json(events.map(event => maskEventForDisplay(event)));
});

app.get("/admin/events/:eventId", requireAuth, async (req, res) => {
  const event = await getEventById(db, req.params.eventId);
  if (!event) return res.status(404).json({ error: "not found" });
  res.json(maskEventForDisplay(event));
});

app.get("/debug/pipeline", async (req, res) => {
  let dbConnected = false;
  let errorMessage = null;
  try {
    await db.get("SELECT 1");
    dbConnected = true;
  } catch (error) {
    errorMessage = error.toString();
  }

  let latestInbound = null;
  let latestOutbound = null;
  try {
    const inboundRow = await db.get(
      "SELECT received_at_utc_ms, received_at, created_at FROM events ORDER BY id DESC LIMIT 1"
    );
    latestInbound =
      inboundRow?.received_at_utc_ms ?? inboundRow?.received_at ?? inboundRow?.created_at ?? null;
    const outboundRow = await db.get("SELECT attempted_at FROM outbound_logs ORDER BY id DESC LIMIT 1");
    latestOutbound = outboundRow?.attempted_at ?? null;
  } catch (error) {
    errorMessage = errorMessage || error.toString();
  }

  res.json({
    ok: true,
    db_connected: dbConnected,
    latest_inbound_log: latestInbound,
    latest_outbound_log: latestOutbound,
    backlog: null,
    error: errorMessage
  });
});

app.options("/v/track", publicCors);
app.post("/v/track", publicCors, async (req, res) => {
  console.log("[TRACK HIT]", {
    hasSiteKey: Boolean(req.headers["x-site-key"] || req.body?.site_key),
    bodyKeys: Object.keys(req.body || {}),
    video_id: req.body?.video_id ?? null,
    percent: req.body?.percent ?? null
  });
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

  const traceId = crypto.randomUUID();
  const { video_id, percent, event_id, event_source_url, watch_seconds, duration, fbp, fbc, fbclid } = req.body || {};
  if (!video_id || percent === undefined || percent === null) {
    return res.status(400).json({ ok: false, error: "missing required fields" });
  }

  const video = await getVideoBySiteAndVideoId(db, site.site_id, video_id);
  const mode = video ? normalizeVideoMode(video.mode) : "off";
  const percentValue = Number.parseInt(percent, 10);
  const eventName = Number.isFinite(percentValue) ? `Video${percentValue}` : "Video";
  const resolvedSourceUrl = event_source_url || video?.page_url || resolveEventSourceUrl({}, req) || "";
  if (!resolvedSourceUrl) {
    return res.status(400).json({ ok: false, error: "missing event_source_url" });
  }

  const eventId = event_id || uuid();
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
    event_id: eventId,
    action_source: "website",
    event_source_url: resolvedSourceUrl,
    user_data: userData,
    custom_data: {
      video_id,
      percent: percentValue,
      watch_seconds,
      duration,
      page_url: video?.page_url ?? null
    }
  };
  const inboundLogPayload = {
    ...inboundEvent,
    custom_data: {
      ...inboundEvent.custom_data,
      provider: video?.provider ?? null,
      provider_video_id: video?.provider_video_id ?? null
    }
  };
  const origin = resolveOrigin(resolvedSourceUrl);

  let inboundId;
  const receivedAtUtcMs = Date.now();
  const eventTimeClient = Number.parseInt(req.body?.event_time ?? "", 10);
  const eventTimeClientValue = Number.isNaN(eventTimeClient) ? null : eventTimeClient;
  try {
    inboundId = await insertEvent(db, {
      site_id: site.site_id,
      type: "video_milestone",
      event_id: eventId,
      event_name: inboundEvent.event_name,
      video_id,
      percent: percentValue,
      event_source_url: resolvedSourceUrl,
      status: "received",
      inbound_json: JSON.stringify(sanitizePayload(inboundLogPayload, site.log_full_payloads === 1)),
      video_mode: mode,
      user_agent: req.get("user-agent"),
      ip_address: getClientIp(req),
      received_at_utc_ms: receivedAtUtcMs,
      trace_id: traceId,
      event_time_client: eventTimeClientValue
    });
  } catch (error) {
    await insertError(db, { type: "db", site_id: site.site_id, event_id: eventId, message: error.toString() });
    await log({ type: "error", message: "failed to persist inbound event", error: error.toString() });
    return res.status(500).json({ ok: false, error: "failed to persist inbound event" });
  }

  console.log(
    `[TRACK] inbound_id=${inboundId} site=${site.site_key} video=${video_id} event=${eventName} pct=${percentValue} ws=${watch_seconds ?? "—"} trace=${traceId} origin=${origin ?? "—"}`
  );

  await log({
    type: "video_event_inbound",
    site_id: site.site_id,
    video_id,
    percent: percentValue,
    mode,
    inbound_id: inboundId
  });

  const dedupTtlHours = await getSettingNumber("dedup_ttl_hours", 48);
  if (eventId) {
    const seen = await hasRecentEventId(db, site.site_id, eventId, dedupTtlHours);
    if (seen) {
      const duplicateCountRow = await db.get(
        "SELECT COUNT(*) as count FROM events WHERE site_id = ? AND event_id = ?",
        site.site_id,
        eventId
      );
      const duplicateCount = Math.max(0, (duplicateCountRow?.count ?? 1) - 1);
      await markInboundDuplicate(db, inboundId, duplicateCount);
      await insertOutboundLog(db, {
        inbound_id: inboundId,
        mode_used: mode,
        request_payload_json: JSON.stringify({
          data: [sanitizePayload(inboundEvent, site.log_full_payloads === 1)]
        }),
        result: "skipped",
        reason: "deduped"
      });
      await updateInboundOutbound(db, inboundId, { outboundResult: "skipped", outboundReason: "deduped" });
      console.log(
        `[FORWARD] inbound_id=${inboundId} trace=${traceId} ok=false reason=${formatForwardReason("deduped")}`
      );
      await log({
        type: "dedup",
        message: "duplicate video event received",
        site_id: site.site_id,
        meta: { event_id: eventId, event_name: inboundEvent.event_name }
      });
      await log({
        type: "v/track",
        message: `[v/track] trace=${traceId} inbound_id=${inboundId} video=${video_id} percent=${percentValue} saved_at=${receivedAtUtcMs} forward=skipped reason=deduped`
      });
      await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
      return res.json({
        ok: true,
        inbound_id: inboundId,
        trace_id: traceId,
        forwarded: false,
        deduped: true,
        reason: "deduped"
      });
    }
    await storeEventId(db, site.site_id, eventId, dedupTtlHours);
  }

  const outboundPayload = {
    data: [inboundEvent],
    ...(mode === "test" && site.test_event_code ? { test_event_code: site.test_event_code } : {})
  };
  const outboundLogPayload = JSON.stringify({
    ...outboundPayload,
    data: [sanitizePayload(inboundEvent, site.log_full_payloads === 1)]
  });

  const accessToken = resolveAccessToken(site);
  const shouldSendToMeta = site.send_to_meta && !site.dry_run;
  let outboundResult = "skipped";
  let outboundReason = null;
  let forwarded = false;
  let outboundLogged = false;

  if (!video) {
    outboundReason = "video_not_found";
  } else if (!video.enabled) {
    outboundReason = "video_disabled";
  } else if (!shouldSendToMeta) {
    outboundReason = site.dry_run ? "dry_run" : "send_disabled";
  } else if (mode === "off") {
    outboundReason = "video_mode_off";
  } else if (!site.pixel_id || !accessToken) {
    outboundReason = "missing_meta_credentials";
  } else if (mode === "test" && !site.test_event_code) {
    outboundReason = "missing_test_event_code";
  } else if (!hasMinimumUserData(userData)) {
    outboundReason = "insufficient_user_data";
  } else {
    const apiVersion = await getSettingValue("default_meta_api_version", "v24.0");
    const url = `https://graph.facebook.com/${apiVersion}/${site.pixel_id}/events?access_token=${accessToken}`;
    try {
      const retryCount = await getSettingNumber("retry_count", 1);
      const { response, body } = await sendToMeta({ url, payload: outboundPayload, retryCount });
      const status = response.status;
      outboundResult = response.ok ? "sent" : "failed";
      outboundReason = response.ok ? null : status >= 500 ? "meta_5xx" : "meta_4xx";
      forwarded = response.ok;

      await insertOutboundLog(db, {
        inbound_id: inboundId,
        mode_used: mode,
        request_payload_json: outboundLogPayload,
        http_status: status,
        response_body_json: JSON.stringify(body),
        fbtrace_id: body?.fbtrace_id ?? null,
        result: outboundResult,
        reason: outboundReason
      });
      outboundLogged = true;
      await updateInboundOutbound(db, inboundId, { outboundResult, outboundReason });

      if (!response.ok) {
        await insertError(db, {
          type: outboundReason,
          site_id: site.site_id,
          event_db_id: inboundId,
          event_id: eventId,
          message: "Meta API error",
          meta_status: status,
          meta_body: JSON.stringify(body)
        });
      }

      await log({
        type: "video_event_sent",
        site_id: site.site_id,
        video_id,
        percent: percentValue,
        mode,
        meta_status: status,
        meta_response: body
      });
      await logMetaSend({
        site,
        mode,
        testEventCode: mode === "test" ? site.test_event_code : null,
        status,
        responseBody: body
      });
    } catch (err) {
      outboundResult = "failed";
      outboundReason = "exception";
      forwarded = false;
      await insertOutboundLog(db, {
        inbound_id: inboundId,
        mode_used: mode,
        request_payload_json: outboundLogPayload,
        result: outboundResult,
        reason: outboundReason,
        response_body_json: JSON.stringify({ error: err.toString() })
      });
      outboundLogged = true;
      await updateInboundOutbound(db, inboundId, { outboundResult, outboundReason });
      await insertError(db, {
        type: "network",
        site_id: site.site_id,
        event_db_id: inboundId,
        event_id: eventId,
        message: err.toString()
      });
    }
  }

  if (outboundReason && !outboundLogged) {
    await insertOutboundLog(db, {
      inbound_id: inboundId,
      mode_used: mode,
      request_payload_json: outboundLogPayload,
      result: outboundResult,
      reason: outboundReason
    });
    outboundLogged = true;
    await updateInboundOutbound(db, inboundId, { outboundResult, outboundReason });
  }

  await cleanupRetention(db, await getSettingNumber("log_retention_hours", 168));
  console.log(
    `[FORWARD] inbound_id=${inboundId} trace=${traceId} ok=${outboundResult === "sent"} reason=${formatForwardReason(outboundReason)}`
  );
  await log({
    type: "v/track",
    message: `[v/track] trace=${traceId} inbound_id=${inboundId} video=${video_id} percent=${percentValue} saved_at=${receivedAtUtcMs} forward=${outboundResult} reason=${outboundReason || "none"}`
  });
  res.json({
    ok: true,
    inbound_id: inboundId,
    trace_id: traceId,
    forwarded,
    reason: outboundReason
  });
});

app.options("/collect", publicCors);
app.post("/collect", publicCors, async (req, res) => {
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

  const eventTimeClient = Number.parseInt(inboundEvent.event_time ?? "", 10);
  const eventTimeClientValue = Number.isNaN(eventTimeClient) ? null : eventTimeClient;
  const receivedAtUtcMs = Date.now();
  const baseInsertPayload = {
    site_id: site.site_id,
    event_id: eventId,
    event_name: inboundEvent.event_name,
    event_source_url: inboundEvent.event_source_url,
    event_time_client: eventTimeClientValue,
    received_at_utc_ms: receivedAtUtcMs
  };

  const dedupTtlHours = await getSettingNumber("dedup_ttl_hours", 48);

  if (eventId) {
    const seen = await hasRecentEventId(db, site.site_id, eventId, dedupTtlHours);
    if (seen) {
      await insertEvent(db, {
        ...baseInsertPayload,
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
      ...baseInsertPayload,
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
      ...baseInsertPayload,
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
      ...baseInsertPayload,
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
      ...baseInsertPayload,
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
    await logMetaSend({
      site,
      mode: "live",
      testEventCode: site.test_event_code,
      status,
      responseBody: body
    });

    res.status(response.ok ? 200 : status).json({ ok: response.ok, meta: body });
  } catch (err) {
    const eventDbId = await insertEvent(db, {
      ...baseInsertPayload,
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
