import express from "express";
import { v4 as uuid } from "uuid";

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "admin";

// In-memory store (v1)
const sites = {};
const logs = [];

function log(entry) {
  logs.unshift({ time: new Date().toISOString(), ...entry });
  if (logs.length > 100) logs.pop();
  console.log(entry);
}

// Admin auth (very simple v1)
function adminAuth(req, res, next) {
  if (req.headers["x-admin-password"] !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: "unauthorized" });
  }
  next();
}

app.get("/health", (req, res) => res.json({ ok: true }));

// Admin: add site
app.post("/admin/sites", adminAuth, (req, res) => {
  const { name, pixel_id, access_token, test_event_code } = req.body;
  const site_id = uuid();
  const site_key = uuid();

  sites[site_id] = {
    site_id,
    site_key,
    name,
    pixel_id,
    access_token,
    test_event_code
  };

  log({ type: "admin", message: "site created", site_id });
  res.json({ site_id, site_key });
});

// Admin: list sites
app.get("/admin/sites", adminAuth, (req, res) => {
  res.json(Object.values(sites).map(s => ({
    site_id: s.site_id,
    name: s.name,
    pixel_id: s.pixel_id
  })));
});

// Admin: logs
app.get("/admin/logs", adminAuth, (req, res) => {
  res.json(logs);
});

// Public ingest
app.post("/collect", async (req, res) => {
  const siteKey = req.headers["x-site-key"];
  const site = Object.values(sites).find(s => s.site_key === siteKey);

  if (!site) {
    log({ type: "error", message: "invalid site key" });
    return res.status(401).json({ error: "invalid site key" });
  }

  const payload = {
    data: [req.body],
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

    log({
      type: "event",
      site: site.name,
      event: req.body.event_name,
      status: response.status,
      meta: result
    });

    res.json({ ok: true, meta: result });
  } catch (err) {
    log({ type: "error", error: err.toString() });
    res.status(500).json({ error: "failed to send to meta" });
  }
});

app.listen(PORT, () => {
  console.log(`Meta CAPI Gateway running on :${PORT}`);
});