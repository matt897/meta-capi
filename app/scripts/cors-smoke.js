const baseUrl = process.env.BASE_URL ?? "http://localhost:3000";
const origin = process.env.ORIGIN ?? "https://mattyfleisch.com";
const siteKey = process.env.SITE_KEY ?? "";
const videoId = process.env.VIDEO_ID ?? "video_smoke_test";
const eventSourceUrl = process.env.EVENT_SOURCE_URL ?? "https://example.com/video";

if (!siteKey) {
  console.error("Missing SITE_KEY env var.");
  process.exit(1);
}

const optionsResponse = await fetch(`${baseUrl}/v/track`, {
  method: "OPTIONS",
  headers: {
    origin,
    "access-control-request-method": "POST",
    "access-control-request-headers": "content-type, x-site-key"
  }
});

const allowOrigin = optionsResponse.headers.get("access-control-allow-origin");
const allowHeaders = optionsResponse.headers.get("access-control-allow-headers");

if (optionsResponse.status !== 204) {
  console.error("Unexpected OPTIONS status", optionsResponse.status);
  process.exit(1);
}

if (allowOrigin !== origin) {
  console.error("Unexpected allow origin header", allowOrigin);
  process.exit(1);
}

if (!allowHeaders || !allowHeaders.toLowerCase().includes("x-site-key")) {
  console.error("Missing x-site-key in allow headers", allowHeaders);
  process.exit(1);
}

const trackResponse = await fetch(`${baseUrl}/v/track`, {
  method: "POST",
  headers: {
    "content-type": "application/json",
    "x-site-key": siteKey,
    origin
  },
  body: JSON.stringify({
    video_id: videoId,
    percent: 25,
    event_source_url: eventSourceUrl
  })
});

console.log("OPTIONS status", optionsResponse.status);
console.log("OPTIONS allow-origin", allowOrigin);
console.log("OPTIONS allow-headers", allowHeaders);
console.log("POST status", trackResponse.status);
console.log("POST body", await trackResponse.text());
