# Meta CAPI Gateway v2

A Dockerized, SQLite-backed Meta Conversions API gateway with a server-rendered dashboard for live ad testing.

## Quick start

```bash
docker compose up --build
```

Open `http://localhost:3000/` for the lightweight status page, or visit
`http://localhost:3000/login` and sign in with the admin password (default `admin123` from
`docker-compose.yml`).

> **Security note:** If `ADMIN_PASSWORD` is not set, the gateway falls back to `admin123` and
> shows a warning banner in the dashboard until you change it in **Settings**.

## Add a site

1. Go to **Sites** → **Create site**.
2. Enter a site name. Credentials are optional until you’re ready to forward events.
3. Copy the generated **Site Key** and use it in the `x-site-key` header when sending events.

**Site status**

- **Not Configured**: missing Pixel ID or access token.
- **Dry Run**: credentials exist but send-to-Meta is off or dry-run mode is enabled.
- **Ready**: Pixel ID + access token are set and send-to-Meta is enabled.

## Send a test event

```bash
curl -X POST http://localhost:3000/collect \
  -H 'content-type: application/json' \
  -H 'x-site-key: <site_key>' \
  -d '{
    "event_name": "Purchase",
    "event_time": 1717000000,
    "event_id": "order-123",
    "user_data": {
      "em": "hashed_email",
      "ph": "hashed_phone",
      "external_id": "user-42"
    }
  }'
```

## Track HTML5 video milestones

1. Go to **Videos** → **Add Video**.
2. Select a site and paste the **Page URL** (the page where the video is embedded).
3. Optionally add the **Video Source URL** (the actual video file or provider URL like Vimeo/YouTube).
4. Optionally set a CSS selector (defaults to `video`).
5. Save to generate a copy-paste snippet.
6. Paste the snippet on the page containing the `<video>` element.

The snippet loads a first-party SDK at `/sdk/video-tracker.js`. The SDK:

- Fetches `/sdk/config` on load to confirm the video is enabled.
- Tracks watched time (anti-scrub) and fires `Video25`, `Video50`, `Video75`, `Video95` milestones.
- Sends events to `/v/track` with `video_id`, `percent`, and playback metrics.
  - If a video is disabled or unknown, `/v/track` responds with `{ ok: false, reason: "video_disabled" }`.

### Revocation

Toggle **Enabled** off for a video in the dashboard to immediately stop tracking. The SDK checks
`/sdk/config` on load and will stop sending events for disabled videos without any code changes.

### Meta audiences

Video events are forwarded as custom events (e.g., `Video25`) with `custom_data.video_id`. Use
those fields in Meta **Events Manager → Custom Audiences** to build retargeting segments.

### Page URL vs. Video Source URL

- **Page URL** is required and identifies where the video is embedded (used for event source URL and debugging).
- **Video Source URL** is optional metadata that identifies the actual video asset (mp4, Vimeo, YouTube, Mux, etc.) for future organization and storage management.

## Minimum user_data for Meta matching

Meta requires customer info parameters for matching. The gateway now enforces a minimum of:

- `user_data.client_ip_address`
- `user_data.client_user_agent`

Recommended extras include `_fbp`/`_fbc` cookies or hashed identifiers (`user_data.em`, `user_data.ph`, `user_data.external_id`). The `/collect` endpoint enriches missing IP/UA from request headers and will skip forwarding if they are still unavailable.

## Verify in Meta Test Events

1. Add a **Test Event Code** on the site settings page.
2. Enable **Send to Meta** and disable dry-run mode.
3. Use the **Send Test Event** button or send a test event as above.
4. Visit Meta **Events Manager → Test Events** to confirm the event appears.

## Deduplication behavior

- If you send an `event_id`, the gateway stores it for the configured TTL (default 48 hours).
- If you omit `event_id` but include `event_name`, `event_time`, and at least one of `user_data.em`, `user_data.ph`, or `user_data.external_id`, the gateway generates a deterministic event ID.
- Duplicate event IDs within the TTL are marked as **deduped** and not forwarded to Meta.

## Dashboard highlights

- **Dashboard**: status, 24h events/errors, dedup rate, and recent activity.
- **Sites**: per-site cards with status chips, test event action, and credentials editor (masked by default).
- **Videos**: register HTML5 videos, copy snippets, and revoke tracking instantly.
- **Live Events**: auto-refreshing stream with inbound/outbound status, skipped reasons, and payload tabs.
- **Errors**: grouped by type with suggested resolutions.
- **Settings**: runtime config (Meta API version, retries, dedup TTL, log retention, HMAC, rate limits).

## Homepage + admin APIs

Previously the container returned `Cannot GET /` because no homepage route or static files were
served at `/`. The gateway now ships a minimal developer homepage at `/` plus login-gated admin
pages and JSON endpoints (`/dashboard/*`, `/admin/*`).

## Configuration

Required environment variables:

- `ADMIN_PASSWORD`: Admin login password (required for production use).
- `PUBLIC_BASE_URL`: Public base URL used in generated snippets (e.g. `https://capi.mattmakesmoney.com`).

Recommended / optional:

- `SESSION_SECRET`: Session signing secret (defaults to `meta-capi-session`).
- `APP_ENCRYPTION_KEY`: Optional AES-256-GCM key for encrypting access tokens at rest.
  - Provide a 64-character hex string or base64-encoded 32-byte key.
- `COOKIE_SECURE`: Set to `true` to force secure cookies (auto-enabled when `PUBLIC_BASE_URL` is HTTPS).
- `DB_PATH`: SQLite database path (defaults to `./data/meta-capi.sqlite`).
- `RATE_LIMIT_PER_MIN`: Per-site-key + IP rate limit for public ingest endpoints (defaults to `60`).

## Reverse proxy deployment

When running behind Nginx/Traefik/Cloudflare:

- Ensure `X-Forwarded-Proto` and `X-Forwarded-For` are forwarded so the app can derive the correct
  `https` scheme and client IPs (the app sets `trust proxy` to `true`).
- Set `PUBLIC_BASE_URL=https://capi.mattmakesmoney.com` so snippets always reference the public
  domain.
- Terminate TLS at the proxy and set `COOKIE_SECURE=true` (or rely on HTTPS `PUBLIC_BASE_URL`).

## Docker notes

- The SQLite database is persisted via the `meta-capi-data` volume defined in `docker-compose.yml`.
- Settings are stored in SQLite and apply immediately without restarting the container.

## Dry run & forwarding behavior

- `/collect` always accepts inbound events for valid site keys and logs them.
- If a site is **Not Configured** or **Dry Run**, events are logged as `outbound_skipped` and not forwarded.
- If a site is **Ready** and send-to-Meta is enabled, events are forwarded to Meta and responses are logged.
