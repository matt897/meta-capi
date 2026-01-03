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
- **Live Events**: auto-refreshing stream with inbound/outbound status, skipped reasons, and payload tabs.
- **Errors**: grouped by type with suggested resolutions.
- **Settings**: runtime config (Meta API version, retries, dedup TTL, log retention, HMAC, rate limits).

## Homepage + admin APIs

Previously the container returned `Cannot GET /` because no homepage route or static files were
served at `/`. The gateway now ships a minimal developer homepage at `/` plus a header-authenticated
admin page at `/admin` with supporting JSON endpoints (`/admin/sites`, `/admin/logs`, `/health`).

## Docker notes

- The SQLite database is persisted via the `meta-capi-data` volume defined in `docker-compose.yml`.
- Settings are stored in SQLite and apply immediately without restarting the container.

## Dry run & forwarding behavior

- `/collect` always accepts inbound events for valid site keys and logs them.
- If a site is **Not Configured** or **Dry Run**, events are logged as `outbound_skipped` and not forwarded.
- If a site is **Ready** and send-to-Meta is enabled, events are forwarded to Meta and responses are logged.
