# Meta CAPI Gateway v2

A Dockerized, SQLite-backed Meta Conversions API gateway with a server-rendered dashboard for live ad testing.

## Quick start

```bash
docker compose up --build
```

Open `http://localhost:3000/login` and sign in with the admin password (default `admin123` from `docker-compose.yml`).

## Add a site

1. Go to **Sites** → **Create site**.
2. Enter your site name, Meta Pixel ID, access token, and optional test event code.
3. Copy the generated **Site Key** and use it in the `x-site-key` header when sending events.

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

## Verify in Meta Test Events

1. Add a **Test Event Code** on the site settings page.
2. Send a test event as above.
3. Visit Meta **Events Manager → Test Events** to confirm the event appears.

## Deduplication behavior

- If you send an `event_id`, the gateway stores it for the configured TTL (default 48 hours).
- If you omit `event_id` but include `event_name`, `event_time`, and at least one of `user_data.em`, `user_data.ph`, or `user_data.external_id`, the gateway generates a deterministic event ID.
- Duplicate event IDs within the TTL are marked as **deduped** and not forwarded to Meta.

## Dashboard highlights

- **Dashboard**: status, 24h events/errors, dedup rate, and recent activity.
- **Sites**: per-site cards with events/errors today, rotate site keys, and debug toggles.
- **Live Events**: auto-refreshing stream with event details and payload tabs.
- **Errors**: grouped by type with suggested resolutions.
- **Settings**: runtime config (Meta API version, retries, dedup TTL, log retention, HMAC, rate limits).

## Docker notes

- The SQLite database is persisted via the `meta-capi-data` volume defined in `docker-compose.yml`.
- Settings are stored in SQLite and apply immediately without restarting the container.
