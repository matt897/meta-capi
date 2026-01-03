# Meta CAPI Gateway v2

## Setup

1. Copy env example:

```bash
cp .env.example .env
```

2. Start the service:

```bash
docker compose up --build
```

The app runs at `http://localhost:3000`.

## Dashboard

Visit `http://localhost:3000/login` and enter the admin password. From there you can:

- Create and manage sites (site key, pixel ID, access token, test event code).
- View the event console with polling logs.
- Update global settings (HMAC, rate limit, log retention).

## Add a site

1. Open **Sites**.
2. Use **Create site** to add your Meta Pixel ID, access token, and optional test event code.
3. Copy the generated **site key** for client requests.

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

To confirm in Meta, provide the **test_event_code** in the site configuration and watch the event appear in the Meta Test Events tool.

## Deduplication

- If you send an `event_id`, the gateway forwards it and stores it for 48 hours to suppress duplicates.
- If you omit `event_id` **and** include `event_name`, `event_time`, plus at least one of `user_data.em`, `user_data.ph`, or `user_data.external_id`, the gateway generates a deterministic event ID from those values.
- If those inputs are missing, no event ID is generated and deduplication is skipped.

## Optional HMAC signature

Set `HMAC_REQUIRED=true` and `HMAC_SECRET` in Settings (or `.env`) to enforce HMAC signatures.

Compute the signature:

```bash
payload='{"event_name":"Purchase","event_time":1717000000}'
signature=$(printf '%s' "$payload" | openssl dgst -sha256 -hmac "$HMAC_SECRET" | awk '{print $2}')

curl -X POST http://localhost:3000/collect \
  -H 'content-type: application/json' \
  -H "x-site-key: <site_key>" \
  -H "x-signature: $signature" \
  -d "$payload"
```

## Logs

The event console shows structured JSON logs, including Meta response status/body.

## API endpoints

- `POST /collect` – ingest events (requires `x-site-key`, optional `x-signature`).
- `GET /admin/logs` – JSON logs (session auth).
- `GET /admin/sites` – JSON site list (session auth).
