# wedplan Server

Express + MongoDB + Stripe API for the VowVista wedding planning platform.

## Quick start

```bash
npm install
cp .env.example .env
npm run dev
```

Health check: `GET http://localhost:5000/` → `{ "ok": true, ... }`.

Requires Node 18+ and a reachable MongoDB Atlas cluster.

## Environment

| Variable | Purpose |
| --- | --- |
| `PORT` | API port, default `5000` |
| `MONGODB_URI` | MongoDB connection string |
| `DB_NAME` / `MONGODB_DB_NAME` | Database name; must match the client (`wedplan`). `DB_NAME` wins |
| `BETTER_AUTH_SECRET`, `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET` | Auth configuration |
| `STRIPE_SECRET_KEY` | Stripe API key |
| `STRIPE_WEBHOOK_SECRET` | Webhook signing secret (`whsec_...`) for `POST /payments/webhook` |
| `IMGBB_KEY` | Image upload key |
| `CLIENT_URL` | Comma-separated allowed CORS origins |

Replace all placeholder/example values in `.env` with real ones. The server logs
`Connected to MongoDB (db: ...)` and `Stripe webhook secret configured: true` on a good start.

## Auth

Protected routes require `Authorization: Bearer <token>` from a Better Auth session.
Roles: `vendor`, `customer`, `admin`. Admin-only routes reject other roles with `403`.

## Endpoints

| Method | Path | Access | Description |
| --- | --- | --- | --- |
| GET | `/` | public | Health check |
| GET | `/services` | public | Approved, active services |
| GET | `/services/vendor` | vendor | Caller's services |
| GET | `/services/:id` | public | Service by id |
| POST | `/services` | vendor | Create service |
| PATCH | `/services/:id` | vendor | Update own service |
| DELETE | `/services/:id` | admin | Delete service |
| PATCH | `/services/:id/status` | admin | Approve / reject |
| POST | `/bookings` | customer | Create booking |
| GET | `/bookings/customer` | customer | Customer bookings |
| GET | `/bookings/vendor` | vendor | Vendor bookings |
| PATCH | `/bookings/:id/status` | vendor | Accept / reject |
| PATCH | `/bookings/:id/cancel` | customer | Cancel booking |
| GET | `/admin/stats` | admin | Dashboard counters |
| GET | `/admin/users` | admin | Users (`?search=`, `?role=`) |
| PATCH | `/admin/users/:id/block` | admin | Toggle block |
| GET | `/admin/services` | admin | All services |
| GET | `/admin/transactions` | admin | All payment transactions |
| POST | `/payments/create-checkout-session` | vendor | Creates Stripe Checkout session; stores `metadata.vendorId` |
| POST | `/payments/webhook` | Stripe | Raw body + signature verified webhook |
| POST | `/payments/verify-session` | vendor / admin | Verified fallback fulfillment |

Transactions are immutable: mutating `/admin/transactions/:id` returns `405`.

## Payments

`create-checkout-session` → Stripe Checkout → `checkout.session.completed` webhook →
`fulfillSubscriptionSession`.

Fulfillment is idempotent:

- `paymentFulfillments` claims one entry per Stripe session ID.
- `transactions` has a unique sparse index on `stripeSessionId`.
- Retries, webhook redelivery and the fallback endpoint cannot create duplicate
  transactions or re-extend premium; failed fulfillment releases its claim.
- Premium = `subscriptionPlan: "premium"` plus `subscriptionExpiresAt` (30 days per paid
  session, never shortened). Transactions are stored even if the vendor user is gone
  (`vendorFound: false` on the response).

### Local webhook setup

```bash
stripe listen --forward-to localhost:5000/payments/webhook
```

Copy the printed `whsec_...` into `STRIPE_WEBHOOK_SECRET`, restart the server, then pay
with test card `4242 4242 4242 4242`. Expect a log line
`checkout.session.completed fulfillment: { ok: true, ... }`.

If a checkouts succeeds but no transaction appears, the API was almost certainly down or
the webhook was not forwarded. Start `npm run dev` **and** `stripe listen` in separate
terminals, then recover missed sessions:

```powershell
$env:BACKFILL_PAYMENTS="1"; node index.js
```

This lists paid Stripe sessions and replays them idempotently; it closes MongoDB and exits
afterwards. For a single session, use the fallback endpoint:

```bash
curl -X POST http://localhost:5000/payments/verify-session \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"sessionId":"cs_test_..."}'
```

It verifies ownership against `metadata.vendorId`, retrieves the session from Stripe,
inserts the transaction and sets premium. Repeating returns `duplicate: true`.

## Verification

```bash
node --check index.js
```

With Mongo shell or a MongoDB client, confirm `wedplan.transactions`,
`wedplan.paymentFulfillments` and `wedplan.user` (premium fields) after a test payment.
Admin UI: `GET /admin/transactions` with an admin Bearer token.
