# Vantrex PayMongo QRPH Integration

This project remains on Supabase. The Cloudflare Worker keeps the original Firebase/Novarise routes and adds separate `/vantrex/...` routes for Vantrex.

## What changed
- Deposit minimum is PHP 500 in the Vantrex UI and Worker.
- Deposit requests create PayMongo QRPH payment intents.
- A deposit is recorded as `pending` in Supabase.
- The QR payment is credited only after a valid PayMongo `payment.paid` webhook, amount/currency verification, and the database's atomic one-time credit function.
- The account screen polls the user's own transaction row and refreshes the profile after confirmation.
- Existing pages and withdrawal flow were left in place.

## 1. Apply the Supabase migration
In Supabase Dashboard → SQL Editor, run the contents of:
`supabase/migrations/20261115000100_paymongo_qrph_deposits.sql`

This adds payment metadata columns and the service-role-only RPC that credits the profile exactly once.

## 2. Deploy the Cloudflare Worker
Use `cloudflare-worker-vantrex.js` as the Worker source. It retains the existing Worker routes and adds:
- `POST /vantrex/create-paymongo-payment`
- `GET /vantrex/recharge-status`
- `POST /vantrex/paymongo-webhook`

Add these Worker secrets/variables in Cloudflare:
- `PAYMONGO_SECRET_KEY` — PayMongo secret key (secret)
- `PAYMONGO_WEBHOOK_SECRET` — webhook signing secret (secret)
- `SUPABASE_URL` — your Supabase project URL
- `SUPABASE_ANON_KEY` — Supabase anon/publishable key
- `SUPABASE_SERVICE_ROLE_KEY` — Supabase service-role key (SECRET; never put this in frontend code or GitHub)

Do not send secret keys in chat and do not put them in `.env` or frontend source.

## 3. Configure the PayMongo webhook
In PayMongo, add a webhook endpoint pointing to:
`https://YOUR-WORKER-NAME.YOUR-SUBDOMAIN.workers.dev/vantrex/paymongo-webhook`

Subscribe to `payment.paid`. If you want failed/expired transaction display later, those events can be added in a follow-up. Copy the webhook signing secret into Cloudflare as `PAYMONGO_WEBHOOK_SECRET`.

## 4. Configure the Vite frontend
Edit `.env` and replace the placeholder `VITE_PAYMENT_WORKER_URL` with your deployed Worker base URL, for example:
`VITE_PAYMENT_WORKER_URL=https://your-worker.your-subdomain.workers.dev`

Keep the existing Supabase URL and anon key as they are for this project. Do not add the service-role key here.

## 5. Build and deploy
Run:
```bash
npm install
npm run typecheck
npm run build
```
Then upload/push the project to GitHub and deploy it using your existing Vercel settings. If you configure environment variables in Vercel instead of committing `.env`, add the same three `VITE_...` variables there and redeploy.

## Important test note
Use PayMongo test credentials and a test webhook first. A QR image being displayed does not mean payment succeeded. The balance should change only after the webhook reaches the Worker and the transaction changes to `completed`. QRPH availability and which wallets can scan it depend on the merchant's PayMongo account and wallet support.
