# Crash (play money) on Cloudflare Workers + D1

## Setup
1. `npm i -g wrangler && wrangler login`
2. `wrangler d1 create crash-db` → paste the `database_id` into `wrangler.toml`
3. `wrangler d1 execute crash-db --remote --file=schema.sql`
4. Google Cloud Console → APIs & Services → Credentials → OAuth client ID (Web application).
   Add your Worker URL (e.g. `https://crash-play.<you>.workers.dev`) and any custom domain
   to **Authorized JavaScript origins**. Put the client ID in `wrangler.toml` (`GOOGLE_CLIENT_ID`).
   For local testing also add `http://localhost:8787`.
5. `wrangler deploy`

## How fairness works
Each round, the server picks a random `seed` and publishes `sha256(seed)` *before* betting opens.
`crash = max(1.00, floor(99/(1-r))/100)`, where `r = first 13 hex chars of HMAC-SHA256(key=seed, msg=roundId) / 2^52`
(~1% house edge). After the crash, the seed is revealed; anyone can recompute both the hash and crash point
(shown in the "Recent rounds" list). The seed is never sent to clients before the crash.

## Security notes
- Google ID token is verified server-side (RS256 signature, audience, issuer, expiry).
- Session: random 256-bit token, only its SHA-256 stored in D1; `__Host-` HttpOnly Secure SameSite=Lax cookie.
- All state-changing endpoints check the `Origin` header (CSRF); strict nonce-based CSP.
- Balances are changed only via atomic D1 batches; bets/cashouts/payouts are idempotent.
- Add a Cloudflare WAF rate-limiting rule on `/api/*` (e.g. 20 req/10s per IP) before going public.
