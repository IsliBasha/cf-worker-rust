# cf-worker-rust

A Cloudflare Worker written in Rust that handles two things you probably don't want to skip: JWT validation and rate limiting. It runs at the edge, compiles to WASM via [workers-rs](https://github.com/cloudflare/workers-rs), and stays out of the way for legitimate requests.

## What it does

Every incoming request goes through this pipeline:

1. **Rate limiting** — checks a per-IP counter in Cloudflare KV. If an IP has exceeded the limit within the current window, it gets a `429`. The window and limit are configurable.
2. **JWT validation** — expects a `Bearer` token in the `Authorization` header. Validates it with either HS256 (shared secret) or RS256 (public key). Invalid or expired tokens get a `401`.
3. **Response** — if both pass, returns `{ "ok": true, "sub": "<subject>" }`.

## Getting started

You'll need Rust, the `wasm32-unknown-unknown` target, `wrangler`, and `worker-build`.

```bash
# Install Rust if you haven't
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add the WASM target
rustup target add wasm32-unknown-unknown

# Install the build tools
cargo install worker-build
npm install -g wrangler
```

Then clone and set up:

```bash
git clone https://github.com/IsliBasha/cf-worker-rust
cd cf-worker-rust

# Copy the example env file and fill in your secret
cp .dev.vars.example .dev.vars
```

## Configuration

**`.dev.vars`** (local only, never commit this):
```
JWT_SECRET=your-hs256-secret-here
RATE_LIMIT_MAX=60
RATE_LIMIT_WINDOW=60
```

For RS256, use `JWT_PUBLIC_KEY` instead of `JWT_SECRET` — paste the PEM with `\n` for newlines.

**`wrangler.toml`** — create a KV namespace and drop the IDs in:
```bash
wrangler kv namespace create RATE_LIMIT
```

Then update the `id` and `preview_id` fields in `wrangler.toml`.

## Running locally

```bash
wrangler dev
```

Test it with a valid JWT:
```bash
curl -H "Authorization: Bearer <your-token>" http://localhost:8787
```

## Tests

```bash
cargo test
```

Four unit tests covering the JWT module: valid token, wrong secret, missing key, and malformed token.

## Deploying

```bash
wrangler deploy
```

For production secrets, use `wrangler secret put JWT_SECRET` instead of `.dev.vars`.

CI/CD is wired up in `.github/workflows/ci.yml` — tests and a release build run on every push, and it deploys to Cloudflare automatically on pushes to `main` if you add a `CLOUDFLARE_API_TOKEN` secret to the repo.

## Stack

- [workers-rs](https://github.com/cloudflare/workers-rs) — Rust bindings for the Workers runtime
- [jsonwebtoken](https://github.com/Keats/jsonwebtoken) — JWT decode and validation
- Cloudflare KV — rate limit counters
