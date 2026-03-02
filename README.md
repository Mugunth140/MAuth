# MAuth

**Universal authentication library for modern JavaScript runtimes.**

Zero dependencies. TypeScript-first. Works everywhere — Node.js, Bun, Deno, Cloudflare Workers, Vercel Edge.

Built on **Web Crypto API** for maximum cross-runtime compatibility.

## Features

| Module | Description |
|---|---|
| **JWT** | Sign, verify, decode tokens with HS256/384/512. Token pair (access + refresh) management. |
| **Password** | PBKDF2 password hashing with PHC-formatted output. Constant-time verification. |
| **Session** | Cookie-based sessions with pluggable stores. Rolling sessions. Web Standard Request support. |
| **OAuth** | Google, GitHub, Discord, Microsoft, Apple, Twitter/X + custom providers. |
| **TOTP** | RFC 6238 time-based one-time passwords for 2FA. QR code URI generation. |
| **API Key** | Secure key generation with prefix, SHA-256 hashing for storage. |
| **Magic Link** | HMAC-signed email tokens for passwordless authentication. |
| **CSRF** | Double-submit cookie pattern with HMAC tokens. |
| **Rate Limit** | Sliding window rate limiter with customizable stores. |
| **Middleware** | Framework-agnostic auth middleware using Web Standard Request/Response. |

## Install

```bash
# npm
npm install mauth-js

# bun
bun add mauth-js

# deno
deno add npm:mauth-js

# pnpm / yarn
pnpm add mauth-js
yarn add mauth-js
```

## Quick Start

```typescript
import { MAuth } from "mauth-js";

const auth = new MAuth({
  secret: process.env.AUTH_SECRET!,
});

// ─── Password Hashing ────────────────────────────────────────────────
const hash = await auth.password.hash("super-secret-password");
const valid = await auth.password.verify("super-secret-password", hash);
// valid === true

// ─── JWT ──────────────────────────────────────────────────────────────
const token = await auth.jwt.sign({ sub: "user-123", role: "admin" });
const { payload } = await auth.jwt.verify(token);
// payload.sub === "user-123"

// ─── Sessions ─────────────────────────────────────────────────────────
const session = await auth.session.create({ userId: "user-123" });
const retrieved = await auth.session.get(session.id);

// ─── TOTP (2FA) ──────────────────────────────────────────────────────
const secret = auth.totp.generateSecret("user@example.com");
// secret.uri → otpauth://totp/... (for QR code)
const code = await auth.totp.generate(secret.base32);
const isValid = await auth.totp.verify(code, secret.base32);
```

## Modular Imports

Import only what you need for smaller bundles:

```typescript
import { JWT } from "mauth-js/jwt";
import { Password } from "mauth-js/password";
import { SessionManager } from "mauth-js/session";
import { TOTP } from "mauth-js/totp";
import { CSRF } from "mauth-js/csrf";
import { APIKey } from "mauth-js/api-key";
import { MagicLink } from "mauth-js/magic-link";
import { RateLimiter } from "mauth-js/rate-limit";
import { OAuthManager } from "mauth-js/oauth";
import { createAuthMiddleware } from "mauth-js/middleware";
```

---

## JWT

```typescript
import { JWT } from "mauth-js/jwt";

const jwt = new JWT({
  secret: "your-secret-key",
  algorithm: "HS256",       // HS256 | HS384 | HS512
  expiresIn: "1h",          // Duration string or seconds
  issuer: "my-app",
  audience: "my-api",
});

// Sign
const token = await jwt.sign({
  sub: "user-123",
  role: "admin",
  customClaim: "hello",
});

// Verify
const { payload, header } = await jwt.verify(token);

// Decode without verification (e.g., for expired tokens)
const decoded = jwt.decode(token);
```

### Access + Refresh Token Pairs

```typescript
import { JWTTokenPairManager } from "mauth-js/jwt";

const tokens = new JWTTokenPairManager({
  access: { secret: "secret", expiresIn: "15m" },
  refresh: { secret: "secret", expiresIn: "7d" },
});

// Generate pair
const { accessToken, refreshToken } = await tokens.generate({ sub: "user-123" });

// Verify access token
const result = await tokens.verifyAccess(accessToken);

// Refresh: verify refresh token, get new pair
const newTokens = await tokens.refresh(refreshToken);
```

---

## Password Hashing

```typescript
import { Password } from "mauth-js/password";

const password = new Password({
  algorithm: "pbkdf2",   // Uses Web Crypto PBKDF2
  iterations: 310000,    // OWASP recommended
  keyLength: 32,
});

// Hash (returns PHC-formatted string)
const hash = await password.hash("user-password");
// $pbkdf2-sha256$i=310000,l=32$<salt>$<hash>

// Verify
const valid = await password.verify("user-password", hash);

// Check if rehashing needed (after config change)
if (password.needsRehash(hash)) {
  const newHash = await password.hash("user-password");
}
```

---

## Sessions

```typescript
import { SessionManager, MemoryStore } from "mauth-js/session";

const sessions = new SessionManager({
  maxAge: 86400,          // 24 hours
  rolling: true,          // Renew on access
  cookieName: "sid",
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  },
});

// Create
const session = await sessions.create({ userId: "123", role: "admin" });

// Get (auto-renews if rolling)
const s = await sessions.get(session.id);

// Update
await sessions.update(session.id, { role: "superadmin" });

// Destroy
await sessions.destroy(session.id);

// Cookie helpers
const setCookie = sessions.getSetCookieHeader(session.id);
const sessionId = sessions.getSessionIdFromCookie(request.headers.get("cookie"));
```

### Custom Session Store

```typescript
import type { SessionStore, Session } from "mauth-js/session";

class RedisStore implements SessionStore {
  async get(id: string): Promise<Session | null> { /* redis.get */ }
  async set(id: string, session: Session): Promise<void> { /* redis.set */ }
  async destroy(id: string): Promise<void> { /* redis.del */ }
  async touch(id: string, expiresAt: number): Promise<void> { /* redis.expire */ }
}

const sessions = new SessionManager({ store: new RedisStore() });
```

---

## OAuth 2.0

```typescript
import { OAuthManager } from "mauth-js/oauth";

const oauth = new OAuthManager();

// Register providers
oauth
  .google({
    clientId: process.env.GOOGLE_CLIENT_ID!,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    redirectUri: "http://localhost:3000/auth/google/callback",
  })
  .github({
    clientId: process.env.GITHUB_CLIENT_ID!,
    clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    redirectUri: "http://localhost:3000/auth/github/callback",
  })
  .discord({ /* ... */ });

// Step 1: Redirect user to provider
const authUrl = oauth.getAuthUrl("google", "random-state");
// → redirect user to authUrl

// Step 2: Handle callback
const { tokens, user } = await oauth.handleCallback("google", code);
// user = { id, email, name, avatar, provider, raw }
```

### Supported Providers

- **Google** — OpenID Connect
- **GitHub** — Fetches primary email automatically
- **Discord** — Includes avatar CDN URL
- **Microsoft** — Microsoft Graph API
- **Apple** — Sign in with Apple (form_post)
- **Twitter/X** — OAuth 2.0 PKCE
- **Custom** — Any OAuth 2.0 provider

```typescript
oauth.custom("gitlab", {
  clientId: "...",
  clientSecret: "...",
  redirectUri: "...",
  authorizationUrl: "https://gitlab.com/oauth/authorize",
  tokenUrl: "https://gitlab.com/oauth/token",
  userInfoUrl: "https://gitlab.com/api/v4/user",
});
```

---

## TOTP (2FA)

```typescript
import { TOTP } from "mauth-js/totp";

const totp = new TOTP({
  issuer: "MyApp",
  digits: 6,
  period: 30,
  algorithm: "SHA-1",
  window: 1,            // ±1 time step tolerance
});

// Generate secret (show QR code from uri)
const secret = totp.generateSecret("user@example.com");
// secret.base32 → "JBSWY3DPEHPK3PXP..."
// secret.uri    → "otpauth://totp/MyApp:user@example.com?secret=..."

// Generate current code
const code = await totp.generate(secret.base32);

// Verify user-submitted code
const valid = await totp.verify(userCode, secret.base32);
```

---

## API Keys

```typescript
import { APIKey } from "mauth-js/api-key";

const apiKey = new APIKey({
  prefix: "mk",         // Key prefix: mk_a1b2c3d4...
  keyLength: 32,
});

// Generate (show `key` to user once, store `hash` in DB)
const { key, hash, prefix } = await apiKey.generate();
// key    → "mk_7f3a9b2c..."
// hash   → "sha256-hash-for-storage"
// prefix → "mk_7f3a9b2c..." (truncated for display)

// Verify
const valid = await apiKey.verify(userProvidedKey, storedHash);

// Hash a key for lookup
const keyHash = await apiKey.hashKey(userProvidedKey);
```

---

## Magic Links

```typescript
import { MagicLink } from "mauth-js/magic-link";

const magicLink = new MagicLink({
  secret: "your-secret",
  baseUrl: "https://myapp.com",
  callbackPath: "/auth/verify",
  expiresIn: 600,       // 10 minutes
});

// Generate
const { token, url, expiresAt } = await magicLink.generate("user@example.com");
// Send `url` via email

// Verify (when user clicks the link)
const { valid, email, metadata } = await magicLink.verify(token);
```

---

## CSRF Protection

```typescript
import { CSRF } from "mauth-js/csrf";

const csrf = new CSRF({
  secret: "your-secret",
  expiresIn: 3600,      // 1 hour
});

// Generate token (include in form/header)
const token = await csrf.generate();

// Verify token
const valid = await csrf.verify(token);

// Double-submit cookie pattern
const { cookie, header } = await csrf.createDoubleSubmit();
```

---

## Rate Limiting

```typescript
import { RateLimiter } from "mauth-js/rate-limit";

const limiter = new RateLimiter({
  max: 100,             // 100 requests
  window: 900,          // per 15 minutes
});

// Check
const result = await limiter.check("user-ip-or-id");
// { allowed: true, remaining: 99, limit: 100, resetAt: 1234567890 }

// Or throw on limit exceeded
await limiter.limit("user-ip");  // throws MAuthError with code RATE_LIMITED

// Get headers for response
const headers = limiter.getHeaders(result);
// X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset
```

---

## Middleware

Framework-agnostic middleware using Web Standard `Request`/`Response`:

```typescript
import { createAuthMiddleware, protect } from "mauth-js/middleware";

// JWT middleware
const jwtAuth = createAuthMiddleware({
  type: "jwt",
  jwt: { secret: "your-secret" },
  onError: (error) =>
    new Response(JSON.stringify({ error: error.message }), { status: 401 }),
});

// Use with any framework
async function handler(request: Request) {
  const { auth, response } = await jwtAuth(request);
  if (response) return response;  // Auth failed
  // auth.userId, auth.payload available
  return new Response(`Hello ${auth.userId}`);
}

// Protect shorthand
const protectedHandler = protect(
  { type: "jwt", jwt: { secret: "your-secret" } },
  async (request, auth) => {
    return new Response(`Authenticated as ${auth.userId}`);
  }
);
```

### Multi-auth

```typescript
import { createMultiAuthMiddleware } from "mauth-js/middleware";

const auth = createMultiAuthMiddleware([
  { type: "jwt", jwt: { secret: "secret" } },
  { type: "api-key", apiKey: { verify: async (key) => key === "valid-key" } },
]);
```

---

## Framework Integration Examples

### Hono

```typescript
import { Hono } from "hono";
import { MAuth } from "mauth-js";

const auth = new MAuth({ secret: process.env.AUTH_SECRET! });
const app = new Hono();

app.post("/auth/login", async (c) => {
  const { email, password } = await c.req.json();
  // ... verify user credentials
  const token = await auth.jwt.sign({ sub: userId, email });
  return c.json({ token });
});

app.get("/protected", async (c) => {
  const authHeader = c.req.header("authorization");
  if (!authHeader?.startsWith("Bearer ")) return c.json({ error: "Unauthorized" }, 401);
  const { payload } = await auth.jwt.verify(authHeader.slice(7));
  return c.json({ user: payload.sub });
});
```

### Express

```typescript
import express from "express";
import { MAuth } from "mauth-js";

const auth = new MAuth({ secret: process.env.AUTH_SECRET! });
const app = express();

app.post("/login", async (req, res) => {
  const valid = await auth.password.verify(req.body.password, storedHash);
  if (!valid) return res.status(401).json({ error: "Invalid credentials" });
  const token = await auth.jwt.sign({ sub: userId });
  res.json({ token });
});
```

### Bun

```typescript
import { MAuth } from "mauth-js";

const auth = new MAuth({ secret: Bun.env.AUTH_SECRET! });

Bun.serve({
  async fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/api/protected") {
      const authHeader = request.headers.get("authorization");
      if (!authHeader) return new Response("Unauthorized", { status: 401 });
      const { payload } = await auth.jwt.verify(authHeader.slice(7));
      return Response.json({ user: payload.sub });
    }

    return new Response("Not found", { status: 404 });
  },
});
```

### Deno

```typescript
import { MAuth } from "npm:mauth-js";

const auth = new MAuth({ secret: Deno.env.get("AUTH_SECRET")! });

Deno.serve(async (request) => {
  const token = await auth.jwt.sign({ sub: "user-123" });
  return new Response(JSON.stringify({ token }));
});
```

---

## Crypto Utilities

Low-level crypto helpers are also exported for advanced use:

```typescript
import {
  randomBytes, randomString, uuid,
  toBase64, fromBase64, toBase64Url, fromBase64Url,
  toHex, fromHex, toBase32, fromBase32,
  hmacSign, hmacVerify,
  hash, hashHex,
  pbkdf2,
  timingSafeEqual,
  parseDuration, now,
} from "mauth-js";
```

---

## Runtime Support

| Runtime | Version | Status |
|---|---|---|
| Node.js | >= 18 | ✅ Full support |
| Bun | >= 1.0 | ✅ Full support |
| Deno | >= 1.0 | ✅ Full support |
| Cloudflare Workers | — | ✅ Full support |
| Vercel Edge | — | ✅ Full support |

All cryptographic operations use the **Web Crypto API** (`crypto.subtle`), which is available in all modern runtimes.

## Zero Dependencies

MAuth has **zero runtime dependencies**. The only dev dependencies are TypeScript and the bundler.

## License

MIT
