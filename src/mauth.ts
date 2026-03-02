// ─── MAuth: Universal Authentication Library ─────────────────────────────────
// Main orchestrator class that ties all modules together

import { APIKey } from "./api-key/api-key";
import { CSRF } from "./csrf/csrf";
import { JWT } from "./jwt/jwt";
import { MagicLink } from "./magic-link/magic-link";
import { createAuthMiddleware, protect } from "./middleware/middleware";
import { OAuthManager } from "./oauth/oauth";
import { Password } from "./password/password";
import { RateLimiter } from "./rate-limit/rate-limit";
import { SessionManager } from "./session/session";
import { TOTP } from "./totp/totp";
import type {
    AuthContext,
    MAuthConfig,
    MiddlewareConfig
} from "./types";
import { MAuthError } from "./types";

/**
 * MAuth - Universal Authentication Library
 *
 * A single entry point for all authentication needs:
 * JWT, passwords, sessions, OAuth, TOTP, CSRF, API keys, magic links, and rate limiting.
 *
 * @example
 * ```ts
 * import { MAuth } from "@mugunth140/mauth";
 *
 * const auth = new MAuth({ secret: "your-secret-key" });
 *
 * // Hash & verify passwords
 * const hash = await auth.password.hash("my-password");
 * const valid = await auth.password.verify("my-password", hash);
 *
 * // Sign & verify JWTs
 * const token = await auth.jwt.sign({ sub: "user-123" });
 * const result = await auth.jwt.verify(token);
 *
 * // Session management
 * const session = await auth.session.create({ userId: "123" });
 * ```
 */
export class MAuth {
  /** JWT token signing & verification */
  public readonly jwt: JWT;

  /** Password hashing & verification */
  public readonly password: Password;

  /** Session management */
  public readonly session: SessionManager;

  /** OAuth 2.0 providers */
  public readonly oauth: OAuthManager;

  /** Time-based One-Time Passwords (2FA) */
  public readonly totp: TOTP;

  /** CSRF token protection */
  public readonly csrf: CSRF;

  /** API key generation & verification */
  public readonly apiKey: APIKey;

  /** Magic link (passwordless) authentication */
  public readonly magicLink: MagicLink;

  /** Rate limiting */
  public readonly rateLimit: RateLimiter;

  /** The shared secret */
  private readonly secret: string;

  constructor(config: MAuthConfig) {
    if (!config.secret) {
      throw new MAuthError("A secret key is required to initialize MAuth", "CONFIGURATION_ERROR", 500);
    }

    this.secret = config.secret;

    // Initialize JWT
    this.jwt = new JWT({
      secret: config.secret,
      ...config.jwt,
    });

    // Initialize Password
    this.password = new Password(config.password);

    // Initialize Session
    this.session = new SessionManager(config.session);

    // Initialize OAuth
    this.oauth = new OAuthManager();

    // Initialize TOTP
    this.totp = new TOTP(config.totp);

    // Initialize CSRF
    this.csrf = new CSRF({
      secret: config.secret,
      ...config.csrf,
    });

    // Initialize API Key
    this.apiKey = new APIKey(config.apiKey);

    // Initialize Magic Link
    this.magicLink = new MagicLink({
      secret: config.secret,
      baseUrl: config.magicLink?.baseUrl ?? "http://localhost:3000",
      ...config.magicLink,
    });

    // Initialize Rate Limiter
    this.rateLimit = new RateLimiter(
      config.rateLimit ?? { max: 100, window: 900 }
    );
  }

  /**
   * Create a JWT-based middleware
   */
  jwtMiddleware(options?: Partial<MiddlewareConfig>) {
    return createAuthMiddleware({
      type: "jwt",
      jwt: { secret: this.secret },
      ...options,
    });
  }

  /**
   * Create a session-based middleware
   */
  sessionMiddleware(options?: Partial<MiddlewareConfig>) {
    return createAuthMiddleware({
      type: "session",
      session: {},
      ...options,
    });
  }

  /**
   * Create a protected route handler
   */
  protect(
    config: MiddlewareConfig,
    handler: (request: Request, auth: AuthContext) => Promise<Response> | Response
  ) {
    return protect(config, handler);
  }
}
