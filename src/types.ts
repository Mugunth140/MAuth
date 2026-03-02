// ─── Core Types ───────────────────────────────────────────────────────────────

/** Generic JSON-serializable payload */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = Record<string, JsonValue>;

// ─── JWT Types ────────────────────────────────────────────────────────────────

export type JWTAlgorithm = "HS256" | "HS384" | "HS512";

export interface JWTHeader {
  alg: JWTAlgorithm;
  typ: "JWT";
}

export interface JWTPayload {
  /** Subject (user ID) */
  sub?: string;
  /** Issuer */
  iss?: string;
  /** Audience */
  aud?: string | string[];
  /** Expiration time (Unix timestamp) */
  exp?: number;
  /** Not before (Unix timestamp) */
  nbf?: number;
  /** Issued at (Unix timestamp) */
  iat?: number;
  /** JWT ID */
  jti?: string;
  /** Custom claims */
  [key: string]: unknown;
}

export interface JWTConfig {
  /** Secret key for signing */
  secret: string;
  /** Signing algorithm (default: HS256) */
  algorithm?: JWTAlgorithm;
  /** Token expiration (e.g. "1h", "7d", "30m") or seconds */
  expiresIn?: string | number;
  /** Issuer claim */
  issuer?: string;
  /** Audience claim */
  audience?: string | string[];
}

export interface JWTVerifyResult<T extends JWTPayload = JWTPayload> {
  payload: T;
  header: JWTHeader;
}

export interface JWTTokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface JWTTokenPairConfig {
  access: JWTConfig & { expiresIn: string | number };
  refresh: JWTConfig & { expiresIn: string | number };
}

// ─── Password Types ───────────────────────────────────────────────────────────

export type HashAlgorithm = "pbkdf2" | "scrypt";

export interface PasswordConfig {
  /** Hashing algorithm (default: pbkdf2) */
  algorithm?: HashAlgorithm;
  /** Number of iterations for PBKDF2 (default: 310000) */
  iterations?: number;
  /** Key length in bytes (default: 32) */
  keyLength?: number;
  /** Salt length in bytes (default: 16) */
  saltLength?: number;
  /** Scrypt cost parameter (default: 16384) */
  scryptCost?: number;
  /** Scrypt block size (default: 8) */
  scryptBlockSize?: number;
  /** Scrypt parallelization (default: 1) */
  scryptParallelization?: number;
}

export interface HashedPassword {
  hash: string;
  salt: string;
  algorithm: HashAlgorithm;
  params: Record<string, number>;
}

// ─── Session Types ────────────────────────────────────────────────────────────

export interface SessionData {
  [key: string]: unknown;
}

export interface Session<T extends SessionData = SessionData> {
  id: string;
  data: T;
  createdAt: number;
  expiresAt: number;
  lastAccessedAt: number;
}

export interface SessionConfig {
  /** Session TTL in seconds (default: 86400 = 24h) */
  maxAge?: number;
  /** Auto-renew session on access (default: true) */
  rolling?: boolean;
  /** Session store (default: MemoryStore) */
  store?: SessionStore;
  /** Cookie name (default: "mauth.sid") */
  cookieName?: string;
  /** Cookie options */
  cookie?: CookieOptions;
}

export interface CookieOptions {
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: "strict" | "lax" | "none";
  path?: string;
  domain?: string;
  maxAge?: number;
}

export interface SessionStore {
  get(id: string): Promise<Session | null>;
  set(id: string, session: Session): Promise<void>;
  destroy(id: string): Promise<void>;
  touch(id: string, expiresAt: number): Promise<void>;
}

// ─── OAuth Types ──────────────────────────────────────────────────────────────

export interface OAuthProviderConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
}

export interface OAuthTokenResponse {
  accessToken: string;
  tokenType: string;
  expiresIn?: number;
  refreshToken?: string;
  scope?: string;
  idToken?: string;
}

export interface OAuthUser {
  id: string;
  email?: string;
  name?: string;
  avatar?: string;
  provider: string;
  raw: Record<string, unknown>;
}

export interface OAuthProvider {
  name: string;
  getAuthorizationUrl(state?: string): string;
  handleCallback(code: string): Promise<{ tokens: OAuthTokenResponse; user: OAuthUser }>;
  refreshAccessToken?(refreshToken: string): Promise<OAuthTokenResponse>;
}

export interface OAuthConfig {
  google?: OAuthProviderConfig;
  github?: OAuthProviderConfig;
  discord?: OAuthProviderConfig;
  apple?: OAuthProviderConfig & { teamId: string; keyId: string; privateKey: string };
  microsoft?: OAuthProviderConfig;
  twitter?: OAuthProviderConfig;
  custom?: Record<string, OAuthProviderConfig & {
    authorizationUrl: string;
    tokenUrl: string;
    userInfoUrl: string;
    userMapping: (data: Record<string, unknown>) => OAuthUser;
  }>;
}

// ─── TOTP Types ───────────────────────────────────────────────────────────────

export interface TOTPConfig {
  /** TOTP secret length in bytes (default: 20) */
  secretLength?: number;
  /** Number of digits (default: 6) */
  digits?: number;
  /** Time step in seconds (default: 30) */
  period?: number;
  /** Hash algorithm (default: SHA-1 per RFC 6238) */
  algorithm?: "SHA-1" | "SHA-256" | "SHA-512";
  /** Number of time steps to allow for clock skew (default: 1) */
  window?: number;
  /** Issuer name for QR codes */
  issuer?: string;
}

export interface TOTPSecret {
  /** Base32-encoded secret */
  base32: string;
  /** Raw secret bytes as hex */
  hex: string;
  /** otpauth:// URI for QR codes */
  uri: string;
}

// ─── API Key Types ────────────────────────────────────────────────────────────

export interface APIKeyConfig {
  /** Prefix for generated keys (default: "mk") */
  prefix?: string;
  /** Key length in bytes (default: 32) */
  keyLength?: number;
  /** Hash algorithm for storage (default: SHA-256) */
  hashAlgorithm?: "SHA-256" | "SHA-512";
}

export interface APIKeyResult {
  /** The full API key (only available at creation time) */
  key: string;
  /** The key prefix for display (e.g. "mk_abc1...") */
  prefix: string;
  /** SHA-256 hash for storage and lookups */
  hash: string;
  /** Creation timestamp */
  createdAt: number;
}

// ─── Magic Link Types ─────────────────────────────────────────────────────────

export interface MagicLinkConfig {
  /** Token expiration in seconds (default: 600 = 10 minutes) */
  expiresIn?: number;
  /** Secret for signing tokens */
  secret: string;
  /** Base URL for the magic link */
  baseUrl: string;
  /** URL path (default: "/auth/magic-link/verify") */
  callbackPath?: string;
}

export interface MagicLinkToken {
  /** The magic link token */
  token: string;
  /** The full URL to send to the user */
  url: string;
  /** Expiration timestamp */
  expiresAt: number;
}

export interface MagicLinkVerifyResult {
  /** Whether the token is valid */
  valid: boolean;
  /** The email from the token */
  email: string;
  /** Token metadata */
  metadata?: Record<string, unknown>;
}

// ─── CSRF Types ───────────────────────────────────────────────────────────────

export interface CSRFConfig {
  /** Secret for HMAC signing */
  secret: string;
  /** Token expiration in seconds (default: 3600) */
  expiresIn?: number;
  /** Salt length in bytes (default: 8) */
  saltLength?: number;
}

// ─── Rate Limit Types ─────────────────────────────────────────────────────────

export interface RateLimitConfig {
  /** Maximum number of requests */
  max: number;
  /** Time window in seconds */
  window: number;
  /** Key prefix for storage */
  prefix?: string;
  /** Storage backend (default: in-memory) */
  store?: RateLimitStore;
}

export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Remaining requests in the window */
  remaining: number;
  /** Total limit */
  limit: number;
  /** Unix timestamp when the window resets */
  resetAt: number;
  /** Retry-After in seconds (only when blocked) */
  retryAfter?: number;
}

export interface RateLimitStore {
  increment(key: string, window: number): Promise<{ count: number; resetAt: number }>;
  reset(key: string): Promise<void>;
}

// ─── Middleware Types ─────────────────────────────────────────────────────────

export type AuthType = "jwt" | "session" | "api-key" | "basic";

export interface MiddlewareConfig {
  type: AuthType;
  jwt?: JWTConfig;
  session?: SessionConfig;
  apiKey?: {
    header?: string;
    queryParam?: string;
    verify: (key: string) => Promise<boolean | Record<string, unknown>>;
  };
  onError?: (error: MAuthError) => Response;
  onSuccess?: (auth: AuthContext) => void | Promise<void>;
}

export interface AuthContext {
  type: AuthType;
  userId?: string;
  payload?: JWTPayload;
  session?: Session;
  apiKey?: Record<string, unknown>;
}

// ─── MAuth Config ─────────────────────────────────────────────────────────────

export interface MAuthConfig {
  /** Secret key used across modules */
  secret: string;
  jwt?: Omit<JWTConfig, "secret">;
  password?: PasswordConfig;
  session?: SessionConfig;
  oauth?: OAuthConfig;
  totp?: TOTPConfig;
  csrf?: Omit<CSRFConfig, "secret">;
  apiKey?: APIKeyConfig;
  magicLink?: Omit<MagicLinkConfig, "secret">;
  rateLimit?: RateLimitConfig;
}

// ─── Error Types ──────────────────────────────────────────────────────────────

export type MAuthErrorCode =
  | "TOKEN_EXPIRED"
  | "TOKEN_INVALID"
  | "TOKEN_MALFORMED"
  | "SIGNATURE_INVALID"
  | "HASH_MISMATCH"
  | "SESSION_EXPIRED"
  | "SESSION_NOT_FOUND"
  | "OAUTH_ERROR"
  | "OAUTH_STATE_MISMATCH"
  | "TOTP_INVALID"
  | "CSRF_INVALID"
  | "RATE_LIMITED"
  | "API_KEY_INVALID"
  | "MAGIC_LINK_EXPIRED"
  | "MAGIC_LINK_INVALID"
  | "UNAUTHORIZED"
  | "CONFIGURATION_ERROR";

export class MAuthError extends Error {
  public readonly code: MAuthErrorCode;
  public readonly statusCode: number;

  constructor(message: string, code: MAuthErrorCode, statusCode: number = 401) {
    super(message);
    this.name = "MAuthError";
    this.code = code;
    this.statusCode = statusCode;
  }

  toJSON() {
    return {
      error: this.name,
      code: this.code,
      message: this.message,
      statusCode: this.statusCode,
    };
  }
}
