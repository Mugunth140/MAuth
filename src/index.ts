// ─── MAuth: Universal Authentication Library ─────────────────────────────────
// Main entry point - exports everything

// Core
export { MAuth } from "./mauth";
export { MAuthError } from "./types";

// Modules
export { APIKey } from "./api-key/api-key";
export { CSRF } from "./csrf/csrf";
export { JWT, JWTTokenPairManager } from "./jwt/jwt";
export { MagicLink } from "./magic-link/magic-link";
export { createAuthMiddleware, createMultiAuthMiddleware, protect } from "./middleware/middleware";
export {
    AppleOAuthProvider, CustomOAuthProvider, DiscordOAuthProvider, GitHubOAuthProvider, GoogleOAuthProvider, MicrosoftOAuthProvider, OAuthManager, TwitterOAuthProvider
} from "./oauth/oauth";
export { Password } from "./password/password";
export { MemoryRateLimitStore, RateLimiter } from "./rate-limit/rate-limit";
export { MemoryStore, SessionManager } from "./session/session";
export { TOTP } from "./totp/totp";

// Crypto utilities (for advanced users)
export {
    fromBase32, fromBase64, fromBase64Url, fromHex, hash,
    hashHex, hmacSign,
    hmacVerify, now, parseDuration, pbkdf2, randomBytes,
    randomString, timingSafeEqual, toBase32, toBase64, toBase64Url, toHex, uuid
} from "./crypto";

// Types
export type {
    // API Key
    APIKeyConfig,
    APIKeyResult, AuthContext,
    AuthType,
    // CSRF
    CSRFConfig, CookieOptions, HashAlgorithm, HashedPassword, JWTAlgorithm,
    // JWT
    JWTConfig, JWTHeader, JWTPayload, JWTTokenPair,
    JWTTokenPairConfig, JWTVerifyResult, JsonObject, JsonValue,
    // Core
    MAuthConfig,
    MAuthErrorCode,
    // Magic Link
    MagicLinkConfig,
    MagicLinkToken,
    MagicLinkVerifyResult,
    // Middleware
    MiddlewareConfig,
    // OAuth
    OAuthConfig, OAuthProvider, OAuthProviderConfig,
    OAuthTokenResponse,
    OAuthUser,
    // Password
    PasswordConfig,
    // Rate Limit
    RateLimitConfig,
    RateLimitResult,
    RateLimitStore, Session,
    // Session
    SessionConfig,
    SessionData, SessionStore,
    // TOTP
    TOTPConfig,
    TOTPSecret
} from "./types";

