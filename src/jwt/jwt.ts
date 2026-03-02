// ─── JWT Module ───────────────────────────────────────────────────────────────
// JSON Web Token creation and verification using Web Crypto HMAC

import { fromBase64Url, hmacSign, hmacVerify, now, parseDuration, toBase64Url, uuid } from "../crypto";
import type { JWTAlgorithm, JWTConfig, JWTHeader, JWTPayload, JWTTokenPair, JWTTokenPairConfig, JWTVerifyResult } from "../types";
import { MAuthError } from "../types";

const encoder = new TextEncoder();

const ALG_MAP: Record<JWTAlgorithm, "SHA-256" | "SHA-384" | "SHA-512"> = {
  HS256: "SHA-256",
  HS384: "SHA-384",
  HS512: "SHA-512",
};

export class JWT {
  private config: Required<Pick<JWTConfig, "secret" | "algorithm">> & JWTConfig;

  constructor(config: JWTConfig) {
    if (!config.secret) {
      throw new MAuthError("JWT secret is required", "CONFIGURATION_ERROR", 500);
    }
    this.config = {
      algorithm: "HS256",
      ...config,
    };
  }

  /**
   * Sign a JWT token with the given payload
   */
  async sign<T extends JWTPayload = JWTPayload>(payload: T): Promise<string> {
    const header: JWTHeader = {
      alg: this.config.algorithm,
      typ: "JWT",
    };

    const currentTime = now();
    const finalPayload: JWTPayload = {
      ...payload,
      iat: payload.iat ?? currentTime,
      jti: payload.jti ?? uuid(),
    };

    // Set issuer and audience from config
    if (this.config.issuer && !finalPayload.iss) {
      finalPayload.iss = this.config.issuer;
    }
    if (this.config.audience && !finalPayload.aud) {
      finalPayload.aud = this.config.audience;
    }

    // Set expiration
    if (this.config.expiresIn && !finalPayload.exp) {
      const seconds = parseDuration(this.config.expiresIn);
      finalPayload.exp = currentTime + seconds;
    }

    const headerB64 = toBase64Url(JSON.stringify(header));
    const payloadB64 = toBase64Url(JSON.stringify(finalPayload));
    const signingInput = `${headerB64}.${payloadB64}`;

    const hashAlg = ALG_MAP[this.config.algorithm];
    const signature = await hmacSign(signingInput, this.config.secret, hashAlg);
    const signatureB64 = toBase64Url(signature);

    return `${signingInput}.${signatureB64}`;
  }

  /**
   * Verify and decode a JWT token
   */
  async verify<T extends JWTPayload = JWTPayload>(token: string): Promise<JWTVerifyResult<T>> {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new MAuthError("Token must have 3 parts", "TOKEN_MALFORMED");
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // Decode header
    let header: JWTHeader;
    try {
      header = JSON.parse(new TextDecoder().decode(fromBase64Url(headerB64)));
    } catch {
      throw new MAuthError("Invalid token header", "TOKEN_MALFORMED");
    }

    // Verify algorithm
    if (header.alg !== this.config.algorithm) {
      throw new MAuthError(`Algorithm mismatch: expected ${this.config.algorithm}, got ${header.alg}`, "TOKEN_INVALID");
    }

    // Verify signature
    const signingInput = `${headerB64}.${payloadB64}`;
    const signature = fromBase64Url(signatureB64);
    const hashAlg = ALG_MAP[this.config.algorithm];

    const valid = await hmacVerify(signingInput, signature, this.config.secret, hashAlg);
    if (!valid) {
      throw new MAuthError("Invalid token signature", "SIGNATURE_INVALID");
    }

    // Decode payload
    let payload: T;
    try {
      payload = JSON.parse(new TextDecoder().decode(fromBase64Url(payloadB64)));
    } catch {
      throw new MAuthError("Invalid token payload", "TOKEN_MALFORMED");
    }

    // Verify expiration
    if (payload.exp && payload.exp < now()) {
      throw new MAuthError("Token has expired", "TOKEN_EXPIRED");
    }

    // Verify nbf
    if (payload.nbf && payload.nbf > now()) {
      throw new MAuthError("Token is not yet valid", "TOKEN_INVALID");
    }

    // Verify issuer
    if (this.config.issuer && payload.iss !== this.config.issuer) {
      throw new MAuthError(`Issuer mismatch: expected ${this.config.issuer}`, "TOKEN_INVALID");
    }

    // Verify audience
    if (this.config.audience) {
      const expectedAud = Array.isArray(this.config.audience) ? this.config.audience : [this.config.audience];
      const tokenAud = Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [];
      if (!expectedAud.some((a) => tokenAud.includes(a))) {
        throw new MAuthError("Audience mismatch", "TOKEN_INVALID");
      }
    }

    return { payload, header };
  }

  /**
   * Decode a JWT without verification (useful for reading expired tokens)
   */
  decode<T extends JWTPayload = JWTPayload>(token: string): JWTVerifyResult<T> {
    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new MAuthError("Token must have 3 parts", "TOKEN_MALFORMED");
    }

    try {
      const header = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[0]))) as JWTHeader;
      const payload = JSON.parse(new TextDecoder().decode(fromBase64Url(parts[1]))) as T;
      return { header, payload };
    } catch {
      throw new MAuthError("Invalid token format", "TOKEN_MALFORMED");
    }
  }
}

/**
 * Create a JWT token pair manager for access/refresh token patterns
 */
export class JWTTokenPairManager {
  private accessJWT: JWT;
  private refreshJWT: JWT;

  constructor(config: JWTTokenPairConfig) {
    this.accessJWT = new JWT(config.access);
    this.refreshJWT = new JWT(config.refresh);
  }

  /** Generate both access and refresh tokens */
  async generate(payload: JWTPayload): Promise<JWTTokenPair> {
    const [accessToken, refreshToken] = await Promise.all([
      this.accessJWT.sign(payload),
      this.refreshJWT.sign({ ...payload, type: "refresh" }),
    ]);
    return { accessToken, refreshToken };
  }

  /** Verify access token */
  async verifyAccess<T extends JWTPayload = JWTPayload>(token: string): Promise<JWTVerifyResult<T>> {
    return this.accessJWT.verify<T>(token);
  }

  /** Verify refresh token and generate new token pair */
  async refresh<T extends JWTPayload = JWTPayload>(refreshToken: string): Promise<JWTTokenPair & { payload: T }> {
    const { payload } = await this.refreshJWT.verify<T>(refreshToken);
    // Remove refresh-specific claims before re-signing
    const { exp, iat, jti, type, ...cleanPayload } = payload as JWTPayload & { type?: string };
    const tokens = await this.generate(cleanPayload as JWTPayload);
    return { ...tokens, payload: cleanPayload as T };
  }
}

export { type JWTConfig, type JWTHeader, type JWTPayload, type JWTTokenPair, type JWTTokenPairConfig, type JWTVerifyResult };

