// ─── Magic Link Module ────────────────────────────────────────────────────────
// Token-based passwordless authentication via email magic links

import { fromBase64Url, hmacSign, hmacVerify, now, toBase64Url, uuid } from "../crypto";
import type { MagicLinkConfig, MagicLinkToken, MagicLinkVerifyResult } from "../types";
import { MAuthError } from "../types";

const encoder = new TextEncoder();

export class MagicLink {
  private config: Required<MagicLinkConfig>;

  constructor(config: MagicLinkConfig) {
    if (!config.secret) {
      throw new MAuthError("Magic link secret is required", "CONFIGURATION_ERROR", 500);
    }
    this.config = {
      expiresIn: 600, // 10 minutes
      callbackPath: "/auth/magic-link/verify",
      ...config,
    };
  }

  /**
   * Generate a magic link token for the given email
   */
  async generate(email: string, metadata?: Record<string, unknown>): Promise<MagicLinkToken> {
    if (!email) {
      throw new MAuthError("Email is required", "CONFIGURATION_ERROR", 400);
    }

    const expiresAt = now() + this.config.expiresIn;
    const payload = {
      email,
      exp: expiresAt,
      jti: uuid(),
      ...metadata,
    };

    const payloadB64 = toBase64Url(JSON.stringify(payload));
    const signature = await hmacSign(payloadB64, this.config.secret, "SHA-256");
    const signatureB64 = toBase64Url(signature);
    const token = `${payloadB64}.${signatureB64}`;

    const url = `${this.config.baseUrl}${this.config.callbackPath}?token=${encodeURIComponent(token)}`;

    return { token, url, expiresAt };
  }

  /**
   * Verify a magic link token
   */
  async verify(token: string): Promise<MagicLinkVerifyResult> {
    const parts = token.split(".");
    if (parts.length !== 2) {
      throw new MAuthError("Invalid magic link token format", "MAGIC_LINK_INVALID");
    }

    const [payloadB64, signatureB64] = parts;

    // Verify signature
    const signature = fromBase64Url(signatureB64);
    const valid = await hmacVerify(payloadB64, signature, this.config.secret, "SHA-256");

    if (!valid) {
      throw new MAuthError("Invalid magic link signature", "MAGIC_LINK_INVALID");
    }

    // Decode payload
    let payload: { email: string; exp: number; jti: string; [key: string]: unknown };
    try {
      payload = JSON.parse(new TextDecoder().decode(fromBase64Url(payloadB64)));
    } catch {
      throw new MAuthError("Invalid magic link payload", "MAGIC_LINK_INVALID");
    }

    // Check expiration
    if (payload.exp < now()) {
      throw new MAuthError("Magic link has expired", "MAGIC_LINK_EXPIRED");
    }

    const { email, exp, jti, ...metadata } = payload;
    return {
      valid: true,
      email,
      metadata: Object.keys(metadata).length > 0 ? metadata : undefined,
    };
  }
}

export { type MagicLinkConfig, type MagicLinkToken, type MagicLinkVerifyResult };
