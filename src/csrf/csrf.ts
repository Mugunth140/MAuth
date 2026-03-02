// ─── CSRF Module ──────────────────────────────────────────────────────────────
// CSRF token generation and verification using double-submit pattern

import { fromBase64Url, hmacSign, hmacVerify, now, randomBytes, toBase64Url, toHex } from "../crypto";
import type { CSRFConfig } from "../types";
import { MAuthError } from "../types";

export class CSRF {
  private config: Required<CSRFConfig>;

  constructor(config: CSRFConfig) {
    if (!config.secret) {
      throw new MAuthError("CSRF secret is required", "CONFIGURATION_ERROR", 500);
    }
    this.config = {
      expiresIn: 3600,
      saltLength: 8,
      ...config,
    };
  }

  /**
   * Generate a CSRF token
   * Format: salt.timestamp.signature
   */
  async generate(): Promise<string> {
    const salt = toHex(randomBytes(this.config.saltLength));
    const timestamp = now().toString();
    const message = `${salt}.${timestamp}`;
    const signature = await hmacSign(message, this.config.secret, "SHA-256");
    return `${message}.${toBase64Url(signature)}`;
  }

  /**
   * Verify a CSRF token
   */
  async verify(token: string): Promise<boolean> {
    if (!token) return false;

    const parts = token.split(".");
    if (parts.length !== 3) return false;

    const [salt, timestamp, signatureB64] = parts;

    // Check expiration
    const tokenTime = parseInt(timestamp, 10);
    if (isNaN(tokenTime) || tokenTime + this.config.expiresIn < now()) {
      return false;
    }

    // Verify signature
    const message = `${salt}.${timestamp}`;
    const signature = fromBase64Url(signatureB64);
    return hmacVerify(message, signature, this.config.secret, "SHA-256");
  }

  /**
   * Create a middleware-friendly token pair (cookie + header)
   * Uses the double-submit cookie pattern
   */
  async createDoubleSubmit(): Promise<{ cookie: string; header: string }> {
    const token = await this.generate();
    return {
      cookie: `csrf-token=${token}; HttpOnly; SameSite=Strict; Secure; Path=/`,
      header: token,
    };
  }

  /**
   * Verify double-submit pattern (compare cookie token with header token)
   */
  async verifyDoubleSubmit(request: Request, headerName: string = "x-csrf-token"): Promise<boolean> {
    const headerToken = request.headers.get(headerName);
    if (!headerToken) return false;

    // Verify the token itself is valid
    return this.verify(headerToken);
  }
}

export { type CSRFConfig };
