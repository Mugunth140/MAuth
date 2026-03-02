// ─── TOTP Module ──────────────────────────────────────────────────────────────
// Time-based One-Time Password (RFC 6238) using Web Crypto API

import { fromBase32, hmacSign, randomBytes, toBase32, toHex } from "../crypto";
import type { TOTPConfig, TOTPSecret } from "../types";

const DEFAULT_CONFIG: Required<TOTPConfig> = {
  secretLength: 20,
  digits: 6,
  period: 30,
  algorithm: "SHA-1",
  window: 1,
  issuer: "",
};

export class TOTP {
  private config: Required<TOTPConfig>;

  constructor(config: TOTPConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /** Generate a new TOTP secret */
  generateSecret(accountName: string): TOTPSecret {
    const bytes = randomBytes(this.config.secretLength);
    const base32 = toBase32(bytes);
    const hex = toHex(bytes);

    // Build otpauth:// URI
    const params = new URLSearchParams({
      secret: base32,
      digits: this.config.digits.toString(),
      period: this.config.period.toString(),
      algorithm: this.config.algorithm.replace("-", ""),
    });

    if (this.config.issuer) {
      params.set("issuer", this.config.issuer);
    }

    const label = this.config.issuer
      ? `${encodeURIComponent(this.config.issuer)}:${encodeURIComponent(accountName)}`
      : encodeURIComponent(accountName);

    const uri = `otpauth://totp/${label}?${params.toString()}`;

    return { base32, hex, uri };
  }

  /** Generate a TOTP code for the current time (or a specific time) */
  async generate(secret: string, timestamp?: number): Promise<string> {
    const time = timestamp ?? Math.floor(Date.now() / 1000);
    const counter = Math.floor(time / this.config.period);
    return this.generateHOTP(secret, counter);
  }

  /** Verify a TOTP code with time window tolerance */
  async verify(code: string, secret: string, timestamp?: number): Promise<boolean> {
    if (!code || code.length !== this.config.digits) return false;

    const time = timestamp ?? Math.floor(Date.now() / 1000);
    const counter = Math.floor(time / this.config.period);

    // Check within the window
    for (let i = -this.config.window; i <= this.config.window; i++) {
      const expected = await this.generateHOTP(secret, counter + i);
      if (timingSafeStringEqual(code, expected)) {
        return true;
      }
    }

    return false;
  }

  /** Generate HOTP code (HMAC-based One-Time Password, RFC 4226) */
  private async generateHOTP(base32Secret: string, counter: number): Promise<string> {
    const secretBytes = fromBase32(base32Secret);

    // Counter to 8-byte big-endian buffer
    const counterBuffer = new Uint8Array(8);
    let c = counter;
    for (let i = 7; i >= 0; i--) {
      counterBuffer[i] = c & 0xff;
      c = Math.floor(c / 256);
    }

    // HMAC
    const hmac = await hmacSign(counterBuffer, secretBytes, this.config.algorithm);

    // Dynamic truncation (RFC 4226 section 5.4)
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);

    const otp = binary % Math.pow(10, this.config.digits);
    return otp.toString().padStart(this.config.digits, "0");
  }
}

/** Constant-time string comparison */
function timingSafeStringEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export { type TOTPConfig, type TOTPSecret };
