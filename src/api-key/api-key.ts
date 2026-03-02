// ─── API Key Module ───────────────────────────────────────────────────────────
// Secure API key generation and verification

import { hashHex, randomBytes, timingSafeEqual, toHex } from "../crypto";
import type { APIKeyConfig, APIKeyResult } from "../types";

const DEFAULT_CONFIG: Required<APIKeyConfig> = {
  prefix: "mk",
  keyLength: 32,
  hashAlgorithm: "SHA-256",
};

export class APIKey {
  private config: Required<APIKeyConfig>;

  constructor(config: APIKeyConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Generate a new API key
   * Returns the full key (only shown once) and the hash (for storage)
   */
  async generate(metadata?: Record<string, unknown>): Promise<APIKeyResult> {
    const bytes = randomBytes(this.config.keyLength);
    const keyBody = toHex(bytes);
    const key = `${this.config.prefix}_${keyBody}`;

    // Hash the key for storage
    const hash = await hashHex(key, this.config.hashAlgorithm);

    return {
      key,
      prefix: `${this.config.prefix}_${keyBody.substring(0, 8)}...`,
      hash,
      createdAt: Math.floor(Date.now() / 1000),
    };
  }

  /**
   * Hash an API key (for lookup)
   */
  async hashKey(key: string): Promise<string> {
    return hashHex(key, this.config.hashAlgorithm);
  }

  /**
   * Verify an API key against a stored hash
   */
  async verify(key: string, storedHash: string): Promise<boolean> {
    if (!key || !storedHash) return false;
    try {
      const keyHash = await hashHex(key, this.config.hashAlgorithm);
      return timingSafeEqual(keyHash, storedHash);
    } catch {
      return false;
    }
  }

  /**
   * Validate API key format
   */
  isValidFormat(key: string): boolean {
    if (!key) return false;
    const parts = key.split("_");
    if (parts.length !== 2) return false;
    return parts[0] === this.config.prefix && parts[1].length === this.config.keyLength * 2;
  }
}

export { type APIKeyConfig, type APIKeyResult };
