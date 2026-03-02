// ─── Password Hashing Module ──────────────────────────────────────────────────
// Cross-runtime password hashing using PBKDF2 via Web Crypto API

import { fromHex, pbkdf2, randomBytes, timingSafeEqual, toHex } from "../crypto";
import type { HashedPassword, PasswordConfig } from "../types";
import { MAuthError } from "../types";

const DEFAULT_CONFIG: Required<PasswordConfig> = {
  algorithm: "pbkdf2",
  iterations: 310000,
  keyLength: 32,
  saltLength: 16,
  scryptCost: 16384,
  scryptBlockSize: 8,
  scryptParallelization: 1,
};

export class Password {
  private config: Required<PasswordConfig>;

  constructor(config: PasswordConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Hash a password
   * Returns a PHC-formatted string: $algorithm$params$salt$hash
   */
  async hash(password: string): Promise<string> {
    if (!password) {
      throw new MAuthError("Password cannot be empty", "CONFIGURATION_ERROR", 400);
    }

    const salt = randomBytes(this.config.saltLength);
    const derived = await pbkdf2(
      password,
      salt,
      this.config.iterations,
      this.config.keyLength
    );

    // PHC string format: $pbkdf2-sha256$i=310000$salt$hash
    const saltHex = toHex(salt);
    const hashHex = toHex(derived);

    return `$pbkdf2-sha256$i=${this.config.iterations},l=${this.config.keyLength}$${saltHex}$${hashHex}`;
  }

  /**
   * Verify a password against a hash
   */
  async verify(password: string, hashString: string): Promise<boolean> {
    if (!password || !hashString) return false;

    try {
      const parsed = this.parseHash(hashString);
      const derived = await pbkdf2(
        password,
        fromHex(parsed.salt),
        parsed.params.iterations ?? this.config.iterations,
        parsed.params.keyLength ?? this.config.keyLength
      );

      return timingSafeEqual(derived, fromHex(parsed.hash));
    } catch {
      return false;
    }
  }

  /**
   * Check if a hash needs to be rehashed (e.g. after config changes)
   */
  needsRehash(hashString: string): boolean {
    try {
      const parsed = this.parseHash(hashString);
      return (
        parsed.params.iterations !== this.config.iterations ||
        parsed.params.keyLength !== this.config.keyLength
      );
    } catch {
      return true;
    }
  }

  /**
   * Parse a PHC-formatted hash string
   */
  private parseHash(hashString: string): HashedPassword {
    const parts = hashString.split("$").filter(Boolean);

    if (parts.length < 4) {
      throw new MAuthError("Invalid hash format", "HASH_MISMATCH");
    }

    const [algorithm, paramsStr, salt, hash] = parts;

    if (algorithm !== "pbkdf2-sha256") {
      throw new MAuthError(`Unsupported algorithm: ${algorithm}`, "HASH_MISMATCH");
    }

    const params: Record<string, number> = {};
    for (const param of paramsStr.split(",")) {
      const [key, value] = param.split("=");
      if (key === "i") params.iterations = parseInt(value, 10);
      if (key === "l") params.keyLength = parseInt(value, 10);
    }

    return {
      algorithm: "pbkdf2",
      params,
      salt,
      hash,
    };
  }
}

export { type HashedPassword, type PasswordConfig };

