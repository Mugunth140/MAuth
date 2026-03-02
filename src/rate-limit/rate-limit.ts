// ─── Rate Limiter Module ──────────────────────────────────────────────────────
// In-memory sliding window rate limiter

import { now } from "../crypto";
import type { RateLimitConfig, RateLimitResult, RateLimitStore } from "../types";
import { MAuthError } from "../types";

// ─── Memory Rate Limit Store ──────────────────────────────────────────────────

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

export class MemoryRateLimitStore implements RateLimitStore {
  private entries = new Map<string, RateLimitEntry>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(cleanupIntervalMs: number = 60_000) {
    if (typeof setInterval !== "undefined") {
      this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
      if (this.cleanupInterval && typeof this.cleanupInterval === "object" && "unref" in this.cleanupInterval) {
        (this.cleanupInterval as { unref: () => void }).unref();
      }
    }
  }

  async increment(key: string, window: number): Promise<{ count: number; resetAt: number }> {
    const currentTime = now();
    const entry = this.entries.get(key);

    if (!entry || entry.resetAt <= currentTime) {
      // Start new window
      const resetAt = currentTime + window;
      this.entries.set(key, { count: 1, resetAt });
      return { count: 1, resetAt };
    }

    // Increment existing window
    entry.count++;
    return { count: entry.count, resetAt: entry.resetAt };
  }

  async reset(key: string): Promise<void> {
    this.entries.delete(key);
  }

  private cleanup(): void {
    const currentTime = now();
    for (const [key, entry] of this.entries) {
      if (entry.resetAt <= currentTime) {
        this.entries.delete(key);
      }
    }
  }

  close(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
  }
}

// ─── Rate Limiter ─────────────────────────────────────────────────────────────

export class RateLimiter {
  private config: Required<Omit<RateLimitConfig, "store">> & { store: RateLimitStore };

  constructor(config: RateLimitConfig) {
    this.config = {
      prefix: "rl",
      ...config,
      store: config.store ?? new MemoryRateLimitStore(),
    };
  }

  /**
   * Check if a request is allowed
   */
  async check(key: string): Promise<RateLimitResult> {
    const fullKey = `${this.config.prefix}:${key}`;
    const { count, resetAt } = await this.config.store.increment(fullKey, this.config.window);

    const allowed = count <= this.config.max;
    const remaining = Math.max(0, this.config.max - count);

    const result: RateLimitResult = {
      allowed,
      remaining,
      limit: this.config.max,
      resetAt,
    };

    if (!allowed) {
      result.retryAfter = resetAt - now();
    }

    return result;
  }

  /**
   * Reset rate limit for a key
   */
  async reset(key: string): Promise<void> {
    const fullKey = `${this.config.prefix}:${key}`;
    await this.config.store.reset(fullKey);
  }

  /**
   * Get rate limit headers for a Response
   */
  getHeaders(result: RateLimitResult): Record<string, string> {
    const headers: Record<string, string> = {
      "X-RateLimit-Limit": result.limit.toString(),
      "X-RateLimit-Remaining": result.remaining.toString(),
      "X-RateLimit-Reset": result.resetAt.toString(),
    };

    if (result.retryAfter !== undefined) {
      headers["Retry-After"] = result.retryAfter.toString();
    }

    return headers;
  }

  /**
   * Express/Hono-style middleware helper that returns rate limit info
   * and throws if the limit is exceeded
   */
  async limit(key: string): Promise<RateLimitResult> {
    const result = await this.check(key);
    if (!result.allowed) {
      throw new MAuthError(
        `Rate limit exceeded. Try again in ${result.retryAfter} seconds`,
        "RATE_LIMITED",
        429
      );
    }
    return result;
  }
}

export { type RateLimitConfig, type RateLimitResult, type RateLimitStore };
