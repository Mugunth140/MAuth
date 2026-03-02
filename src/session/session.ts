// ─── Session Management ───────────────────────────────────────────────────────
// Framework-agnostic session management with pluggable stores

import { now, randomString } from "../crypto";
import type { CookieOptions, Session, SessionConfig, SessionData, SessionStore } from "../types";

// ─── Memory Store (Default) ──────────────────────────────────────────────────

export class MemoryStore implements SessionStore {
  private store = new Map<string, Session>();
  private cleanupInterval: ReturnType<typeof setInterval> | null = null;

  constructor(cleanupIntervalMs: number = 60_000) {
    // Periodically clean expired sessions
    if (typeof setInterval !== "undefined") {
      this.cleanupInterval = setInterval(() => this.cleanup(), cleanupIntervalMs);
      // Allow process to exit naturally (Node.js)
      if (this.cleanupInterval && typeof this.cleanupInterval === "object" && "unref" in this.cleanupInterval) {
        (this.cleanupInterval as { unref: () => void }).unref();
      }
    }
  }

  async get(id: string): Promise<Session | null> {
    const session = this.store.get(id);
    if (!session) return null;
    if (session.expiresAt < now()) {
      this.store.delete(id);
      return null;
    }
    return session;
  }

  async set(id: string, session: Session): Promise<void> {
    this.store.set(id, session);
  }

  async destroy(id: string): Promise<void> {
    this.store.delete(id);
  }

  async touch(id: string, expiresAt: number): Promise<void> {
    const session = this.store.get(id);
    if (session) {
      session.expiresAt = expiresAt;
      session.lastAccessedAt = now();
    }
  }

  private cleanup(): void {
    const currentTime = now();
    for (const [id, session] of this.store) {
      if (session.expiresAt < currentTime) {
        this.store.delete(id);
      }
    }
  }

  dispose(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.store.clear();
  }
}

// ─── Session Manager ─────────────────────────────────────────────────────────

const DEFAULT_COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "lax",
  path: "/",
};

export class SessionManager<T extends SessionData = SessionData> {
  private store: SessionStore;
  private config: Required<Pick<SessionConfig, "maxAge" | "rolling" | "cookieName">> & SessionConfig;
  private cookieOptions: CookieOptions;

  constructor(config: SessionConfig = {}) {
    this.store = config.store ?? new MemoryStore();
    this.config = {
      maxAge: 86400, // 24 hours
      rolling: true,
      cookieName: "mauth.sid",
      ...config,
    };
    this.cookieOptions = {
      ...DEFAULT_COOKIE_OPTIONS,
      maxAge: this.config.maxAge,
      ...(config.cookie ?? {}),
    };
  }

  /** Create a new session */
  async create(data: T): Promise<Session<T>> {
    const id = randomString(32);
    const currentTime = now();

    const session: Session<T> = {
      id,
      data,
      createdAt: currentTime,
      expiresAt: currentTime + this.config.maxAge,
      lastAccessedAt: currentTime,
    };

    await this.store.set(id, session as Session);
    return session;
  }

  /** Get a session by ID */
  async get(id: string): Promise<Session<T> | null> {
    const session = await this.store.get(id);
    if (!session) return null;

    // Auto-renew if rolling is enabled
    if (this.config.rolling) {
      const newExpiry = now() + this.config.maxAge;
      await this.store.touch(id, newExpiry);
      session.expiresAt = newExpiry;
      session.lastAccessedAt = now();
    }

    return session as Session<T>;
  }

  /** Update session data */
  async update(id: string, data: Partial<T>): Promise<Session<T> | null> {
    const session = await this.store.get(id);
    if (!session) return null;

    const updated: Session<T> = {
      ...session,
      data: { ...session.data, ...data } as T,
      lastAccessedAt: now(),
    };

    if (this.config.rolling) {
      updated.expiresAt = now() + this.config.maxAge;
    }

    await this.store.set(id, updated as Session);
    return updated;
  }

  /** Destroy a session */
  async destroy(id: string): Promise<void> {
    await this.store.destroy(id);
  }

  /** Get the session ID from a cookie header string */
  getSessionIdFromCookie(cookieHeader: string | null): string | null {
    if (!cookieHeader) return null;
    const cookies = cookieHeader.split(";").map((c) => c.trim());
    const sessionCookie = cookies.find((c) => c.startsWith(`${this.config.cookieName}=`));
    if (!sessionCookie) return null;
    return sessionCookie.split("=")[1] ?? null;
  }

  /** Generate a Set-Cookie header string */
  getSetCookieHeader(sessionId: string): string {
    const opts = this.cookieOptions;
    let cookie = `${this.config.cookieName}=${sessionId}`;

    if (opts.path) cookie += `; Path=${opts.path}`;
    if (opts.domain) cookie += `; Domain=${opts.domain}`;
    if (opts.maxAge) cookie += `; Max-Age=${opts.maxAge}`;
    if (opts.httpOnly) cookie += "; HttpOnly";
    if (opts.secure) cookie += "; Secure";
    if (opts.sameSite) cookie += `; SameSite=${opts.sameSite.charAt(0).toUpperCase() + opts.sameSite.slice(1)}`;

    return cookie;
  }

  /** Generate a cookie-clearing header */
  getClearCookieHeader(): string {
    return `${this.config.cookieName}=; Path=${this.cookieOptions.path ?? "/"}; Max-Age=0; HttpOnly; Secure`;
  }

  /** Handle a Web Standard Request - extract or create session */
  async fromRequest(request: Request): Promise<{ session: Session<T>; isNew: boolean }> {
    const cookieHeader = request.headers.get("cookie");
    const sessionId = this.getSessionIdFromCookie(cookieHeader);

    if (sessionId) {
      const session = await this.get(sessionId);
      if (session) {
        return { session, isNew: false };
      }
    }

    // Create new empty session
    const session = await this.create({} as T);
    return { session, isNew: true };
  }
}

export { type CookieOptions, type Session, type SessionConfig, type SessionData, type SessionStore };

