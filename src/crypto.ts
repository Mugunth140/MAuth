// ─── Cross-runtime Crypto Utilities ───────────────────────────────────────────
// Uses Web Crypto API for universal runtime support (Node 18+, Bun, Deno, Edge)

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Get the global crypto object (works in all runtimes) */
function getCrypto(): Crypto {
  if (typeof globalThis.crypto !== "undefined") {
    return globalThis.crypto;
  }
  throw new Error("Web Crypto API is not available in this runtime");
}

// ─── Random ───────────────────────────────────────────────────────────────────

/** Generate cryptographically secure random bytes */
export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  getCrypto().getRandomValues(bytes);
  return bytes;
}

/** Generate a random string of specified length using the given alphabet */
export function randomString(length: number, alphabet: string = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"): string {
  const bytes = randomBytes(length);
  let result = "";
  for (let i = 0; i < length; i++) {
    result += alphabet[bytes[i] % alphabet.length];
  }
  return result;
}

/** Generate a UUID v4 */
export function uuid(): string {
  return getCrypto().randomUUID();
}

// ─── Encoding ─────────────────────────────────────────────────────────────────

/** Encode Uint8Array to base64 */
export function toBase64(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

/** Decode base64 string to Uint8Array */
export function fromBase64(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/** Encode a string/Uint8Array to base64url (URL-safe, no padding) */
export function toBase64Url(data: Uint8Array | string): string {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode base64url to Uint8Array */
export function fromBase64Url(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  // Add padding
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return fromBase64(base64);
}

/** Decode base64url to string */
export function base64UrlToString(str: string): string {
  return decoder.decode(fromBase64Url(str));
}

/** Encode Uint8Array to hex string */
export function toHex(data: Uint8Array): string {
  return Array.from(data)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Decode hex string to Uint8Array */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ─── Base32 ───────────────────────────────────────────────────────────────────

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Encode Uint8Array to base32 */
export function toBase32(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/** Decode base32 string to Uint8Array */
export function fromBase32(str: string): Uint8Array {
  const cleaned = str.toUpperCase().replace(/=+$/, "");
  const output: number[] = [];
  let bits = 0;
  let value = 0;

  for (let i = 0; i < cleaned.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleaned[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

// ─── HMAC ─────────────────────────────────────────────────────────────────────

type HMACAlgorithm = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

/** Create HMAC signature */
export async function hmacSign(
  data: Uint8Array | string,
  secret: Uint8Array | string,
  algorithm: HMACAlgorithm = "SHA-256"
): Promise<Uint8Array> {
  const crypto = getCrypto();
  const keyData = typeof secret === "string" ? encoder.encode(secret) : secret;
  const msgData = typeof data === "string" ? encoder.encode(data) : data;

  const key = await crypto.subtle.importKey(
    "raw",
    keyData as unknown as ArrayBuffer,
    { name: "HMAC", hash: algorithm },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", key, msgData as unknown as ArrayBuffer);
  return new Uint8Array(signature);
}

/** Verify HMAC signature using constant-time comparison */
export async function hmacVerify(
  data: Uint8Array | string,
  signature: Uint8Array,
  secret: Uint8Array | string,
  algorithm: HMACAlgorithm = "SHA-256"
): Promise<boolean> {
  const crypto = getCrypto();
  const keyData = typeof secret === "string" ? encoder.encode(secret) : secret;
  const msgData = typeof data === "string" ? encoder.encode(data) : data;

  const key = await crypto.subtle.importKey(
    "raw",
    keyData as unknown as ArrayBuffer,
    { name: "HMAC", hash: algorithm },
    false,
    ["verify"]
  );

  return crypto.subtle.verify("HMAC", key, signature as unknown as ArrayBuffer, msgData as unknown as ArrayBuffer);
}

// ─── Hashing ──────────────────────────────────────────────────────────────────

/** Hash data with SHA-256 (or other) */
export async function hash(
  data: Uint8Array | string,
  algorithm: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-256"
): Promise<Uint8Array> {
  const crypto = getCrypto();
  const msgData = typeof data === "string" ? encoder.encode(data) : data;
  const digest = await crypto.subtle.digest(algorithm, msgData as unknown as ArrayBuffer);
  return new Uint8Array(digest);
}

/** Hash data and return hex string */
export async function hashHex(
  data: Uint8Array | string,
  algorithm: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-256"
): Promise<string> {
  const result = await hash(data, algorithm);
  return toHex(result);
}

// ─── PBKDF2 ───────────────────────────────────────────────────────────────────

/** Derive key using PBKDF2 */
export async function pbkdf2(
  password: string,
  salt: Uint8Array,
  iterations: number,
  keyLength: number,
  hashAlgorithm: "SHA-256" | "SHA-384" | "SHA-512" = "SHA-256"
): Promise<Uint8Array> {
  const crypto = getCrypto();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password) as unknown as ArrayBuffer,
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as unknown as ArrayBuffer,
      iterations,
      hash: hashAlgorithm,
    },
    keyMaterial,
    keyLength * 8
  );

  return new Uint8Array(bits);
}

// ─── Constant Time Compare ───────────────────────────────────────────────────

/** Constant-time comparison of two strings/buffers to prevent timing attacks */
export function timingSafeEqual(a: Uint8Array | string, b: Uint8Array | string): boolean {
  const bufA = typeof a === "string" ? encoder.encode(a) : a;
  const bufB = typeof b === "string" ? encoder.encode(b) : b;

  if (bufA.length !== bufB.length) return false;

  let result = 0;
  for (let i = 0; i < bufA.length; i++) {
    result |= bufA[i] ^ bufB[i];
  }
  return result === 0;
}

// ─── Time Helpers ─────────────────────────────────────────────────────────────

/** Parse duration string to seconds (e.g., "1h", "30m", "7d", "1y") */
export function parseDuration(duration: string | number): number {
  if (typeof duration === "number") return duration;

  const match = duration.match(/^(\d+)\s*(s|m|h|d|w|y)$/i);
  if (!match) throw new Error(`Invalid duration format: ${duration}`);

  const value = parseInt(match[1], 10);
  const unit = match[2].toLowerCase();

  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
    y: 31536000,
  };

  return value * (multipliers[unit] || 1);
}

/** Get current Unix timestamp in seconds */
export function now(): number {
  return Math.floor(Date.now() / 1000);
}
