// ─── Middleware Module ─────────────────────────────────────────────────────────
// Framework-agnostic middleware using Web Standard Request/Response

import { JWT } from "../jwt/jwt";
import { SessionManager } from "../session/session";
import type { AuthContext, AuthType, JWTPayload, MiddlewareConfig } from "../types";
import { MAuthError } from "../types";

type MiddlewareHandler = (request: Request) => Promise<{ auth: AuthContext; response?: Response }>;

/**
 * Create an authentication middleware function
 * Works with any framework that uses Web Standard Request/Response
 */
export function createAuthMiddleware(config: MiddlewareConfig): MiddlewareHandler {
  return async (request: Request) => {
    try {
      switch (config.type) {
        case "jwt":
          return await handleJWT(request, config);
        case "session":
          return await handleSession(request, config);
        case "api-key":
          return await handleAPIKey(request, config);
        case "basic":
          return await handleBasicAuth(request, config);
        default:
          throw new MAuthError(`Unknown auth type: ${config.type}`, "CONFIGURATION_ERROR", 500);
      }
    } catch (error) {
      if (error instanceof MAuthError) {
        if (config.onError) {
          return { auth: { type: config.type }, response: config.onError(error) };
        }
        return {
          auth: { type: config.type },
          response: new Response(JSON.stringify(error.toJSON()), {
            status: error.statusCode,
            headers: { "Content-Type": "application/json" },
          }),
        };
      }
      throw error;
    }
  };
}

async function handleJWT(request: Request, config: MiddlewareConfig): Promise<{ auth: AuthContext }> {
  if (!config.jwt) {
    throw new MAuthError("JWT config is required for JWT middleware", "CONFIGURATION_ERROR", 500);
  }

  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    throw new MAuthError("Missing or invalid Authorization header", "UNAUTHORIZED");
  }

  const token = authHeader.slice(7);
  const jwt = new JWT(config.jwt);
  const { payload } = await jwt.verify(token);

  const auth: AuthContext = {
    type: "jwt",
    userId: payload.sub,
    payload,
  };

  if (config.onSuccess) await config.onSuccess(auth);
  return { auth };
}

async function handleSession(request: Request, config: MiddlewareConfig): Promise<{ auth: AuthContext }> {
  if (!config.session) {
    throw new MAuthError("Session config is required for session middleware", "CONFIGURATION_ERROR", 500);
  }

  const manager = new SessionManager(config.session);
  const { session, isNew } = await manager.fromRequest(request);

  if (isNew || !session) {
    throw new MAuthError("No valid session found", "SESSION_NOT_FOUND");
  }

  if (!session) {
    throw new MAuthError("No valid session found", "SESSION_NOT_FOUND");
  }

  const auth: AuthContext = {
    type: "session",
    userId: session.data.userId as string | undefined,
    session,
  };

  if (config.onSuccess) await config.onSuccess(auth);
  return { auth };
}

async function handleAPIKey(request: Request, config: MiddlewareConfig): Promise<{ auth: AuthContext }> {
  if (!config.apiKey) {
    throw new MAuthError("API key config is required", "CONFIGURATION_ERROR", 500);
  }

  const headerName = config.apiKey.header ?? "x-api-key";
  const queryParam = config.apiKey.queryParam ?? "api_key";

  // Check header first, then query param
  let key = request.headers.get(headerName);
  if (!key) {
    const url = new URL(request.url);
    key = url.searchParams.get(queryParam);
  }

  if (!key) {
    throw new MAuthError("Missing API key", "API_KEY_INVALID");
  }

  const result = await config.apiKey.verify(key);
  if (!result) {
    throw new MAuthError("Invalid API key", "API_KEY_INVALID");
  }

  const auth: AuthContext = {
    type: "api-key",
    apiKey: typeof result === "object" ? result : {},
  };

  if (config.onSuccess) await config.onSuccess(auth);
  return { auth };
}

async function handleBasicAuth(request: Request, config: MiddlewareConfig): Promise<{ auth: AuthContext }> {
  const authHeader = request.headers.get("authorization");
  if (!authHeader?.startsWith("Basic ")) {
    throw new MAuthError("Missing or invalid Authorization header", "UNAUTHORIZED");
  }

  const decoded = atob(authHeader.slice(6));
  const separatorIndex = decoded.indexOf(":");
  if (separatorIndex === -1) {
    throw new MAuthError("Invalid Basic auth format", "UNAUTHORIZED");
  }

  const username = decoded.slice(0, separatorIndex);
  const password = decoded.slice(separatorIndex + 1);

  const auth: AuthContext = {
    type: "basic",
    payload: { sub: username, password } as unknown as JWTPayload,
  };

  if (config.onSuccess) await config.onSuccess(auth);
  return { auth };
}

/**
 * Combine multiple auth middlewares — tries each in order, succeeds on first match
 */
export function createMultiAuthMiddleware(
  configs: MiddlewareConfig[]
): MiddlewareHandler {
  return async (request: Request) => {
    const errors: MAuthError[] = [];

    for (const config of configs) {
      const handler = createAuthMiddleware(config);
      try {
        const result = await handler(request);
        if (!result.response) return result; // Success
      } catch (error) {
        if (error instanceof MAuthError) {
          errors.push(error);
        } else {
          throw error;
        }
      }
    }

    // All methods failed
    const lastError = errors[errors.length - 1] ?? new MAuthError("Unauthorized", "UNAUTHORIZED");
    throw lastError;
  };
}

/**
 * Helper to protect a route handler with authentication
 * Returns a function that wraps your handler and injects AuthContext
 */
export function protect<T>(
  config: MiddlewareConfig,
  handler: (request: Request, auth: AuthContext) => Promise<Response> | Response
): (request: Request) => Promise<Response> {
  const middleware = createAuthMiddleware(config);

  return async (request: Request): Promise<Response> => {
    const result = await middleware(request);
    if (result.response) return result.response; // Auth error
    return handler(request, result.auth);
  };
}

export type { AuthContext, AuthType, MiddlewareConfig, MiddlewareHandler };

