// ─── OAuth Module ─────────────────────────────────────────────────────────────
// OAuth 2.0 provider implementations

import { randomString } from "../crypto";
import type { OAuthProvider, OAuthProviderConfig, OAuthTokenResponse, OAuthUser } from "../types";
import { MAuthError } from "../types";

// ─── Base OAuth Provider ──────────────────────────────────────────────────────

interface ProviderEndpoints {
  authorization: string;
  token: string;
  userInfo: string;
}

abstract class BaseOAuthProvider implements OAuthProvider {
  abstract readonly name: string;
  protected abstract readonly endpoints: ProviderEndpoints;
  protected config: OAuthProviderConfig;

  constructor(config: OAuthProviderConfig) {
    this.config = config;
  }

  /** Generate the authorization URL */
  getAuthorizationUrl(state?: string): string {
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: "code",
      state: state ?? randomString(32),
    });

    if (this.config.scopes?.length) {
      params.set("scope", this.config.scopes.join(" "));
    }

    this.addAuthParams(params);
    return `${this.endpoints.authorization}?${params.toString()}`;
  }

  /** Exchange authorization code for tokens and user info */
  async handleCallback(code: string): Promise<{ tokens: OAuthTokenResponse; user: OAuthUser }> {
    const tokens = await this.exchangeCode(code);
    const user = await this.fetchUser(tokens.accessToken);
    return { tokens, user };
  }

  /** Refresh an access token */
  async refreshAccessToken(refreshToken: string): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });

    const response = await fetch(this.endpoints.token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: body.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new MAuthError(`OAuth token refresh failed: ${error}`, "OAUTH_ERROR");
    }

    const data = await response.json() as Record<string, unknown>;
    return this.mapTokenResponse(data);
  }

  /** Override to add provider-specific auth params */
  protected addAuthParams(_params: URLSearchParams): void {}

  /** Exchange authorization code for tokens */
  protected async exchangeCode(code: string): Promise<OAuthTokenResponse> {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.config.redirectUri,
      client_id: this.config.clientId,
      client_secret: this.config.clientSecret,
    });

    const response = await fetch(this.endpoints.token, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
      body: body.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new MAuthError(`OAuth code exchange failed: ${error}`, "OAUTH_ERROR");
    }

    const data = await response.json() as Record<string, unknown>;
    return this.mapTokenResponse(data);
  }

  /** Fetch user info from the provider */
  protected async fetchUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(this.endpoints.userInfo, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new MAuthError("Failed to fetch user info", "OAUTH_ERROR");
    }

    const data = await response.json() as Record<string, unknown>;
    return this.mapUser(data);
  }

  /** Map raw token response to standard format */
  protected mapTokenResponse(data: Record<string, unknown>): OAuthTokenResponse {
    return {
      accessToken: (data.access_token as string) ?? "",
      tokenType: (data.token_type as string) ?? "Bearer",
      expiresIn: data.expires_in as number | undefined,
      refreshToken: data.refresh_token as string | undefined,
      scope: data.scope as string | undefined,
      idToken: data.id_token as string | undefined,
    };
  }

  /** Map provider user data to standard OAuthUser - must be implemented per provider */
  protected abstract mapUser(data: Record<string, unknown>): OAuthUser;
}

// ─── Google Provider ──────────────────────────────────────────────────────────

export class GoogleOAuthProvider extends BaseOAuthProvider {
  readonly name = "google";
  protected readonly endpoints: ProviderEndpoints = {
    authorization: "https://accounts.google.com/o/oauth2/v2/auth",
    token: "https://oauth2.googleapis.com/token",
    userInfo: "https://www.googleapis.com/oauth2/v2/userinfo",
  };

  constructor(config: OAuthProviderConfig) {
    super({
      scopes: ["openid", "email", "profile"],
      ...config,
    });
  }

  protected addAuthParams(params: URLSearchParams): void {
    params.set("access_type", "offline");
    params.set("prompt", "consent");
  }

  protected mapUser(data: Record<string, unknown>): OAuthUser {
    return {
      id: data.id as string,
      email: data.email as string | undefined,
      name: data.name as string | undefined,
      avatar: data.picture as string | undefined,
      provider: this.name,
      raw: data,
    };
  }
}

// ─── GitHub Provider ──────────────────────────────────────────────────────────

export class GitHubOAuthProvider extends BaseOAuthProvider {
  readonly name = "github";
  protected readonly endpoints: ProviderEndpoints = {
    authorization: "https://github.com/login/oauth/authorize",
    token: "https://github.com/login/oauth/access_token",
    userInfo: "https://api.github.com/user",
  };

  constructor(config: OAuthProviderConfig) {
    super({
      scopes: ["read:user", "user:email"],
      ...config,
    });
  }

  protected mapUser(data: Record<string, unknown>): OAuthUser {
    return {
      id: String(data.id),
      email: data.email as string | undefined,
      name: (data.name ?? data.login) as string | undefined,
      avatar: data.avatar_url as string | undefined,
      provider: this.name,
      raw: data,
    };
  }

  /** GitHub doesn't always return email in user endpoint */
  protected async fetchUser(accessToken: string): Promise<OAuthUser> {
    const [userResponse, emailResponse] = await Promise.all([
      fetch(this.endpoints.userInfo, {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      }),
      fetch("https://api.github.com/user/emails", {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
      }),
    ]);

    if (!userResponse.ok) {
      throw new MAuthError("Failed to fetch GitHub user info", "OAUTH_ERROR");
    }

    const userData = await userResponse.json() as Record<string, unknown>;
    const user = this.mapUser(userData);

    // Get primary email if not available
    if (!user.email && emailResponse.ok) {
      const emails = await emailResponse.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
      const primary = emails.find((e) => e.primary && e.verified);
      if (primary) user.email = primary.email;
    }

    return user;
  }
}

// ─── Discord Provider ─────────────────────────────────────────────────────────

export class DiscordOAuthProvider extends BaseOAuthProvider {
  readonly name = "discord";
  protected readonly endpoints: ProviderEndpoints = {
    authorization: "https://discord.com/api/oauth2/authorize",
    token: "https://discord.com/api/oauth2/token",
    userInfo: "https://discord.com/api/users/@me",
  };

  constructor(config: OAuthProviderConfig) {
    super({
      scopes: ["identify", "email"],
      ...config,
    });
  }

  protected mapUser(data: Record<string, unknown>): OAuthUser {
    const id = data.id as string;
    const discriminator = data.discriminator as string;
    const avatar = data.avatar as string | null;
    const avatarUrl = avatar
      ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png`
      : `https://cdn.discordapp.com/embed/avatars/${parseInt(discriminator || "0") % 5}.png`;

    return {
      id,
      email: data.email as string | undefined,
      name: data.global_name as string ?? data.username as string,
      avatar: avatarUrl,
      provider: this.name,
      raw: data,
    };
  }
}

// ─── Microsoft Provider ───────────────────────────────────────────────────────

export class MicrosoftOAuthProvider extends BaseOAuthProvider {
  readonly name = "microsoft";
  protected readonly endpoints: ProviderEndpoints = {
    authorization: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    token: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
    userInfo: "https://graph.microsoft.com/v1.0/me",
  };

  constructor(config: OAuthProviderConfig) {
    super({
      scopes: ["openid", "email", "profile", "User.Read"],
      ...config,
    });
  }

  protected addAuthParams(params: URLSearchParams): void {
    params.set("response_mode", "query");
  }

  protected mapUser(data: Record<string, unknown>): OAuthUser {
    return {
      id: data.id as string,
      email: (data.mail ?? data.userPrincipalName) as string | undefined,
      name: data.displayName as string | undefined,
      avatar: undefined, // Microsoft Graph needs separate call for photo
      provider: this.name,
      raw: data,
    };
  }
}

// ─── Apple Provider ───────────────────────────────────────────────────────────

export class AppleOAuthProvider extends BaseOAuthProvider {
  readonly name = "apple";
  protected readonly endpoints: ProviderEndpoints = {
    authorization: "https://appleid.apple.com/auth/authorize",
    token: "https://appleid.apple.com/auth/token",
    userInfo: "", // Apple returns user info in the token
  };

  constructor(config: OAuthProviderConfig) {
    super({
      scopes: ["name", "email"],
      ...config,
    });
  }

  protected addAuthParams(params: URLSearchParams): void {
    params.set("response_mode", "form_post");
  }

  protected mapUser(data: Record<string, unknown>): OAuthUser {
    return {
      id: data.sub as string,
      email: data.email as string | undefined,
      name: undefined, // Apple only sends name on first auth
      avatar: undefined,
      provider: this.name,
      raw: data,
    };
  }

  /** Apple returns user data in the ID token, not a separate endpoint */
  async handleCallback(code: string): Promise<{ tokens: OAuthTokenResponse; user: OAuthUser }> {
    const tokens = await this.exchangeCode(code);

    // Decode the ID token to get user info (without verification for simplicity)
    let userData: Record<string, unknown> = {};
    if (tokens.idToken) {
      try {
        const payloadB64 = tokens.idToken.split(".")[1];
        const decoded = atob(payloadB64.replace(/-/g, "+").replace(/_/g, "/"));
        userData = JSON.parse(decoded);
      } catch {
        // Fallback: use what we have
      }
    }

    const user = this.mapUser(userData);
    return { tokens, user };
  }
}

// ─── Twitter / X Provider ─────────────────────────────────────────────────────

export class TwitterOAuthProvider extends BaseOAuthProvider {
  readonly name = "twitter";
  protected readonly endpoints: ProviderEndpoints = {
    authorization: "https://twitter.com/i/oauth2/authorize",
    token: "https://api.twitter.com/2/oauth2/token",
    userInfo: "https://api.twitter.com/2/users/me",
  };

  constructor(config: OAuthProviderConfig) {
    super({
      scopes: ["users.read", "tweet.read"],
      ...config,
    });
  }

  protected addAuthParams(params: URLSearchParams): void {
    params.set("code_challenge", "challenge");
    params.set("code_challenge_method", "plain");
  }

  protected async fetchUser(accessToken: string): Promise<OAuthUser> {
    const response = await fetch(`${this.endpoints.userInfo}?user.fields=profile_image_url,name,username`, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) {
      throw new MAuthError("Failed to fetch Twitter user info", "OAUTH_ERROR");
    }

    const result = await response.json() as { data: Record<string, unknown> };
    return this.mapUser(result.data);
  }

  protected mapUser(data: Record<string, unknown>): OAuthUser {
    return {
      id: data.id as string,
      email: undefined, // Twitter doesn't provide email via this endpoint
      name: data.name as string | undefined,
      avatar: data.profile_image_url as string | undefined,
      provider: this.name,
      raw: data,
    };
  }
}

// ─── Custom OAuth Provider ────────────────────────────────────────────────────

interface CustomProviderConfig extends OAuthProviderConfig {
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
  userMapping?: (data: Record<string, unknown>) => OAuthUser;
}

export class CustomOAuthProvider extends BaseOAuthProvider {
  readonly name: string;
  protected readonly endpoints: ProviderEndpoints;
  private userMapping?: (data: Record<string, unknown>) => OAuthUser;

  constructor(name: string, config: CustomProviderConfig) {
    super(config);
    this.name = name;
    this.endpoints = {
      authorization: config.authorizationUrl,
      token: config.tokenUrl,
      userInfo: config.userInfoUrl,
    };
    this.userMapping = config.userMapping;
  }

  protected mapUser(data: Record<string, unknown>): OAuthUser {
    if (this.userMapping) {
      return this.userMapping(data);
    }
    return {
      id: (data.id ?? data.sub ?? data.user_id) as string,
      email: (data.email ?? data.mail) as string | undefined,
      name: (data.name ?? data.display_name ?? data.username) as string | undefined,
      avatar: (data.avatar ?? data.picture ?? data.avatar_url) as string | undefined,
      provider: this.name,
      raw: data,
    };
  }
}

// ─── OAuth Manager ────────────────────────────────────────────────────────────

export class OAuthManager {
  private providers = new Map<string, OAuthProvider>();

  /** Register a built-in provider */
  google(config: OAuthProviderConfig): this {
    this.providers.set("google", new GoogleOAuthProvider(config));
    return this;
  }

  github(config: OAuthProviderConfig): this {
    this.providers.set("github", new GitHubOAuthProvider(config));
    return this;
  }

  discord(config: OAuthProviderConfig): this {
    this.providers.set("discord", new DiscordOAuthProvider(config));
    return this;
  }

  microsoft(config: OAuthProviderConfig): this {
    this.providers.set("microsoft", new MicrosoftOAuthProvider(config));
    return this;
  }

  apple(config: OAuthProviderConfig): this {
    this.providers.set("apple", new AppleOAuthProvider(config));
    return this;
  }

  twitter(config: OAuthProviderConfig): this {
    this.providers.set("twitter", new TwitterOAuthProvider(config));
    return this;
  }

  /** Register a custom OAuth provider */
  custom(name: string, config: CustomProviderConfig): this {
    this.providers.set(name, new CustomOAuthProvider(name, config));
    return this;
  }

  /** Get a registered provider */
  provider(name: string): OAuthProvider {
    const p = this.providers.get(name);
    if (!p) {
      throw new MAuthError(`OAuth provider "${name}" is not configured`, "CONFIGURATION_ERROR", 500);
    }
    return p;
  }

  /** Get authorization URL for a provider */
  getAuthUrl(providerName: string, state?: string): string {
    return this.provider(providerName).getAuthorizationUrl(state);
  }

  /** Handle OAuth callback for a provider */
  async handleCallback(providerName: string, code: string): Promise<{ tokens: OAuthTokenResponse; user: OAuthUser }> {
    return this.provider(providerName).handleCallback(code);
  }

  /** List registered provider names */
  get registeredProviders(): string[] {
    return Array.from(this.providers.keys());
  }
}

export type { OAuthProvider, OAuthProviderConfig, OAuthTokenResponse, OAuthUser };

