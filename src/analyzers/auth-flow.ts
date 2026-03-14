import type { ScannedFile } from "../types.js";

/**
 * Auth Flow Analyzer
 *
 * Detects standard authentication and token management patterns:
 * - OAuth2 token refresh flows
 * - API key/token configuration loading
 * - JWT token creation/verification
 * - Session management
 *
 * When detected, the file is flagged as containing legitimate auth logic,
 * which helps reduce false positives in data-exfil, env-leak, etc.
 */

// ─── Auth flow patterns ───

/** Token/credential management patterns (getting, refreshing, validating tokens) */
const TOKEN_MANAGEMENT_RE =
  /getToken|refreshToken|accessToken|tokenRefresh|renewToken|rotateToken|revokeToken|validateToken|verifyToken|isTokenExpired|tokenExpir|authToken|bearerToken|idToken|oauthToken/i;

/** OAuth2 flow patterns */
const OAUTH_FLOW_RE =
  /oauth2?|authorization_code|client_credentials|grant_type|redirect_uri|auth_code|pkce|code_verifier|code_challenge|token_endpoint|authorize_endpoint|openid|oidc/i;

/** JWT patterns */
const JWT_RE =
  /jwt\.(sign|verify|decode)|jsonwebtoken|jose\.|JWTPayload|JwtHeader|signJwt|verifyJwt|createJwt|parseJwt/i;

/** Session management patterns */
const SESSION_RE =
  /createSession|destroySession|sessionToken|sessionId|session\.save|session\.regenerate|session\.destroy|passport\.(authenticate|initialize|session)/i;

/** API key loading / config patterns */
const API_KEY_CONFIG_RE =
  /apiKey\s*[=:]\s*(process\.env|config|options|params|settings)\b|\.apiKey\s*\|\||loadCredentials|getCredentials|credentialStore|keyVault|secretManager/i;

/** Auth middleware patterns */
const AUTH_MIDDLEWARE_RE =
  /authMiddleware|isAuthenticated|requireAuth|checkAuth|verifyAuth|authenticateRequest|authGuard|canActivate|@UseGuards|@Authorized|@RequiresAuth/i;

/** Header-based auth patterns */
const AUTH_HEADER_RE =
  /['"](Authorization|X-API-Key|X-Auth-Token|Bearer|Basic)\s*['"]|headers\s*\[\s*['"]Authorization|setAuthHeader|addAuthHeader/i;

// ─── Analysis result ───

export interface AuthFlowResult {
  /** True if the file contains legitimate auth flow patterns */
  hasAuthFlow: boolean;
  /** Specific patterns detected */
  patterns: string[];
  /** Overall confidence that this is legitimate auth code */
  confidence: "high" | "medium" | "low";
}

/**
 * Analyze a file for authentication flow patterns.
 * Returns info about detected auth patterns.
 */
export function analyzeAuthFlow(file: ScannedFile): AuthFlowResult {
  const content = file.content;
  const patterns: string[] = [];

  if (TOKEN_MANAGEMENT_RE.test(content)) patterns.push("token-management");
  if (OAUTH_FLOW_RE.test(content)) patterns.push("oauth-flow");
  if (JWT_RE.test(content)) patterns.push("jwt");
  if (SESSION_RE.test(content)) patterns.push("session-management");
  if (API_KEY_CONFIG_RE.test(content)) patterns.push("api-key-config");
  if (AUTH_MIDDLEWARE_RE.test(content)) patterns.push("auth-middleware");
  if (AUTH_HEADER_RE.test(content)) patterns.push("auth-header");

  const hasAuthFlow = patterns.length > 0;

  // Confidence: multiple auth patterns = high, single = medium
  let confidence: "high" | "medium" | "low" = "low";
  if (patterns.length >= 3) confidence = "high";
  else if (patterns.length >= 1) confidence = "medium";

  return { hasAuthFlow, patterns, confidence };
}

/**
 * Check if a specific line is part of an auth flow.
 * More granular check for individual lines.
 */
export function isAuthFlowLine(line: string): boolean {
  return (
    TOKEN_MANAGEMENT_RE.test(line) ||
    OAUTH_FLOW_RE.test(line) ||
    JWT_RE.test(line) ||
    SESSION_RE.test(line) ||
    API_KEY_CONFIG_RE.test(line) ||
    AUTH_MIDDLEWARE_RE.test(line) ||
    AUTH_HEADER_RE.test(line)
  );
}
