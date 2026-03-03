# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-07-13

### Added

#### Core Abstractions
- `ICurrentUser` — scoped service exposing `UserId`, `Email`, `DisplayName`, `IsAuthenticated`, `IpAddress`, `Roles`, `Permissions`, `Principal`, `IsInRole()`, `HasPermission()`, `GetProperty<T>()`
- `IUserContextResolver` — interface for custom identity resolution from `HttpContext`
- `UserInfo` record — resolved user identity data passed to `ICurrentUser`; supports an optional `ImmutableDictionary<string, object> Properties` bag for arbitrary per-request data
- `SecurityClaimTypes` — string constants for standard JWT claim types (`sub`, `email`, `name`, `role`, `permission`)
- `UserClaimMapping` — configurable claim-type-to-property mapping used by `ClaimsUserContextResolver`

#### Resolvers
- `ClaimsUserContextResolver` — default resolver that reads identity data directly from JWT claims, respecting `UserClaimMapping`

#### Permission Authorization
- `PermissionRequirement` / `PermissionAuthorizationHandler` — ASP.NET Core `IAuthorizationRequirement` and handler pair for permission-based access control
- `HasPermissionAttribute` — `[Authorize(Policy = "Permission:<name>")]` shorthand (e.g. `[HasPermission("articles.edit")]`); supports multiple attributes (AND semantics)
- `PermissionPolicyProvider` — dynamic `IAuthorizationPolicyProvider` that creates policies on demand from `Permission:` prefixed names; no manual policy registration required

#### Middleware
- `UserContextResolutionMiddleware` — resolves and populates `ICurrentUser` (and `IpAddress`) per request; registered via `app.UseUserContext()`
- `SecurityHeadersMiddleware` — adds OWASP-recommended response headers (`X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, `Permissions-Policy`, `Content-Security-Policy`) and removes `Server` / `X-Powered-By`; registered via `app.UseSecurityHeaders()`

#### Configuration
- `SecurityOptions` — fluent builder with:
  - `AddJwtBearer(Action<JwtOptions>)` — configure JWT bearer authentication
  - `UseResolver<TResolver>()` — register a custom `IUserContextResolver` by generic type
  - `UseResolver(Func<IServiceProvider, IUserContextResolver>)` — register a custom resolver via factory delegate
  - `ConfigureClaimMapping(Action<UserClaimMapping>)` — override the claim type names read by `ClaimsUserContextResolver`
- `JwtOptions` — strongly-typed JWT configuration:
  - `Authority` — OIDC discovery endpoint (mutually exclusive with `SigningKey`)
  - `Issuer` — token issuer; required when using `SigningKey`
  - `Audience` — expected `aud` claim
  - `SigningKey` — symmetric HMAC key for self-hosted JWT (min 32 chars; mutually exclusive with `Authority`)
  - `RequireHttpsMetadata` (default `true`), `ValidateIssuer` (default `true`), `ValidateAudience` (default `true`), `ValidateLifetime` (default `true`)
  - `MapInboundClaims` (default `false`) — disables WS-Federation claim type mapping
  - `ClockSkew` (default 1 minute) — tolerance for token expiry
  - `TokenCookieName` — read bearer token from an `HttpOnly` / `Secure` cookie (for SignalR WebSockets / SSE)
  - `TokenQueryParameter` — fallback: read bearer token from a query string parameter when cookie is absent

#### DI & Pipeline Helpers
- `ServiceCollectionExtensions.AddSecurity()` — single entry point for all DI registrations
- `ApplicationBuilderExtensions.UseUserContext()` / `UseSecurityHeaders()` — middleware pipeline extension methods
