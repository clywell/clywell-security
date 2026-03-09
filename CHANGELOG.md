# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-03-09

### Added

- `JwtBearerBuilder.WithSigningKey(SecurityKey, issuer, audience?)` — validates self-hosted JWTs signed with any pre-built `SecurityKey` (RSA, ECDSA, etc.); pass the public key derived from your signing key pair. Recommended for production asymmetric JWT issuers.

### Changed

- `JwtBearerBuilder` now automatically sets `TokenValidationParameters.NameClaimType` and `RoleClaimType` from the registered `UserClaimMapping`, ensuring that `ICurrentUser.Roles`, `ClaimsIdentity.RoleClaimType`, and role-based policy checks (`RequireRole`) all use the same claim type as the rest of the security package.

## [1.1.0] - 2026-03-07

### Added

#### Security Headers
- `SecurityHeadersOptions` — configuration model for `SecurityHeadersMiddleware` with sensible OWASP defaults; exposes `ContentTypeOptions`, `FrameOptions`, `ReferrerPolicy`, `PermissionsPolicy` as settable strings (set to `null` to suppress a header)
- `CspBuilder` — fluent builder for `Content-Security-Policy` values; supports `Default`, `Script`, `Style`, `Image`, `Font`, `Connect`, `FrameAncestors`, `Media`, `Object`, `Worker`, `FormAction` directives
- `SecurityHeadersOptions.WithContentSecurityPolicy(string?)` — set a raw CSP string
- `SecurityHeadersOptions.WithContentSecurityPolicy(Action<CspBuilder>)` — configure CSP fluently
- `SecurityHeadersOptions.AddRouteContentSecurityPolicy(string, string)` / `AddRouteContentSecurityPolicy(string, Action<CspBuilder>)` — register path-prefix-scoped CSP overrides (first matching prefix wins)
- `SecurityHeadersOptions.AddHeader(name, value)` — inject arbitrary response headers
- `SecurityHeadersOptions.RemoveHeader(name)` — strip additional response headers beyond `Server` / `X-Powered-By`
- `UseSecurityHeaders(Action<SecurityHeadersOptions>?)` overload — optional configuration action; calling with no arguments preserves the existing default behaviour

### Changed
- `UseSecurityHeaders()` — now accepts an optional `Action<SecurityHeadersOptions>` parameter; existing zero-argument call sites continue to work without modification

### Removed
- `SecurityHeadersMiddleware` no longer takes `IWebHostEnvironment` as a constructor parameter

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
