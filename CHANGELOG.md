# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/). This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.0.1] - 2026-04-18

### Changed

#### `Clywell.Core.Security`
- Bumped `Microsoft.AspNetCore.Authentication.JwtBearer` from `10.0.5` to `10.0.6`
- Bumped `Microsoft.SourceLink.GitHub` from `10.0.201` to `10.0.202`

#### `Clywell.Core.Security.Tests`
- Bumped `Microsoft.AspNetCore.TestHost` from `10.0.5` to `10.0.6`
- Bumped `Microsoft.NET.Test.Sdk` from `18.3.0` to `18.4.0`
- Bumped `coverlet.collector` from `8.0.0` to `10.0.0`

## [2.0.0] - 2026-04-03

### Removed

#### `Clywell.Core.Security`
- `PermissionPolicyProvider` — dynamic `IAuthorizationPolicyProvider` removed; permission policies are now registered statically via `UsePermissionAuthorization(IEnumerable<string>)`
- `PermissionRequirement` — no longer needed; policies use `RequireClaim` directly
- `PermissionAuthorizationHandler` — no longer needed; policies use `RequireClaim` directly

### Changed

#### `Clywell.Core.Security`
- `SecurityOptions.UsePermissionAuthorization(IEnumerable<string> permissionCodes)` — now requires the consumer to supply permission codes explicitly; each code is registered as a `Permission:<code>` policy that checks the configured permission claim type via `RequireClaim`
- `SecurityOptions.UseStepUpAuthorization()` — step-up authorization handler and validator are now opt-in (previously registered by default)
- `AddSecurity()` no longer calls `AddAuthorizationCore()` or replaces `IAuthorizationPolicyProvider` when permission authorization is enabled — uses `PostConfigure<AuthorizationOptions>` instead, avoiding registration conflicts

## [1.5.1] - 2026-03-20

### Removed

#### `Clywell.Core.Security`
- `AcrValues` — removed from this package; ACR value constants are domain concepts and should be defined in each service's own domain layer to avoid pulling the security package into the application/domain tier

## [1.5.0] - 2026-03-20

### Added

#### `Clywell.Core.Security`
- `StepUpRequirement` — `IAuthorizationRequirement` that mandates the bearer token was issued via step-up authentication (`acr = "step-up"`); accepts an optional `RequiredOperationContext` string to further scope the requirement to a specific operation
- `StepUpAuthorizationHandler` — `AuthorizationHandler<StepUpRequirement>` that delegates to `IStepUpProofValidator`; succeeds only when the `X-Step-Up-Proof` header carries a valid proof token with `acr=step-up` and, when required, a matching `operation_context`; registered automatically via `AddSecurity`
- `EndpointConventionBuilderExtensions.RequireStepUp<TBuilder>(string? requiredOperationContext = null)` — minimal API / controller extension that builds an inline authorization policy requiring an authenticated user with a step-up token; optionally scopes the requirement to a named operation context
- `ICurrentUser.Acr` — exposes the `acr` claim from the bearer token; value is `"step-up"` for tokens issued via step-up authentication
- `ICurrentUser.OperationContext` — exposes the `operation_context` claim from step-up tokens
- `SecurityClaimTypes.Acr` (`"acr"`) and `SecurityClaimTypes.OperationContext` (`"operation_context"`) — claim type constants for the new step-up claims
- `SecurityHeaderNames` — static class of HTTP header name constants; currently defines `StepUpProof` (`"X-Step-Up-Proof"`) for use when setting the step-up proof header on requests
- `StepUpProofValidationResult` — enum describing the outcome of validating an `X-Step-Up-Proof` header token: `Valid`, `Missing`, `Invalid`, `ContextMismatch`, `Expired`
- `IStepUpProofValidator` — interface for validating the `X-Step-Up-Proof` request header; use in command handlers for runtime/dynamic step-up requirements
- `StepUpProofValidator` — default implementation; reads `X-Step-Up-Proof`, validates the JWT using the configured bearer `TokenValidationParameters`, checks `acr == "step-up"` and optionally `operation_context`

## [1.4.1] - 2026-03-16

### Added

#### `Clywell.Core.Security`
- `EndpointConventionBuilderExtensions.RequirePermission<TBuilder>(string permissionCode)` — minimal API extension method that calls `.RequireAuthorization("Permission:<permissionCode>")` using the existing `PermissionPolicyProvider` dynamic policy resolution; eliminates boilerplate string concatenation at call sites

### Removed

#### `Clywell.Core.Security`
- `PermissionDefinition` — removed from this package; consumers that need a structured permission type should define it in their own domain layer to avoid pulling the security package into the application/domain tier

## [1.4.0] - 2026-03-15

### Added

#### `Clywell.Core.Security`
- `PermissionDefinition` — readonly record struct that represents a permission with `Code`, `Name`, `Description`, and `Category` properties; includes an implicit conversion to `string` (returns `Code`) for backward compatibility with APIs that accept raw permission code strings

## [1.3.1] - 2026-03-15

### Changed
- updated `Microsoft.AspNetCore.Authentication.JwtBearer` to `10.0.5` (from `10.0.4`)
- updated `Microsoft.AspNetCore.TestHost` to `10.0.5` (from `10.0.3`)

## [1.3.0] - 2026-03-10

### Added

#### `Clywell.Core.Security`
- `JwtBearerBuilder.WithSigningKey(Func<IServiceProvider, SecurityKey> keyFactory, Func<IServiceProvider, string> issuerFactory, Func<IServiceProvider, string>? audienceFactory = null)` — factory overload of `WithSigningKey`; resolves the signing key and issuer lazily at options-resolution time via delegates that receive the application's `IServiceProvider`; use this when the key or issuer is unavailable at service-registration time (e.g. configuration overridden by `WebApplicationFactory` in integration tests, or keys loaded from a vault asynchronously)

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

## [1.0.0] - 2026-03-03

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

[Unreleased]: https://github.com/clywell/clywell-security/compare/v1.5.1...HEAD
[1.5.1]: https://github.com/clywell/clywell-security/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/clywell/clywell-security/compare/v1.4.1...v1.5.0
[1.4.1]: https://github.com/clywell/clywell-security/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/clywell/clywell-security/compare/v1.3.1...v1.4.0
[1.3.1]: https://github.com/clywell/clywell-security/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/clywell/clywell-security/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/clywell/clywell-security/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/clywell/clywell-security/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/clywell/clywell-security/releases/tag/v1.0.0
