# Clywell.Core.Security

Security primitives for .NET — JWT bearer configuration, user context resolution, permission-based authorization, and security headers middleware.

[![NuGet](https://img.shields.io/nuget/v/Clywell.Core.Security.svg)](https://www.nuget.org/packages/Clywell.Core.Security)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Installation

```bash
dotnet add package Clywell.Core.Security
```

## Table of Contents

- [Quick Start](#quick-start)
- [JWT Authentication](#jwt-authentication)
  - [OIDC / External Identity Provider](#oidc--external-identity-provider)
  - [Self-Hosted JWT (Symmetric Key)](#self-hosted-jwt-symmetric-key)
  - [Token from Cookie or Query String](#token-from-cookie-or-query-string)
- [Current User](#current-user)
- [Permission-Based Authorization](#permission-based-authorization)
- [Custom User Context Resolver](#custom-user-context-resolver)
  - [Type-Parameter Registration](#type-parameter-registration)
  - [Factory Registration](#factory-registration)
- [Custom Claim Mapping](#custom-claim-mapping)
- [Security Headers](#security-headers)
- [API Reference](#api-reference)
- [Dependencies](#dependencies)

---

## Quick Start

### 1. Register services

```csharp
builder.Services.AddSecurity(options =>
{
    options.AddJwtBearer()
           .WithOidcProvider("https://your-identity-provider.com", audience: "your-api");
});
```

### 2. Configure the middleware pipeline

```csharp
app.UseAuthentication();
app.UseUserContext();      // Populates ICurrentUser from the resolved identity
app.UseAuthorization();
app.UseSecurityHeaders();  // Adds OWASP-recommended response headers
```

### 3. Inject `ICurrentUser`

```csharp
public class MyService(ICurrentUser currentUser)
{
    public void DoWork()
    {
        if (!currentUser.IsAuthenticated)
            return;

        Console.WriteLine(currentUser.UserId);
        Console.WriteLine(currentUser.Email);
        Console.WriteLine(currentUser.IpAddress);

        if (currentUser.IsInRole("Admin")) { /* ... */ }
        if (currentUser.HasPermission("articles.edit")) { /* ... */ }
    }
}
```

---

## JWT Authentication

`AddJwtBearer()` returns a `JwtBearerBuilder`. Pick your token source first, then optionally chain transport and advanced settings.

### OIDC / External Identity Provider

Use `WithOidcProvider` when tokens are issued by an external provider (Auth0, Azure AD, Keycloak, etc.). Signing keys are discovered automatically.

```csharp
options.AddJwtBearer()
       .WithOidcProvider("https://login.example.com", audience: "my-api");
```

Advanced settings chain naturally:

```csharp
options.AddJwtBearer()
       .WithOidcProvider("https://login.example.com", audience: "my-api")
       .WithClockSkew(TimeSpan.FromSeconds(30))
       .DisableAudienceValidation();  // only if your IdP omits aud
```

### Self-Hosted JWT (Symmetric Key)

Use `WithSymmetricKey` when your own service issues JWTs with no external OIDC provider.

> **Security:** The signing key must be at least 32 characters. Read it from a secret manager or environment variable — never hard-code it.

```csharp
options.AddJwtBearer()
       .WithSymmetricKey(
           signingKey: builder.Configuration["Jwt:SigningKey"], // min 32 chars
           issuer:     "https://my-service.example.com",
           audience:   "my-api");
```

### Token from Cookie or Query String

For transports that cannot send an `Authorization` header (SignalR WebSockets, SSE), chain `WithTokenCookie` and/or `WithTokenQueryParam`. Cookie takes priority over query string when both are present.

> **Security:** The cookie should be `HttpOnly` and `Secure`. Query string tokens may appear in server logs — prefer cookies where possible.

```csharp
options.AddJwtBearer()
       .WithOidcProvider("https://login.example.com", audience: "my-api")
       .WithTokenCookie("access_token")      // HttpOnly, Secure cookie
       .WithTokenQueryParam("access_token"); // fallback when cookie absent
```

---

## Current User

`ICurrentUser` is a scoped service populated per-request by `UseUserContext()`. It exposes:

| Member | Type | Description |
|--------|------|-------------|
| `UserId` | `string?` | Primary subject identifier (`sub` claim by default) |
| `Email` | `string?` | User email address |
| `DisplayName` | `string?` | Display / full name |
| `IsAuthenticated` | `bool` | `true` when a valid identity was resolved |
| `IpAddress` | `string?` | Remote IP from `HttpContext.Connection` |
| `Roles` | `IReadOnlySet<string>` | Case-insensitive role set |
| `Permissions` | `IReadOnlySet<string>` | Case-insensitive permission set |
| `Principal` | `ClaimsPrincipal?` | Underlying ASP.NET Core principal |
| `IsInRole(role)` | `bool` | Role membership check |
| `HasPermission(perm)` | `bool` | Permission check |
| `GetProperty<T>(key)` | `T?` | Read a custom property stored in `UserInfo.Properties` |

### Custom properties on `UserInfo`

`UserInfo` accepts an optional `ImmutableDictionary<string, object>` for arbitrary per-request data (e.g. tenant metadata resolved from the token). Access it via `GetProperty<T>()`:

```csharp
var userInfo = new UserInfo(
    userId,
    email,
    displayName,
    roles,
    permissions,
    Properties: ImmutableDictionary<string, object>.Empty
        .Add("tenantId", "tenant-abc")
        .Add("plan", "pro"));

// Later, in any service:
var tenantId = currentUser.GetProperty<string>("tenantId");
```

---

## Permission-Based Authorization

Decorate controllers or actions with `[HasPermission]`. Multiple attributes require **all** permissions (AND semantics).

```csharp
[HasPermission("articles.edit")]
public IActionResult EditArticle(int id) { ... }

[HasPermission("articles.delete")]
[HasPermission("articles.edit")]   // user must have BOTH
public IActionResult DeleteArticle(int id) { ... }
```

Policies are resolved dynamically by `PermissionPolicyProvider` — no manual policy registration required.

---

## Custom User Context Resolver

The default `ClaimsUserContextResolver` reads identity data straight from JWT claims. To load roles or permissions from a database (or any other source), implement `IUserContextResolver`.

### Type-Parameter Registration

```csharp
public class DatabaseUserContextResolver(
    IUserRepository userRepo) : IUserContextResolver
{
    public async Task<UserInfo?> ResolveAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true)
            return null;

        var userId = context.User.FindFirstValue("sub");
        if (userId is null) return null;

        var user = await userRepo.GetByIdAsync(userId);
        if (user is null) return null;

        return new UserInfo(
            userId,
            user.Email,
            user.DisplayName,
            user.Roles.ToHashSet(),
            user.Permissions.ToHashSet());
    }
}

// Registration
builder.Services.AddSecurity(options =>
    options.UseResolver<DatabaseUserContextResolver>());
```

### Factory Registration

Use the factory overload when the resolver depends on services not available at configuration time:

```csharp
builder.Services.AddSecurity(options =>
    options.UseResolver(sp =>
    {
        var repo = sp.GetRequiredService<IUserRepository>();
        return new DatabaseUserContextResolver(repo);
    }));
```

---

## Custom Claim Mapping

`ClaimsUserContextResolver` reads claims using the names defined in `UserClaimMapping`. Override any of them via `ConfigureClaimMapping()` if your identity provider uses non-standard claim types:

```csharp
builder.Services.AddSecurity(options =>
{
    options.AddJwtBearer(jwt => { /* ... */ });

    options.ConfigureClaimMapping(mapping =>
    {
        mapping.UserId      = "oid";              // Azure AD object ID
        mapping.Email       = "preferred_username";
        mapping.DisplayName = "name";             // default — shown for clarity
        mapping.Roles       = "roles";            // Azure AD app roles
        mapping.Permissions = "scp";              // OAuth 2 scopes as permissions
    });
});
```

**Default claim type mapping:**

| Property | Default claim type |
|----------|--------------------|
| `UserId` | `sub` |
| `Email` | `email` |
| `DisplayName` | `name` |
| `Roles` | `role` |
| `Permissions` | `permission` |

---

## Security Headers

`UseSecurityHeaders()` adds the following response headers and strips server-identifying headers:

| Header | Value |
|--------|-------|
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |
| `Permissions-Policy` | Disables accelerometer, camera, geolocation, gyroscope, magnetometer, microphone, USB |
| `Content-Security-Policy` | `default-src 'self'; frame-ancestors 'none'` |

---

## API Reference

### `SecurityOptions`

| Method | Description |
|--------|-------------|
| `AddJwtBearer()` | Returns a `JwtBearerBuilder` to configure JWT bearer authentication |
| `UseResolver<TResolver>()` | Register a custom `IUserContextResolver` by type |
| `UseResolver(Func<IServiceProvider, IUserContextResolver>)` | Register a custom resolver via factory |
| `ConfigureClaimMapping(Action<UserClaimMapping>)` | Override claim type names read by `ClaimsUserContextResolver` |

### `JwtBearerBuilder`

| Method | Description |
|--------|-------------|
| `WithOidcProvider(authority, audience?)` | Validate tokens from an external OIDC provider |
| `WithSymmetricKey(signingKey, issuer, audience?)` | Validate locally-issued tokens with a symmetric key |
| `WithTokenCookie(cookieName)` | Read bearer token from an `HttpOnly` cookie (SignalR / SSE) |
| `WithTokenQueryParam(parameterName)` | Fallback: read bearer token from a query string parameter |
| `DisableHttpsMetadataRequirement()` | Allow HTTP for OIDC discovery. **Never in production.** |
| `DisableIssuerValidation()` | Skip `iss` claim validation |
| `DisableAudienceValidation()` | Skip `aud` claim validation |
| `DisableLifetimeValidation()` | Skip token expiry check. **Never in production.** |
| `WithClockSkew(TimeSpan)` | Override clock skew tolerance (default: 1 minute) |
| `PreserveInboundClaimTypes()` | Keep WS-Federation claim type URIs instead of mapping to short names |

### `ICurrentUser`

Scoped service available after `UseUserContext()` runs in the pipeline. See the [Current User](#current-user) section for the full member table.

### `UserInfo`

```csharp
public sealed record UserInfo(
    string UserId,
    string? Email = null,
    string? DisplayName = null,
    IReadOnlySet<string>? Roles = null,
    IReadOnlySet<string>? Permissions = null,
    ImmutableDictionary<string, object>? Properties = null);
```

Returned by `IUserContextResolver.ResolveAsync()` to describe the resolved identity for the current request.

### `SecurityClaimTypes`

Constants for common JWT claim type names:

```csharp
SecurityClaimTypes.Subject    // "sub"
SecurityClaimTypes.Email      // "email"
SecurityClaimTypes.Name       // "name"
SecurityClaimTypes.Role       // "role"
SecurityClaimTypes.Permission // "permission"
```

---

## Dependencies

- `Microsoft.AspNetCore.App` (framework reference — no extra NuGet download)
- [`Microsoft.AspNetCore.Authentication.JwtBearer`](https://www.nuget.org/packages/Microsoft.AspNetCore.Authentication.JwtBearer)

---

## License

MIT — see [LICENSE](LICENSE).
