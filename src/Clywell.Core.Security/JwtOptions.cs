namespace Clywell.Core.Security;

/// <summary>Superseded by <see cref="JwtBearerBuilder"/>. Kept for reference only.</summary>
internal sealed class JwtOptions
{
    /// <summary>OIDC discovery endpoint (e.g. "https://auth.example.com"). Mutually exclusive with <see cref="SigningKey"/>.</summary>
    public string? Authority { get; set; }

    /// <summary>Issuer to accept. Required when using <see cref="SigningKey"/> (self-hosted JWT).</summary>
    public string? Issuer { get; set; }

    public string? Audience { get; set; }

    /// <summary>
    /// Symmetric HMAC signing key for self-hosted JWT scenarios. When set, OIDC discovery is not used.
    /// Must be at least 32 characters to satisfy HMAC-SHA256 minimum key strength.
    /// </summary>
    public string? SigningKey { get; set; }

    public bool RequireHttpsMetadata { get; set; } = true;
    public bool ValidateIssuer { get; set; } = true;
    public bool ValidateAudience { get; set; } = true;
    public bool ValidateLifetime { get; set; } = true;
    public bool MapInboundClaims { get; set; }
    public TimeSpan ClockSkew { get; set; } = TimeSpan.FromMinutes(1);

    /// <summary>
    /// Name of the HTTP cookie from which to read the bearer token.
    /// Intended for transports that cannot send Authorization headers (SignalR WebSockets, SSE).
    /// The cookie should be set as HttpOnly and Secure. Takes priority over <see cref="TokenQueryParameter"/>.
    /// </summary>
    public string? TokenCookieName { get; set; }

    /// <summary>
    /// Query string parameter name from which to read the bearer token, used as a fallback
    /// when <see cref="TokenCookieName"/> is configured but absent from the request.
    /// Less secure than cookies — prefer <see cref="TokenCookieName"/> where possible.
    /// </summary>
    public string? TokenQueryParameter { get; set; }
}
