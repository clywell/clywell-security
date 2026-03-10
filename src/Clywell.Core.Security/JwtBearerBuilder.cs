using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Clywell.Core.Security;

/// <summary>
/// Fluent builder for configuring JWT bearer authentication.
/// Start with <see cref="WithOidcProvider"/> or <see cref="WithSymmetricKey"/>,
/// then optionally chain token-transport and advanced methods.
/// </summary>
public sealed class JwtBearerBuilder
{
    private string? _authority;
    private string? _signingKey;
    private SecurityKey? _securityKey;
    private Func<IServiceProvider, SecurityKey>? _signingKeyFactory;
    private Func<IServiceProvider, string>? _issuerFactory;
    private Func<IServiceProvider, string>? _audienceFactory;
    private string? _issuer;
    private string? _audience;
    private bool _requireHttpsMetadata = true;
    private bool _validateIssuer = true;
    private bool _validateAudience = true;
    private bool _validateLifetime = true;
    private bool _mapInboundClaims;
    private TimeSpan _clockSkew = TimeSpan.FromMinutes(1);
    private string? _tokenCookieName;
    private string? _tokenQueryParameter;

    internal JwtBearerBuilder() { }

    // -------------------------------------------------------------------------
    // Identity source — pick one
    // -------------------------------------------------------------------------

    /// <summary>
    /// Validate JWTs issued by an external OIDC identity provider (Auth0, Azure AD, Keycloak, etc.).
    /// Signing keys are discovered automatically from the provider's OIDC discovery endpoint.
    /// </summary>
    /// <param name="authority">OIDC discovery base URL (e.g. "https://login.example.com").</param>
    /// <param name="audience">Expected audience claim. Pass <c>null</c> to skip audience validation.</param>
    public JwtBearerBuilder WithOidcProvider(string authority, string? audience = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        _authority = authority;
        if (audience is not null) _audience = audience;
        return this;
    }

    /// <summary>
    /// Validate JWTs signed with a local symmetric HMAC key — for services that issue their own tokens
    /// without an external OIDC provider.
    /// </summary>
    /// <param name="signingKey">Symmetric signing key. Must be at least 32 characters.</param>
    /// <param name="issuer">The issuer value your service embeds in issued tokens.</param>
    /// <param name="audience">Expected audience claim. Pass <c>null</c> to skip audience validation.</param>
    public JwtBearerBuilder WithSymmetricKey(string signingKey, string issuer, string? audience = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        if (signingKey.Length < 32)
            throw new ArgumentException(
                "SigningKey must be at least 32 characters for adequate security.", nameof(signingKey));

        _signingKey = signingKey;
        _issuer = issuer;
        if (audience is not null) _audience = audience;
        return this;
    }

    /// <summary>
    /// Validate JWTs signed with a pre-built <see cref="SecurityKey"/> - use this for self-hosted
    /// JWT issuers using asymmetric keys (RSA, ECDSA) where you supply the public key directly.
    /// </summary>
    /// <param name="signingKey">The public key used to verify token signatures (e.g. <see cref="RsaSecurityKey"/>).</param>
    /// <param name="issuer">The issuer value your service embeds in issued tokens.</param>
    /// <param name="audience">Expected audience claim. Pass <c>null</c> to skip audience validation.</param>
    public JwtBearerBuilder WithSigningKey(SecurityKey signingKey, string issuer, string? audience = null)
    {
        ArgumentNullException.ThrowIfNull(signingKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        _securityKey = signingKey;
        _issuer = issuer;
        if (audience is not null) _audience = audience;
        return this;
    }

    /// <summary>
    /// Validate JWTs signed with a key that is resolved lazily at options-resolution time via a factory.
    /// The <paramref name="keyFactory"/> receives the application's <see cref="IServiceProvider"/>
    /// and must return the <see cref="SecurityKey"/> used to verify token signatures.
    /// The <paramref name="issuerFactory"/> resolves the expected issuer value in the same way.
    /// <para>
    /// Use this overload when the key or issuer is not available at service-registration time -
    /// for example, when the value comes from configuration that may be overridden by
    /// <c>WebApplicationFactory</c> in integration tests, or from a key vault loaded asynchronously.
    /// </para>
    /// </summary>
    /// <param name="keyFactory">Factory that produces the signing key. Resolved once from the root <see cref="IServiceProvider"/>.</param>
    /// <param name="issuerFactory">Factory that produces the expected token issuer.</param>
    /// <param name="audienceFactory">Optional factory that produces the expected audience. Omit to skip audience validation.</param>
    public JwtBearerBuilder WithSigningKey(
        Func<IServiceProvider, SecurityKey> keyFactory,
        Func<IServiceProvider, string> issuerFactory,
        Func<IServiceProvider, string>? audienceFactory = null)
    {
        ArgumentNullException.ThrowIfNull(keyFactory);
        ArgumentNullException.ThrowIfNull(issuerFactory);
        _signingKeyFactory = keyFactory;
        _issuerFactory = issuerFactory;
        _audienceFactory = audienceFactory;
        return this;
    }

    // -------------------------------------------------------------------------
    // Token transport — for clients that cannot send Authorization headers
    // -------------------------------------------------------------------------

    /// <summary>
    /// Read the bearer token from an <c>HttpOnly</c> Secure cookie.
    /// Intended for SignalR WebSocket and SSE connections. Takes priority over
    /// <see cref="WithTokenQueryParam"/> when both are configured.
    /// </summary>
    public JwtBearerBuilder WithTokenCookie(string cookieName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cookieName);
        _tokenCookieName = cookieName;
        return this;
    }

    /// <summary>
    /// Read the bearer token from a query string parameter as a fallback when the cookie
    /// configured via <see cref="WithTokenCookie"/> is absent from the request.
    /// Prefer cookies over query parameters — query string tokens may appear in server logs.
    /// </summary>
    public JwtBearerBuilder WithTokenQueryParam(string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(parameterName);
        _tokenQueryParameter = parameterName;
        return this;
    }

    // -------------------------------------------------------------------------
    // Advanced settings
    // -------------------------------------------------------------------------

    /// <summary>Disable the HTTPS requirement for OIDC metadata discovery. Never use in production.</summary>
    public JwtBearerBuilder DisableHttpsMetadataRequirement()
    {
        _requireHttpsMetadata = false;
        return this;
    }

    /// <summary>Skip validation of the <c>iss</c> claim.</summary>
    public JwtBearerBuilder DisableIssuerValidation()
    {
        _validateIssuer = false;
        return this;
    }

    /// <summary>Skip validation of the <c>aud</c> claim.</summary>
    public JwtBearerBuilder DisableAudienceValidation()
    {
        _validateAudience = false;
        return this;
    }

    /// <summary>Skip validation of token expiry. Never use in production.</summary>
    public JwtBearerBuilder DisableLifetimeValidation()
    {
        _validateLifetime = false;
        return this;
    }

    /// <summary>Override the clock skew tolerance for token expiry. Default is 1 minute.</summary>
    public JwtBearerBuilder WithClockSkew(TimeSpan skew)
    {
        _clockSkew = skew;
        return this;
    }

    /// <summary>
    /// Keep the original WS-Federation/SOAP claim type URIs instead of mapping them to short JWT names.
    /// Only needed when consuming tokens from legacy WS-Federation providers.
    /// </summary>
    public JwtBearerBuilder PreserveInboundClaimTypes()
    {
        _mapInboundClaims = true;
        return this;
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    internal void Apply(IServiceCollection services, UserClaimMapping claimMapping)
    {
        if (string.IsNullOrEmpty(_authority) && string.IsNullOrEmpty(_signingKey) && _securityKey is null && _signingKeyFactory is null)
            throw new InvalidOperationException(
                "Call WithOidcProvider(), WithSymmetricKey(), or WithSigningKey() to configure JWT bearer authentication.");

        var authority = _authority;
        var signingKey = _signingKey;
        var securityKey = _securityKey;
        var issuer = _issuer;
        var audience = _audience;
        var requireHttps = _requireHttpsMetadata;
        var validateIssuer = _validateIssuer;
        var validateAudience = _validateAudience;
        var validateLifetime = _validateLifetime;
        var mapInboundClaims = _mapInboundClaims;
        var clockSkew = _clockSkew;
        var cookieName = _tokenCookieName;
        var queryParam = _tokenQueryParameter;

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.Authority = authority;
                options.Audience = audience;
                options.RequireHttpsMetadata = requireHttps;
                options.MapInboundClaims = mapInboundClaims;

                options.TokenValidationParameters.ValidateIssuer = validateIssuer;
                options.TokenValidationParameters.ValidateAudience = validateAudience;
                options.TokenValidationParameters.ValidateLifetime = validateLifetime;
                options.TokenValidationParameters.ClockSkew = clockSkew;
                options.TokenValidationParameters.NameClaimType = claimMapping.UserId;
                options.TokenValidationParameters.RoleClaimType = claimMapping.Roles;

                if (securityKey is not null)
                    options.TokenValidationParameters.IssuerSigningKey = securityKey;
                else if (!string.IsNullOrEmpty(signingKey))
                    options.TokenValidationParameters.IssuerSigningKey =
                        new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(signingKey));

                if (!string.IsNullOrEmpty(issuer))
                    options.TokenValidationParameters.ValidIssuer = issuer;

                if (!string.IsNullOrEmpty(cookieName) || !string.IsNullOrEmpty(queryParam))
                {
                    var existingHandler = options.Events?.OnMessageReceived;
                    options.Events = new JwtBearerEvents
                    {
                        OnMessageReceived = async ctx =>
                        {
                            // Cookie takes priority — more secure than query string
                            if (!string.IsNullOrEmpty(cookieName) &&
                                ctx.Request.Cookies.TryGetValue(cookieName, out var cookieToken) &&
                                !string.IsNullOrEmpty(cookieToken))
                            {
                                ctx.Token = cookieToken;
                            }
                            else if (!string.IsNullOrEmpty(queryParam) &&
                                ctx.Request.Query.TryGetValue(queryParam, out var queryToken) &&
                                !string.IsNullOrEmpty(queryToken))
                            {
                                ctx.Token = queryToken;
                            }

                            if (existingHandler is not null)
                                await existingHandler(ctx);
                        }
                    };
                }
            });

        // Factory-based key loading — runs at options-resolution time (after host build),
        // ensuring WebApplicationFactory test overrides from ConfigureWebHost are respected.
        // The consumer owns how the key and issuer are obtained (configuration, secrets, vault, etc.).
        if (_signingKeyFactory is not null)
        {
            var keyFactory = _signingKeyFactory;
            var issuerFactory = _issuerFactory!;
            var audienceFactory = _audienceFactory;

            services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme)
                .Configure<IServiceProvider>((opts, sp) =>
                {
                    opts.TokenValidationParameters.IssuerSigningKey = keyFactory(sp);
                    opts.TokenValidationParameters.ValidIssuer = issuerFactory(sp);

                    if (validateAudience && audienceFactory is not null)
                        opts.TokenValidationParameters.ValidAudience = audienceFactory(sp);
                });
        }
    }
}
