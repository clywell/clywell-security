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

    /// <summary>
    /// Validate JWTs issued by an external OIDC identity provider (Auth0, Azure AD, Keycloak, etc.).
    /// Signing keys are discovered automatically from the provider's OIDC discovery endpoint.
    /// </summary>
    /// <param name="authority">OIDC discovery base URL (for example, "https://login.example.com").</param>
    /// <param name="audience">Expected audience claim. Pass <c>null</c> to skip audience validation.</param>
    public JwtBearerBuilder WithOidcProvider(string authority, string? audience = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(authority);
        _authority = authority;
        if (audience is not null) _audience = audience;
        return this;
    }

    /// <summary>
    /// Validate JWTs signed with a local symmetric HMAC key for services that issue their own tokens
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
    /// Validate JWTs signed with a pre-built <see cref="SecurityKey"/>.
    /// Use this for self-hosted JWT issuers using asymmetric keys (RSA, ECDSA) where you supply the public key directly.
    /// </summary>
    /// <param name="signingKey">The public key used to verify token signatures.</param>
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
    /// and returns the <see cref="SecurityKey"/> used to verify token signatures.
    /// <para>
    /// Use this overload when the key or issuer is not available at service-registration time,
    /// for example when the value comes from configuration that may be overridden by
    /// <c>WebApplicationFactory</c> in integration tests, or from a key vault loaded asynchronously.
    /// </para>
    /// </summary>
    /// <param name="keyFactory">Factory that produces the signing key.</param>
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

    /// <summary>
    /// Read the bearer token from an <c>HttpOnly</c> secure cookie.
    /// Intended for SignalR WebSocket and SSE connections. Takes priority over
    /// <see cref="WithTokenQueryParam"/> when both are configured.
    /// </summary>
    /// <param name="cookieName">The cookie name that contains the bearer token.</param>
    public JwtBearerBuilder WithTokenCookie(string cookieName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cookieName);
        _tokenCookieName = cookieName;
        return this;
    }

    /// <summary>
    /// Read the bearer token from a query string parameter as a fallback when the cookie
    /// configured via <see cref="WithTokenCookie"/> is absent from the request.
    /// Prefer cookies over query parameters because query string tokens may appear in server logs.
    /// </summary>
    /// <param name="parameterName">The query string parameter name that contains the bearer token.</param>
    public JwtBearerBuilder WithTokenQueryParam(string parameterName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(parameterName);
        _tokenQueryParameter = parameterName;
        return this;
    }

    /// <summary>
    /// Disable the HTTPS requirement for OIDC metadata discovery.
    /// Never use this in production.
    /// </summary>
    public JwtBearerBuilder DisableHttpsMetadataRequirement()
    {
        _requireHttpsMetadata = false;
        return this;
    }

    /// <summary>
    /// Skip validation of the <c>iss</c> claim.
    /// </summary>
    public JwtBearerBuilder DisableIssuerValidation()
    {
        _validateIssuer = false;
        return this;
    }

    /// <summary>
    /// Skip validation of the <c>aud</c> claim.
    /// </summary>
    public JwtBearerBuilder DisableAudienceValidation()
    {
        _validateAudience = false;
        return this;
    }

    /// <summary>
    /// Skip validation of token expiry.
    /// Never use this in production.
    /// </summary>
    public JwtBearerBuilder DisableLifetimeValidation()
    {
        _validateLifetime = false;
        return this;
    }

    /// <summary>
    /// Override the clock skew tolerance for token expiry.
    /// The default is 1 minute.
    /// </summary>
    /// <param name="skew">The clock skew tolerance to apply during token lifetime validation.</param>
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

    internal void Apply(IServiceCollection services, UserClaimMapping claimMapping, bool useSessionValidation = false)
    {
        if (string.IsNullOrEmpty(_authority) && string.IsNullOrEmpty(_signingKey) && _securityKey is null && _signingKeyFactory is null)
            throw new InvalidOperationException(
                "Call WithOidcProvider(), WithSymmetricKey(), or WithSigningKey() to configure JWT bearer authentication.");

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                ConfigureOptions(options, claimMapping);
                ConfigureTokenExtractionEvents(options);
                if (useSessionValidation)
                    ConfigureSessionValidationEvent(options);
            });

        if (_signingKeyFactory is not null)
            ApplyFactoryBasedKey(services);
    }

    private void ConfigureOptions(JwtBearerOptions options, UserClaimMapping claimMapping)
    {
        options.Authority = _authority;
        options.Audience = _audience;
        options.RequireHttpsMetadata = _requireHttpsMetadata;
        options.MapInboundClaims = _mapInboundClaims;

        options.TokenValidationParameters.ValidateIssuer = _validateIssuer;
        options.TokenValidationParameters.ValidateAudience = _validateAudience;
        options.TokenValidationParameters.ValidateLifetime = _validateLifetime;
        options.TokenValidationParameters.ClockSkew = _clockSkew;
        options.TokenValidationParameters.NameClaimType = claimMapping.UserId;
        options.TokenValidationParameters.RoleClaimType = claimMapping.Roles;

        if (_securityKey is not null)
        {
            options.TokenValidationParameters.IssuerSigningKey = _securityKey;
        }
        else if (!string.IsNullOrEmpty(_signingKey))
        {
            options.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_signingKey));
        }

        if (!string.IsNullOrEmpty(_issuer))
            options.TokenValidationParameters.ValidIssuer = _issuer;
    }

    private void ConfigureTokenExtractionEvents(JwtBearerOptions options)
    {
        if (string.IsNullOrEmpty(_tokenCookieName) && string.IsNullOrEmpty(_tokenQueryParameter))
            return;

        var cookieName = _tokenCookieName;
        var queryParam = _tokenQueryParameter;

        options.Events ??= new JwtBearerEvents();
        var prior = options.Events.OnMessageReceived;
        options.Events.OnMessageReceived = async ctx =>
        {
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

            if (prior is not null)
                await prior(ctx);
        };
    }

    private void ConfigureSessionValidationEvent(JwtBearerOptions options)
    {
        var mapInboundClaims = _mapInboundClaims;

        options.Events ??= new JwtBearerEvents();
        var prior = options.Events.OnTokenValidated;
        options.Events.OnTokenValidated = async ctx =>
        {
            if (prior is not null)
                await prior(ctx);

            // Short-circuit if a prior handler produced a terminal non-success result
            // (Fail or NoResult). A Success result must not bypass session validation.
            if (ctx.Result is { Succeeded: false })
                return;

            // Resolve the sid claim. When inbound claim mapping is enabled the token
            // handler may translate the raw "sid" JWT short name to ClaimTypes.Sid
            // (the XML-namespace form). Check both so the hook is reliable under
            // either handler configuration.
            var sidClaim = ctx.Principal?.FindFirst(SecurityClaimTypes.Sid);
            if (sidClaim is null && mapInboundClaims)
                sidClaim = ctx.Principal?.FindFirst(ClaimTypes.Sid);

            // Tokens without any sid claim (e.g. client_credentials) bypass the hook.
            if (sidClaim is null)
                return;

            // A sid claim present but empty is not a valid session ID — fail immediately.
            var sid = sidClaim.Value;
            if (string.IsNullOrEmpty(sid))
            {
                ctx.Fail("Session ID claim is present but empty.");
                return;
            }

            var validator = ctx.HttpContext.RequestServices
                .GetRequiredService<ITokenSessionValidator>();

            var valid = await validator.ValidateAsync(
                sid, ctx.HttpContext, ctx.HttpContext.RequestAborted);

            if (!valid)
                ctx.Fail("Session is no longer valid.");
        };
    }

    private void ApplyFactoryBasedKey(IServiceCollection services)
    {
        var keyFactory = _signingKeyFactory!;
        var issuerFactory = _issuerFactory!;
        var audienceFactory = _audienceFactory;
        var validateAudience = _validateAudience;

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
