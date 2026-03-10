using Microsoft.AspNetCore.Authentication;

namespace Clywell.Core.Security;

public sealed class SecurityOptions
{
    private Action<IServiceCollection>? _resolverRegistration;
    private Action<IServiceCollection>? _customAuthSetup;
    private JwtBearerBuilder? _jwtBuilder;
    private readonly UserClaimMapping _claimMapping = new();

    public SecurityOptions UseResolver<TResolver>() where TResolver : class, IUserContextResolver
    {
        _resolverRegistration = services => services.AddScoped<IUserContextResolver, TResolver>();
        return this;
    }

    public SecurityOptions ConfigureClaimMapping(Action<UserClaimMapping> configure)
    {
        configure(_claimMapping);
        return this;
    }

    public SecurityOptions UseResolver(Func<IServiceProvider, IUserContextResolver> factory)
    {
        _resolverRegistration = services => services.AddScoped(factory);
        return this;
    }

    /// <summary>
    /// Add JWT bearer authentication. Chain <see cref="JwtBearerBuilder.WithOidcProvider"/> or
    /// <see cref="JwtBearerBuilder.WithSymmetricKey"/> on the returned builder to specify the
    /// token source, then optionally call <see cref="JwtBearerBuilder.WithTokenCookie"/> /
    /// <see cref="JwtBearerBuilder.WithTokenQueryParam"/> for transport configuration.
    /// </summary>
    public JwtBearerBuilder AddJwtBearer()
    {
        if (_customAuthSetup is not null)
            throw new InvalidOperationException(
                "Cannot call AddJwtBearer after UseAuthenticationHandler. Use one or the other.");

        _jwtBuilder = new JwtBearerBuilder();
        return _jwtBuilder;
    }

    /// <summary>
    /// Register a custom <see cref="AuthenticationHandler{TOptions}"/> as the default authentication scheme.
    /// Use this when you need full control over token validation - for example, to implement
    /// multi-step authentication, load additional user data from a database, or support non-standard token formats.
    /// </summary>
    /// <typeparam name="THandler">The custom authentication handler type.</typeparam>
    /// <typeparam name="TOptions">The options type for the handler.</typeparam>
    /// <param name="schemeName">The authentication scheme name. This becomes the default scheme.</param>
    /// <param name="configure">Optional callback to configure the handler's options.</param>
    /// <returns>This <see cref="SecurityOptions"/> for chaining.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown if <see cref="AddJwtBearer"/> has already been called. Use one or the other.
    /// </exception>
    public SecurityOptions UseAuthenticationHandler<THandler, TOptions>(
        string schemeName,
        Action<TOptions>? configure = null)
        where THandler : AuthenticationHandler<TOptions>
        where TOptions : AuthenticationSchemeOptions, new()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(schemeName);

        if (_jwtBuilder is not null)
            throw new InvalidOperationException(
                "Cannot call UseAuthenticationHandler after AddJwtBearer. Use one or the other.");

        _customAuthSetup = services =>
            services.AddAuthentication(schemeName)
                .AddScheme<TOptions, THandler>(schemeName, configure);
        return this;
    }

    internal void Apply(IServiceCollection services)
    {
        services.TryAddSingleton(_claimMapping);

        if (_resolverRegistration is not null)
            _resolverRegistration(services);
        else
            services.TryAddScoped<IUserContextResolver, ClaimsUserContextResolver>();

        if (_customAuthSetup is not null)
            _customAuthSetup(services);
        else
            _jwtBuilder?.Apply(services, _claimMapping);
    }
}
