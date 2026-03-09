namespace Clywell.Core.Security;

public sealed class SecurityOptions
{
    private Action<IServiceCollection>? _resolverRegistration;
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
        _jwtBuilder = new JwtBearerBuilder();
        return _jwtBuilder;
    }

    internal void Apply(IServiceCollection services)
    {
        services.TryAddSingleton(_claimMapping);

        if (_resolverRegistration is not null)
            _resolverRegistration(services);
        else
            services.TryAddScoped<IUserContextResolver, ClaimsUserContextResolver>();

        _jwtBuilder?.Apply(services, _claimMapping);
    }
}
