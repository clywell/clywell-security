using Microsoft.AspNetCore.Authentication;

namespace Clywell.Core.Security;

public sealed class SecurityOptions
{
    private Action<IServiceCollection>? _resolverRegistration;
    private Action<IServiceCollection>? _customAuthSetup;
    private JwtBearerBuilder? _jwtBuilder;
    private readonly UserClaimMapping _claimMapping = new();
    private IReadOnlyCollection<string>? _permissionCodes;
    private bool _useStepUpAuthorization;
    private bool _useSessionValidation;
    private Action<IServiceCollection>? _sessionValidatorRegistration;

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
    /// Enables permission-based authorization by registering a <c>Permission:&lt;code&gt;</c> policy
    /// for each supplied permission code. Each policy requires a claim of the configured permission
    /// claim type (see <see cref="ConfigureClaimMapping"/>) whose value matches the permission code.
    /// Use with <see cref="EndpointConventionBuilderExtensions.RequirePermission{TBuilder}"/> or
    /// <see cref="HasPermissionAttribute"/> on endpoints and controllers.
    /// </summary>
    /// <param name="permissionCodes">The permission codes to register as authorization policies.</param>
    public SecurityOptions UsePermissionAuthorization(IEnumerable<string> permissionCodes)
    {
        ArgumentNullException.ThrowIfNull(permissionCodes);
        _permissionCodes = permissionCodes as IReadOnlyCollection<string> ?? permissionCodes.ToArray();

        if (_permissionCodes.Count == 0)
            throw new ArgumentException("At least one permission code must be provided.", nameof(permissionCodes));

        return this;
    }

    /// <summary>
    /// Enables step-up authentication authorization.
    /// Registers <see cref="StepUpAuthorizationHandler"/> and <see cref="IStepUpProofValidator"/>.
    /// Use with <see cref="EndpointConventionBuilderExtensions.RequireStepUp{TBuilder}"/> on endpoints.
    /// </summary>
    public SecurityOptions UseStepUpAuthorization()
    {
        _useStepUpAuthorization = true;
        return this;
    }

    /// <summary>
    /// Enables DI-driven session validation after standard JWT validation succeeds.
    /// Only tokens that carry a <c>sid</c> claim are checked; tokens without <c>sid</c>
    /// (e.g., client_credentials) bypass the hook automatically.
    /// </summary>
    /// <typeparam name="TValidator">
    /// The <see cref="ITokenSessionValidator"/> implementation. Resolved from the request DI scope
    /// on every authenticated request; register any dependencies (cache, database, etc.) in the
    /// consuming application — this package adds no direct data-access dependency.
    /// </typeparam>
    /// <exception cref="InvalidOperationException">
    /// Thrown during <see cref="Apply"/> if <see cref="UseAuthenticationHandler{THandler,TOptions}"/>
    /// was also configured, because a custom handler owns its own validation pipeline.
    /// </exception>
    public SecurityOptions UseSessionValidation<TValidator>()
        where TValidator : class, ITokenSessionValidator
    {
        _useSessionValidation = true;
        _sessionValidatorRegistration = services => services.AddScoped<ITokenSessionValidator, TValidator>();
        return this;
    }

    /// <summary>
    /// Enables DI-driven session validation after standard JWT validation succeeds using a factory.
    /// </summary>
    public SecurityOptions UseSessionValidation(Func<IServiceProvider, ITokenSessionValidator> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        _useSessionValidation = true;
        _sessionValidatorRegistration = services => services.AddScoped(factory);
        return this;
    }

    /// <summary>
    /// Register a custom <see cref="AuthenticationHandler{TOptions}"/> as the default authentication scheme.
    /// Use this when you need full control over token validation, for example to implement
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

        if (_useSessionValidation && _customAuthSetup is not null)
            throw new InvalidOperationException(
                "UseSessionValidation is not compatible with UseAuthenticationHandler. " +
                "Configure session validation inside your custom handler instead.");

        if (_sessionValidatorRegistration is not null)
            _sessionValidatorRegistration(services);

        if (_customAuthSetup is not null)
            _customAuthSetup(services);
        else
            _jwtBuilder?.Apply(services, _claimMapping, _useSessionValidation);
    }

    internal bool PermissionAuthorizationEnabled => _permissionCodes is not null;
    internal IReadOnlyCollection<string> PermissionCodes => _permissionCodes ?? Array.Empty<string>();
    internal string PermissionClaimType => _claimMapping.Permissions;
    internal bool StepUpAuthorizationEnabled => _useStepUpAuthorization;
    internal bool SessionValidationEnabled => _useSessionValidation;
}
