namespace Clywell.Core.Security.Tests.Unit;

public class SecurityRegistrationTests
{
    [Fact]
    public void AddSecurity_RegistersCurrentUser()
    {
        var services = new ServiceCollection();

        services.AddSecurity();

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var currentUser = scope.ServiceProvider.GetService<ICurrentUser>();
        Assert.NotNull(currentUser);
        Assert.False(currentUser.IsAuthenticated);
    }

    [Fact]
    public void AddSecurity_RegistersDefaultResolver()
    {
        var services = new ServiceCollection();

        services.AddSecurity();

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var resolver = scope.ServiceProvider.GetService<IUserContextResolver>();
        Assert.NotNull(resolver);
        Assert.IsType<ClaimsUserContextResolver>(resolver);
    }

    [Fact]
    public void AddSecurity_WithCustomResolver_RegistersCustom()
    {
        var services = new ServiceCollection();

        services.AddSecurity(options => options.UseResolver<StubUserContextResolver>());

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var resolver = scope.ServiceProvider.GetService<IUserContextResolver>();
        Assert.NotNull(resolver);
        Assert.IsType<StubUserContextResolver>(resolver);
    }

    [Fact]
    public void AddSecurity_WithFactoryResolver_RegistersFactory()
    {
        var services = new ServiceCollection();
        var expected = new StubUserContextResolver();

        services.AddSecurity(options => options.UseResolver(_ => expected));

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var resolver = scope.ServiceProvider.GetService<IUserContextResolver>();
        Assert.Same(expected, resolver);
    }

    [Fact]
    public void AddSecurity_WithPermissions_RegistersPermissionPolicies()
    {
        var services = new ServiceCollection();
        string[] permissions = ["users.read", "users.write"];

        services.AddSecurity(options => options.UsePermissionAuthorization(permissions));
        services.AddAuthorization();

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;
        Assert.NotNull(authOptions.GetPolicy("Permission:users.read"));
        Assert.NotNull(authOptions.GetPolicy("Permission:users.write"));
    }

    [Fact]
    public void AddSecurity_WithoutPermissions_DoesNotRegisterPermissionPolicies()
    {
        var services = new ServiceCollection();

        services.AddSecurity();
        services.AddAuthorization();

        var provider = services.BuildServiceProvider();
        var authOptions = provider.GetRequiredService<IOptions<AuthorizationOptions>>().Value;
        Assert.Null(authOptions.GetPolicy("Permission:users.read"));
    }

    [Fact]
    public void AddSecurity_WithStepUp_RegistersStepUpAuthorizationHandler()
    {
        var services = new ServiceCollection();
        services.AddSecurity(options => options.UseStepUpAuthorization());
        var provider = services.BuildServiceProvider();

        var handlers = provider.GetServices<IAuthorizationHandler>().ToList();

        Assert.Contains(handlers, h => h is StepUpAuthorizationHandler);
    }

    [Fact]
    public void AddSecurity_WithoutStepUp_DoesNotRegisterStepUpHandler()
    {
        var services = new ServiceCollection();
        services.AddSecurity();
        var provider = services.BuildServiceProvider();

        var handlers = provider.GetServices<IAuthorizationHandler>().ToList();

        Assert.DoesNotContain(handlers, h => h is StepUpAuthorizationHandler);
    }

    [Fact]
    public void AddSecurity_WithStepUp_RegistersIStepUpProofValidatorDescriptor()
    {
        var services = new ServiceCollection();
        services.AddSecurity(options => options.UseStepUpAuthorization());

        Assert.Contains(services, d => d.ServiceType == typeof(IStepUpProofValidator));
    }

    [Fact]
    public void AddSecurity_WithoutStepUp_DoesNotRegisterIStepUpProofValidator()
    {
        var services = new ServiceCollection();
        services.AddSecurity();

        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IStepUpProofValidator));
    }

    [Fact]
    public void AddSecurity_RegistersIHttpContextAccessor()
    {
        var services = new ServiceCollection();
        services.AddSecurity();

        Assert.Contains(services, d => d.ServiceType == typeof(IHttpContextAccessor));
    }

    [Fact]
    public void AddSecurity_ReturnsSameServiceCollection()
    {
        var services = new ServiceCollection();

        var result = services.AddSecurity();

        Assert.Same(services, result);
    }

    [Fact]
    public void AddSecurity_DoesNotDuplicateRegistrations()
    {
        var services = new ServiceCollection();

        services.AddSecurity();
        services.AddSecurity();

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var currentUser = scope.ServiceProvider.GetService<ICurrentUser>();
        Assert.NotNull(currentUser);
    }

    [Fact]
    public void AddSecurity_RegistersUserClaimMapping()
    {
        var services = new ServiceCollection();

        services.AddSecurity();

        var provider = services.BuildServiceProvider();
        var mapping = provider.GetService<UserClaimMapping>();
        Assert.NotNull(mapping);
    }

    [Fact]
    public void AddSecurity_ConfigureClaimMapping_UsesCustomMapping()
    {
        var services = new ServiceCollection();

        services.AddSecurity(options =>
            options.ConfigureClaimMapping(m => m.UserId = "user_id"));

        var provider = services.BuildServiceProvider();
        var mapping = provider.GetRequiredService<UserClaimMapping>();
        Assert.Equal("user_id", mapping.UserId);
    }

    [Fact]
    public void AddSecurity_WithOidcProvider_RegistersAuthentication()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddSecurity(options =>
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com", audience: "api"));

        var provider = services.BuildServiceProvider();
        var jwtOptions = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);
        Assert.NotNull(jwtOptions);
        Assert.Equal("api", jwtOptions.Audience);
    }

    [Fact]
    public void AddSecurity_WithSymmetricKey_SetsIssuerSigningKeyAndValidIssuer()
    {
        var services = new ServiceCollection();
        services.AddLogging();

        services.AddSecurity(options =>
            options.AddJwtBearer()
                .WithSymmetricKey(
                    "at-least-32-chars-long-secret-key!!",
                    issuer: "https://auth.example.com",
                    audience: "api"));

        var provider = services.BuildServiceProvider();
        var tvp = provider.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme).TokenValidationParameters;
        Assert.IsType<SymmetricSecurityKey>(tvp.IssuerSigningKey);
        Assert.Equal("https://auth.example.com", tvp.ValidIssuer);
    }

    [Fact]
    public void AddSecurity_WithSigningKey_SetsIssuerSigningKeyAndValidIssuer()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var key = new RsaSecurityKey(rsa);

        var services = new ServiceCollection();
        services.AddLogging();

        services.AddSecurity(options =>
            options.AddJwtBearer()
                .WithSigningKey(key, issuer: "https://auth.example.com", audience: "api"));

        var jwtOptions = services.BuildServiceProvider()
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);
        var tvp = jwtOptions.TokenValidationParameters;

        Assert.Same(key, tvp.IssuerSigningKey);
        Assert.Equal("https://auth.example.com", tvp.ValidIssuer);
        Assert.Equal("api", jwtOptions.Audience);
    }


    // ── Session validation registration ──────────────────────────────────────

    [Fact]
    public void AddSecurity_WithSessionValidation_RegistersITokenSessionValidator()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation<StubSessionValidator>();
        });

        Assert.Contains(services, d => d.ServiceType == typeof(ITokenSessionValidator));
    }

    [Fact]
    public void AddSecurity_WithoutSessionValidation_DoesNotRegisterITokenSessionValidator()
    {
        var services = new ServiceCollection();
        services.AddSecurity();

        Assert.DoesNotContain(services, d => d.ServiceType == typeof(ITokenSessionValidator));
    }

    [Fact]
    public void AddSecurity_SessionValidationWithFactory_RegistersValidator()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        var expected = new StubSessionValidator();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ => expected);
        });

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var validator = scope.ServiceProvider.GetService<ITokenSessionValidator>();
        Assert.Same(expected, validator);
    }

    [Fact]
    public void AddSecurity_SessionValidationWithCustomHandler_Throws()
    {
        var services = new ServiceCollection();
        var ex = Assert.Throws<InvalidOperationException>(() =>
            services.AddSecurity(options =>
            {
                options.UseAuthenticationHandler<StubAuthHandler, StubAuthHandlerOptions>("custom");
                options.UseSessionValidation<StubSessionValidator>();
            }));

        Assert.Contains("UseSessionValidation", ex.Message);
    }

    private sealed class StubSessionValidator : ITokenSessionValidator
    {
        public Task<bool> ValidateAsync(string sessionId, HttpContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(true);
    }

    private sealed class StubAuthHandlerOptions : AuthenticationSchemeOptions { }

    private sealed class StubAuthHandler(
        IOptionsMonitor<StubAuthHandlerOptions> options,
        ILoggerFactory logger,
        System.Text.Encodings.Web.UrlEncoder encoder)
        : AuthenticationHandler<StubAuthHandlerOptions>(options, logger, encoder)
    {
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
            => Task.FromResult(AuthenticateResult.NoResult());
    }

    private sealed class StubUserContextResolver : IUserContextResolver
    {
        public Task<UserInfo?> ResolveAsync(HttpContext context) => Task.FromResult<UserInfo?>(null);
    }
}
