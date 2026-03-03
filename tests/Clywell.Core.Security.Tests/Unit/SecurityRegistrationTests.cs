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
    public void AddSecurity_RegistersPolicyProvider()
    {
        var services = new ServiceCollection();

        services.AddSecurity();

        var provider = services.BuildServiceProvider();
        var policyProvider = provider.GetService<IAuthorizationPolicyProvider>();
        Assert.NotNull(policyProvider);
    }

    [Fact]
    public void AddSecurity_RegistersPermissionHandler()
    {
        var services = new ServiceCollection();

        services.AddSecurity();

        var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var handlers = scope.ServiceProvider.GetServices<IAuthorizationHandler>();
        Assert.Contains(handlers, h => h is PermissionAuthorizationHandler);
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

    private sealed class StubUserContextResolver : IUserContextResolver
    {
        public Task<UserInfo?> ResolveAsync(HttpContext context) => Task.FromResult<UserInfo?>(null);
    }
}
