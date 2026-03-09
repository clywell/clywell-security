namespace Clywell.Core.Security.Tests.Unit;

public class JwtBearerOptionsTests
{
    // Resolves the named JwtBearer options (registered under "Bearer", not the empty-name default).
    private static JwtBearerOptions BuildJwtOptions(Action<JwtBearerBuilder> configure)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options => configure(options.AddJwtBearer()));
        return services.BuildServiceProvider()
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);
    }

    private static MessageReceivedContext BuildMessageContext(JwtBearerOptions options, HttpContext httpContext)
    {
        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        return new MessageReceivedContext(httpContext, scheme, options);
    }

    // -------------------------------------------------------------------------
    // Symmetric key
    // -------------------------------------------------------------------------

    [Fact]
    public void WithOidcProvider_IssuerSigningKey_IsNull()
    {
        var options = BuildJwtOptions(b => b.WithOidcProvider("https://auth.example.com"));

        Assert.Null(options.TokenValidationParameters.IssuerSigningKey);
    }

    [Fact]
    public void WithSymmetricKey_SetsSymmetricIssuerSigningKey()
    {
        var options = BuildJwtOptions(b =>
            b.WithSymmetricKey("at-least-32-chars-long-secret-key!!", "test-issuer", audience: "api"));

        Assert.IsType<SymmetricSecurityKey>(options.TokenValidationParameters.IssuerSigningKey);
    }

    [Fact]
    public void WithSymmetricKey_SetsValidIssuer()
    {
        var options = BuildJwtOptions(b =>
            b.WithSymmetricKey("at-least-32-chars-long-secret-key!!", "https://auth.example.com"));

        Assert.Equal("https://auth.example.com", options.TokenValidationParameters.ValidIssuer);
    }

    [Fact]
    public void WithOidcProvider_ValidIssuer_IsNull()
    {
        var options = BuildJwtOptions(b => b.WithOidcProvider("https://auth.example.com"));

        Assert.Null(options.TokenValidationParameters.ValidIssuer);
    }

    // -------------------------------------------------------------------------
    // No extraction configured — OnMessageReceived should be a no-op
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WithoutTokenExtraction_OnMessageReceived_IsNoOp()
    {
        var options = BuildJwtOptions(b => b.WithOidcProvider("https://auth.example.com"));

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Cookie"] = "auth_token=some.token";
        httpContext.Request.QueryString = new QueryString("?access_token=some.token");

        var ctx = BuildMessageContext(options, httpContext);
        await options.Events.OnMessageReceived(ctx);

        Assert.Null(ctx.Token); // Default no-op: no extraction happens
    }

    // -------------------------------------------------------------------------
    // Cookie extraction
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WithTokenCookie_ExtractsTokenFromCookie()
    {
        var options = BuildJwtOptions(b =>
            b.WithOidcProvider("https://auth.example.com").WithTokenCookie("auth_token"));

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Cookie"] = "auth_token=my.jwt.token";

        var ctx = BuildMessageContext(options, httpContext);
        await options.Events.OnMessageReceived(ctx);

        Assert.Equal("my.jwt.token", ctx.Token);
    }

    [Fact]
    public async Task WithTokenCookie_NoCookiePresent_TokenRemainsNull()
    {
        var options = BuildJwtOptions(b =>
            b.WithOidcProvider("https://auth.example.com").WithTokenCookie("auth_token"));

        var ctx = BuildMessageContext(options, new DefaultHttpContext());
        await options.Events.OnMessageReceived(ctx);

        Assert.Null(ctx.Token);
    }

    // -------------------------------------------------------------------------
    // Query parameter extraction
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WithTokenQueryParam_ExtractsTokenFromQuery()
    {
        var options = BuildJwtOptions(b =>
            b.WithOidcProvider("https://auth.example.com").WithTokenQueryParam("access_token"));

        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString("?access_token=my.jwt.token");

        var ctx = BuildMessageContext(options, httpContext);
        await options.Events.OnMessageReceived(ctx);

        Assert.Equal("my.jwt.token", ctx.Token);
    }

    [Fact]
    public async Task WithTokenQueryParam_NoQueryPresent_TokenRemainsNull()
    {
        var options = BuildJwtOptions(b =>
            b.WithOidcProvider("https://auth.example.com").WithTokenQueryParam("access_token"));

        var ctx = BuildMessageContext(options, new DefaultHttpContext());
        await options.Events.OnMessageReceived(ctx);

        Assert.Null(ctx.Token);
    }

    // -------------------------------------------------------------------------
    // Cookie takes priority over query parameter
    // -------------------------------------------------------------------------

    [Fact]
    public async Task CookieTakesPriorityOverQueryParameter()
    {
        var options = BuildJwtOptions(b =>
            b.WithOidcProvider("https://auth.example.com")
             .WithTokenCookie("auth_token")
             .WithTokenQueryParam("access_token"));

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Cookie"] = "auth_token=cookie.jwt.token";
        httpContext.Request.QueryString = new QueryString("?access_token=query.jwt.token");

        var ctx = BuildMessageContext(options, httpContext);
        await options.Events.OnMessageReceived(ctx);

        Assert.Equal("cookie.jwt.token", ctx.Token);
    }

    [Fact]
    public async Task FallsBackToQueryParameter_WhenCookieAbsent()
    {
        var options = BuildJwtOptions(b =>
            b.WithOidcProvider("https://auth.example.com")
             .WithTokenCookie("auth_token")
             .WithTokenQueryParam("access_token"));

        var httpContext = new DefaultHttpContext();
        httpContext.Request.QueryString = new QueryString("?access_token=query.jwt.token");
        // No cookie set

        var ctx = BuildMessageContext(options, httpContext);
        await options.Events.OnMessageReceived(ctx);

        Assert.Equal("query.jwt.token", ctx.Token);
    }

    // -------------------------------------------------------------------------
    // RSA / asymmetric signing key (WithSigningKey)
    // -------------------------------------------------------------------------

    [Fact]
    public void WithSigningKey_SetsIssuerSigningKey()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var key = new RsaSecurityKey(rsa);

        var options = BuildJwtOptions(b => b.WithSigningKey(key, "test-issuer"));

        Assert.Same(key, options.TokenValidationParameters.IssuerSigningKey);
    }

    [Fact]
    public void WithSigningKey_SetsValidIssuer()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var key = new RsaSecurityKey(rsa);

        var options = BuildJwtOptions(b => b.WithSigningKey(key, "test-issuer"));

        Assert.Equal("test-issuer", options.TokenValidationParameters.ValidIssuer);
    }

    [Fact]
    public void WithSigningKey_WithAudience_SetsAudience()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var key = new RsaSecurityKey(rsa);

        var options = BuildJwtOptions(b => b.WithSigningKey(key, "test-issuer", audience: "my-api"));

        Assert.Equal("my-api", options.Audience);
    }

    // -------------------------------------------------------------------------
    // Claim mapping sync - NameClaimType and RoleClaimType
    // -------------------------------------------------------------------------

    [Fact]
    public void DefaultClaimMapping_NameClaimType_IsSub()
    {
        var options = BuildJwtOptions(b => b.WithOidcProvider("https://auth.example.com"));

        Assert.Equal("sub", options.TokenValidationParameters.NameClaimType);
    }

    [Fact]
    public void DefaultClaimMapping_RoleClaimType_IsRole()
    {
        var options = BuildJwtOptions(b => b.WithOidcProvider("https://auth.example.com"));

        Assert.Equal("role", options.TokenValidationParameters.RoleClaimType);
    }

    [Fact]
    public void CustomRoleMapping_RoleClaimType_ReflectsCustomValue()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.ConfigureClaimMapping(m => m.Roles = "roles");
        });

        var tvp = services.BuildServiceProvider()
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme)
            .TokenValidationParameters;

        Assert.Equal("roles", tvp.RoleClaimType);
    }
}
