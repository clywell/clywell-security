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

    // -------------------------------------------------------------------------
    // Event composition: prior OnMessageReceived is chained after extraction
    // -------------------------------------------------------------------------

    [Fact]
    public async Task WithTokenCookie_ExistingOnMessageReceived_IsPreservedAndCalledAfterExtraction()
    {
        // Arrange: register a Configure action that sets OnAuthenticationFailed BEFORE
        // AddSecurity adds extraction. This simulates any code that hooks JwtBearerEvents
        // before the extraction delegate is wired.
        var services = new ServiceCollection();
        services.AddLogging();

        var priorMessageReceivedCalled = false;

        // This Configure runs before AddJwtBearer's Configure action.
        services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, opts =>
        {
            var old = opts.Events.OnMessageReceived;
            opts.Events.OnMessageReceived = async ctx =>
            {
                priorMessageReceivedCalled = true;
                if (old is not null) await old(ctx);
            };
        });

        services.AddSecurity(options =>
            options.AddJwtBearer()
                .WithOidcProvider("https://auth.example.com")
                .WithTokenCookie("auth_token"));

        var jwtOptions = services.BuildServiceProvider()
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Headers["Cookie"] = "auth_token=cookie.jwt.token";
        var ctx = BuildMessageContext(jwtOptions, httpContext);
        await jwtOptions.Events.OnMessageReceived(ctx);

        Assert.Equal("cookie.jwt.token", ctx.Token);
        Assert.True(priorMessageReceivedCalled);
    }

    [Fact]
    public async Task WithTokenCookie_OtherJwtBearerEvents_AreNotDropped()
    {
        // Arrange: verify that setting WithTokenCookie does NOT replace the Events object
        // and therefore does not drop event delegates such as OnAuthenticationFailed.
        var services = new ServiceCollection();
        services.AddLogging();

        var authFailedCalled = false;

        // Pre-wire OnAuthenticationFailed BEFORE extraction is configured.
        services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, opts =>
        {
            opts.Events.OnAuthenticationFailed = ctx =>
            {
                authFailedCalled = true;
                return Task.CompletedTask;
            };
        });

        services.AddSecurity(options =>
            options.AddJwtBearer()
                .WithOidcProvider("https://auth.example.com")
                .WithTokenCookie("auth_token"));

        var jwtOptions = services.BuildServiceProvider()
            .GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var failCtx = new AuthenticationFailedContext(new DefaultHttpContext(), scheme, jwtOptions)
        {
            Exception = new Exception("test")
        };
        await jwtOptions.Events.OnAuthenticationFailed(failCtx);

        Assert.True(authFailedCalled);
    }

    // -------------------------------------------------------------------------
    // Session validation hook
    // -------------------------------------------------------------------------

    [Fact]
    public async Task SessionValidation_Bypass_WhenSidClaimAbsent()
    {
        var validatorCalled = false;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ =>
            {
                validatorCalled = true;
                return new StubSessionValidator(true);
            });
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // Principal WITHOUT sid claim
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        await jwtOptions.Events.OnTokenValidated(ctx);

        Assert.False(validatorCalled);
        Assert.Null(ctx.Result);
    }

    [Fact]
    public async Task SessionValidation_Fails_WhenValidatorReturnsFalse()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ => new StubSessionValidator(false));
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim("sid", "sess-abc")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        await jwtOptions.Events.OnTokenValidated(ctx);

        Assert.NotNull(ctx.Result);
        Assert.False(ctx.Result!.Succeeded);
    }

    [Fact]
    public async Task SessionValidation_Succeeds_WhenValidatorReturnsTrue()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ => new StubSessionValidator(true));
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim("sid", "sess-xyz")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        await jwtOptions.Events.OnTokenValidated(ctx);

        Assert.Null(ctx.Result);
    }


    // -------------------------------------------------------------------------
    // Session validation: prior handler short-circuit behaviour
    // -------------------------------------------------------------------------

    [Fact]
    public async Task SessionValidation_PriorHandler_NoResult_ShortCircuits_ValidatorNotCalled()
    {
        // Arrange: pre-wire OnTokenValidated that calls NoResult() before session validation
        var validatorCalled = false;
        var services = new ServiceCollection();
        services.AddLogging();

        services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, opts =>
        {
            opts.Events.OnTokenValidated = ctx =>
            {
                ctx.NoResult();
                return Task.CompletedTask;
            };
        });

        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ =>
            {
                validatorCalled = true;
                return new StubSessionValidator(true);
            });
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim("sid", "sess-abc")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        // Act
        await jwtOptions.Events.OnTokenValidated(ctx);

        // Assert: validator skipped, NoResult preserved
        Assert.False(validatorCalled);
        Assert.NotNull(ctx.Result);
        Assert.False(ctx.Result!.Succeeded);
    }

    [Fact]
    public async Task SessionValidation_PriorHandler_Fail_ShortCircuits_ValidatorNotCalled()
    {
        // Arrange: pre-wire OnTokenValidated that calls Fail() before session validation
        var validatorCalled = false;
        var services = new ServiceCollection();
        services.AddLogging();

        services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, opts =>
        {
            opts.Events.OnTokenValidated = ctx =>
            {
                ctx.Fail("prior failure");
                return Task.CompletedTask;
            };
        });

        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ =>
            {
                validatorCalled = true;
                return new StubSessionValidator(true);
            });
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim("sid", "sess-abc")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        // Act
        await jwtOptions.Events.OnTokenValidated(ctx);

        // Assert: validator skipped, failure preserved
        Assert.False(validatorCalled);
        Assert.NotNull(ctx.Result);
        Assert.False(ctx.Result!.Succeeded);
        Assert.NotNull(ctx.Result!.Failure);
    }

    [Fact]
    public async Task SessionValidation_PriorHandler_Success_DoesNotBypassValidator()
    {
        // Arrange: prior handler calls Success() — session validator must still run
        var validatorCalled = false;
        var services = new ServiceCollection();
        services.AddLogging();

        services.Configure<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme, opts =>
        {
            opts.Events.OnTokenValidated = ctx =>
            {
                ctx.Success(); // prior handler marks success
                return Task.CompletedTask;
            };
        });

        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ =>
            {
                validatorCalled = true;
                return new StubSessionValidator(true);
            });
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim("sid", "sess-abc")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        // Act
        await jwtOptions.Events.OnTokenValidated(ctx);

        // Assert: validator was called despite prior Success
        Assert.True(validatorCalled);
    }

    [Fact]
    public async Task SessionValidation_Fails_WhenSidClaimPresentButEmpty()
    {
        // A principal whose sid claim exists but has an empty value must cause a Fail result,
        // not silently bypass session validation.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer().WithOidcProvider("https://auth.example.com");
            options.UseSessionValidation(_ => new StubSessionValidator(true));
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim(SecurityClaimTypes.Sid, "")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        await jwtOptions.Events.OnTokenValidated(ctx);

        Assert.NotNull(ctx.Result);
        Assert.False(ctx.Result!.Succeeded);
    }

    [Fact]
    public async Task SessionValidation_Succeeds_WhenPreserveInboundClaimTypes_WithMappedSidForm()
    {
        // When PreserveInboundClaimTypes() (MapInboundClaims = true) is active, the token handler
        // may represent the session ID using ClaimTypes.Sid (the XML-namespace form) instead of
        // the raw "sid" JWT short name. The hook must resolve that mapped form.
        var validatorCalled = false;
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSecurity(options =>
        {
            options.AddJwtBearer()
                   .WithOidcProvider("https://auth.example.com")
                   .PreserveInboundClaimTypes();
            options.UseSessionValidation(_ =>
            {
                validatorCalled = true;
                return new StubSessionValidator(true);
            });
        });

        var sp = services.BuildServiceProvider();
        var jwtOptions = sp.GetRequiredService<IOptionsMonitor<JwtBearerOptions>>()
            .Get(JwtBearerDefaults.AuthenticationScheme);

        // Principal carries the mapped claim type form (ClaimTypes.Sid), not the raw "sid" short name.
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [new Claim("sub", "user-1"), new Claim(ClaimTypes.Sid, "sess-mapped-abc")], "Bearer"));

        var httpContext = new DefaultHttpContext();
        httpContext.RequestServices = sp.CreateScope().ServiceProvider;

        var scheme = new AuthenticationScheme(JwtBearerDefaults.AuthenticationScheme, null, typeof(JwtBearerHandler));
        var ctx = new TokenValidatedContext(httpContext, scheme, jwtOptions) { Principal = principal };

        await jwtOptions.Events.OnTokenValidated(ctx);

        Assert.True(validatorCalled);
        Assert.Null(ctx.Result);
    }

    private sealed class StubSessionValidator(bool result) : ITokenSessionValidator
    {
        public Task<bool> ValidateAsync(string sessionId, HttpContext context, CancellationToken cancellationToken = default)
            => Task.FromResult(result);
    }
}
