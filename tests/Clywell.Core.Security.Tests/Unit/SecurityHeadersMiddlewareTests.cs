namespace Clywell.Core.Security.Tests.Unit;

public class SecurityHeadersMiddlewareTests
{
    private static SecurityHeadersMiddleware CreateMiddleware(Action<SecurityHeadersOptions>? configure = null)
    {
        var options = new SecurityHeadersOptions();
        configure?.Invoke(options);
        return new SecurityHeadersMiddleware(_ => Task.CompletedTask, options);
    }

    // --- Default behaviour ---

    [Fact]
    public async Task InvokeAsync_SetsSecurityHeaders()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware().InvokeAsync(httpContext);

        Assert.Equal("nosniff", httpContext.Response.Headers["X-Content-Type-Options"]);
        Assert.Equal("DENY", httpContext.Response.Headers["X-Frame-Options"]);
        Assert.Equal("strict-origin-when-cross-origin", httpContext.Response.Headers["Referrer-Policy"]);
        Assert.Contains("default-src 'self'", httpContext.Response.Headers["Content-Security-Policy"].ToString());
        Assert.Contains("frame-ancestors 'none'", httpContext.Response.Headers["Content-Security-Policy"].ToString());
    }

    [Fact]
    public async Task InvokeAsync_SetsPermissionsPolicy()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware().InvokeAsync(httpContext);

        var permissionsPolicy = httpContext.Response.Headers["Permissions-Policy"].ToString();
        Assert.Contains("camera=()", permissionsPolicy);
        Assert.Contains("microphone=()", permissionsPolicy);
        Assert.Contains("geolocation=()", permissionsPolicy);
    }

    [Fact]
    public async Task InvokeAsync_RemovesServerHeaders()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Response.Headers["Server"] = "Kestrel";
        httpContext.Response.Headers["X-Powered-By"] = "ASP.NET";

        await CreateMiddleware().InvokeAsync(httpContext);

        Assert.False(httpContext.Response.Headers.ContainsKey("Server"));
        Assert.False(httpContext.Response.Headers.ContainsKey("X-Powered-By"));
    }

    [Fact]
    public async Task InvokeAsync_CallsNext()
    {
        var nextCalled = false;
        var options = new SecurityHeadersOptions();
        var middleware = new SecurityHeadersMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        }, options);

        await middleware.InvokeAsync(new DefaultHttpContext());

        Assert.True(nextCalled);
    }

    // --- CSP configuration ---

    [Fact]
    public async Task InvokeAsync_CustomCspString_IsApplied()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware(o => o.WithContentSecurityPolicy("default-src 'none'"))
            .InvokeAsync(httpContext);

        Assert.Equal("default-src 'none'", httpContext.Response.Headers["Content-Security-Policy"]);
    }

    [Fact]
    public async Task InvokeAsync_CspBuilder_BuildsCorrectDirectives()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware(o => o.WithContentSecurityPolicy(csp => csp
                .Default("'self'")
                .Script("'self'", "'unsafe-inline'")
                .FrameAncestors("'none'")))
            .InvokeAsync(httpContext);

        var csp = httpContext.Response.Headers["Content-Security-Policy"].ToString();
        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("script-src 'self' 'unsafe-inline'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
    }

    [Fact]
    public async Task InvokeAsync_NullCsp_SupressesHeader()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware(o => o.WithContentSecurityPolicy((string?)null))
            .InvokeAsync(httpContext);

        Assert.False(httpContext.Response.Headers.ContainsKey("Content-Security-Policy"));
    }

    // --- Route-specific CSP ---

    [Fact]
    public async Task InvokeAsync_RouteOverride_AppliedForMatchingPath()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/scalar";
        await CreateMiddleware(o => o.AddRouteContentSecurityPolicy("/scalar", csp => csp
                .Default("'self'")
                .Script("'self'", "'unsafe-inline'")
                .Style("'self'", "'unsafe-inline'")
                .FrameAncestors("'none'")))
            .InvokeAsync(httpContext);

        var csp = httpContext.Response.Headers["Content-Security-Policy"].ToString();
        Assert.Contains("script-src 'self' 'unsafe-inline'", csp);
        Assert.Contains("style-src 'self' 'unsafe-inline'", csp);
    }

    [Fact]
    public async Task InvokeAsync_RouteOverride_FallsBackToGlobalCspForNonMatchingPath()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/api/users";

        await CreateMiddleware(o => o
                .WithContentSecurityPolicy("default-src 'self'; frame-ancestors 'none'")
                .AddRouteContentSecurityPolicy("/scalar", "default-src 'none'"))
            .InvokeAsync(httpContext);

        Assert.Equal(
            "default-src 'self'; frame-ancestors 'none'",
            httpContext.Response.Headers["Content-Security-Policy"].ToString());
    }

    // --- Custom header injection ---

    [Fact]
    public async Task InvokeAsync_AddHeader_IsPresent()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware(o => o.AddHeader("X-Custom-Header", "my-value"))
            .InvokeAsync(httpContext);

        Assert.Equal("my-value", httpContext.Response.Headers["X-Custom-Header"]);
    }

    // --- Additional header removal ---

    [Fact]
    public async Task InvokeAsync_RemoveHeader_IsAbsent()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Response.Headers["X-Extra"] = "value";

        await CreateMiddleware(o => o.RemoveHeader("X-Extra"))
            .InvokeAsync(httpContext);

        Assert.False(httpContext.Response.Headers.ContainsKey("X-Extra"));
    }

    // --- Suppressing individual headers ---

    [Fact]
    public async Task InvokeAsync_NullFrameOptions_SuppressesHeader()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware(o => o.FrameOptions = null)
            .InvokeAsync(httpContext);

        Assert.False(httpContext.Response.Headers.ContainsKey("X-Frame-Options"));
    }

    // --- Configured real-world scenarios (not built-in) ---

    [Fact]
    public async Task InvokeAsync_ConfiguredScalarRoute_AllowsInlineScriptAndStyle()
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Request.Path = "/scalar";

        await CreateMiddleware(o =>
            o.AddRouteContentSecurityPolicy("/scalar", csp => csp
                .Default("'self'")
                .Script("'self'", "'unsafe-inline'")
                .Style("'self'", "'unsafe-inline'")
                .Image("'self'", "data:", "https:")
                .Font("'self'", "data:")
                .Connect("'self'")
                .FrameAncestors("'none'")))
            .InvokeAsync(httpContext);

        var csp = httpContext.Response.Headers["Content-Security-Policy"].ToString();
        Assert.Contains("script-src 'self' 'unsafe-inline'", csp);
        Assert.Contains("style-src 'self' 'unsafe-inline'", csp);
    }

    [Fact]
    public async Task InvokeAsync_ConfiguredDevWebSockets_AllowsLocalWebSocketConnections()
    {
        var httpContext = new DefaultHttpContext();

        await CreateMiddleware(o =>
            o.WithContentSecurityPolicy(csp => csp
                .Default("'self'")
                .Connect("'self'", "ws://localhost:*", "wss://localhost:*")
                .FrameAncestors("'none'")))
            .InvokeAsync(httpContext);

        var csp = httpContext.Response.Headers["Content-Security-Policy"].ToString();
        Assert.Contains("connect-src 'self' ws://localhost:* wss://localhost:*", csp);
    }

    [Fact]
    public async Task InvokeAsync_DefaultCsp_DoesNotContainLocalWebSocketConnections()
    {
        var httpContext = new DefaultHttpContext();
        await CreateMiddleware().InvokeAsync(httpContext);

        var csp = httpContext.Response.Headers["Content-Security-Policy"].ToString();
        Assert.DoesNotContain("ws://localhost:*", csp);
        Assert.DoesNotContain("wss://localhost:*", csp);
    }
}
