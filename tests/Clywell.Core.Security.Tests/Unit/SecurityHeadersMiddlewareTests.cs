namespace Clywell.Core.Security.Tests.Unit;

public class SecurityHeadersMiddlewareTests
{
    [Fact]
    public async Task InvokeAsync_SetsSecurityHeaders()
    {
        var httpContext = new DefaultHttpContext();
        var middleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(httpContext);

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
        var middleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(httpContext);

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

        var middleware = new SecurityHeadersMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(httpContext);

        Assert.False(httpContext.Response.Headers.ContainsKey("Server"));
        Assert.False(httpContext.Response.Headers.ContainsKey("X-Powered-By"));
    }

    [Fact]
    public async Task InvokeAsync_CallsNext()
    {
        var nextCalled = false;
        var middleware = new SecurityHeadersMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(new DefaultHttpContext());

        Assert.True(nextCalled);
    }
}
