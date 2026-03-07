namespace Clywell.Core.Security;

/// <summary>
/// Middleware that applies configurable security response headers to every request.
/// Register with <c>app.UseSecurityHeaders(...)</c>.
/// </summary>
public sealed class SecurityHeadersMiddleware(RequestDelegate next, SecurityHeadersOptions options)
{
    public Task InvokeAsync(HttpContext context)
    {
        var headers = context.Response.Headers;

        if (options.ContentTypeOptions is not null)
            headers["X-Content-Type-Options"] = options.ContentTypeOptions;

        if (options.FrameOptions is not null)
            headers["X-Frame-Options"] = options.FrameOptions;

        if (options.ReferrerPolicy is not null)
            headers["Referrer-Policy"] = options.ReferrerPolicy;

        if (options.PermissionsPolicy is not null)
            headers["Permissions-Policy"] = options.PermissionsPolicy;

        var csp = ResolveCsp(context.Request.Path);
        if (csp is not null)
            headers["Content-Security-Policy"] = csp;

        foreach (var (name, value) in options.CustomHeaders)
            headers[name] = value;

        foreach (var name in options.HeadersToRemove)
            headers.Remove(name);

        return next(context);
    }

    private string? ResolveCsp(PathString requestPath)
    {
        foreach (var (prefix, policy) in options.RoutePolicies)
        {
            if (requestPath.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
                return policy;
        }

        return options.ContentSecurityPolicy;
    }
}
