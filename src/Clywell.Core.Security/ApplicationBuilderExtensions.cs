namespace Clywell.Core.Security;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseUserContext(this IApplicationBuilder app)
        => app.UseMiddleware<UserContextResolutionMiddleware>();

    /// <summary>
    /// Adds <see cref="SecurityHeadersMiddleware"/> to the pipeline.
    /// Call with no arguments to apply OWASP-recommended defaults, or supply a
    /// <paramref name="configure"/> action to customise any header value.
    /// </summary>
    public static IApplicationBuilder UseSecurityHeaders(
        this IApplicationBuilder app,
        Action<SecurityHeadersOptions>? configure = null)
    {
        var options = new SecurityHeadersOptions();
        configure?.Invoke(options);
        return app.UseMiddleware<SecurityHeadersMiddleware>(options);
    }
}
