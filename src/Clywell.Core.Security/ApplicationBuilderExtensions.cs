namespace Clywell.Core.Security;

public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseUserContext(this IApplicationBuilder app)
        => app.UseMiddleware<UserContextResolutionMiddleware>();

    public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder app)
        => app.UseMiddleware<SecurityHeadersMiddleware>();
}
