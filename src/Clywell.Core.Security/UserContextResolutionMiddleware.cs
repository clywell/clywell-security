namespace Clywell.Core.Security;

public sealed class UserContextResolutionMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext context, IUserContextResolver resolver)
    {
        var currentUser = context.RequestServices.GetRequiredService<CurrentUser>();
        var userInfo = await resolver.ResolveAsync(context);
        currentUser.SetIpAddress(context.Connection.RemoteIpAddress?.ToString());
        if (userInfo is not null)
            currentUser.SetUser(userInfo, context.User);

        await next(context);
    }
}
