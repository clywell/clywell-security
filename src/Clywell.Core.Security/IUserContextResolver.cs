namespace Clywell.Core.Security;

public interface IUserContextResolver
{
    Task<UserInfo?> ResolveAsync(HttpContext context);
}
