namespace Clywell.Core.Security;

/// <summary>Resolves the current user's identity from the <see cref="HttpContext"/>. Implement this interface to support custom token formats or claim mappings.</summary>
public interface IUserContextResolver
{
    /// <summary>Resolves a <see cref="UserInfo"/> from the current <see cref="HttpContext"/>. Returns <c>null</c> when the request is unauthenticated or the user cannot be resolved.</summary>
    Task<UserInfo?> ResolveAsync(HttpContext context);
}
