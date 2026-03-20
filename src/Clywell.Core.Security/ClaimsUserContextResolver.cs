namespace Clywell.Core.Security;

/// <summary>Default <see cref="IUserContextResolver"/> that builds a <see cref="UserInfo"/> from the authenticated <see cref="ClaimsPrincipal"/> using the configured <see cref="UserClaimMapping"/>.</summary>
public sealed class ClaimsUserContextResolver(UserClaimMapping mapping) : IUserContextResolver
{
    public ClaimsUserContextResolver() : this(new UserClaimMapping()) { }

    public Task<UserInfo?> ResolveAsync(HttpContext context)
    {
        if (context.User.Identity?.IsAuthenticated != true)
            return Task.FromResult<UserInfo?>(null);

        var userId = context.User.FindFirst(mapping.UserId)?.Value;
        if (userId is null)
            return Task.FromResult<UserInfo?>(null);

        var email = context.User.FindFirst(mapping.Email)?.Value;
        var displayName = context.User.FindFirst(mapping.DisplayName)?.Value;

        var roles = context.User.FindAll(mapping.Roles)
            .Select(c => c.Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var permissions = context.User.FindAll(mapping.Permissions)
            .Select(c => c.Value)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var acr = context.User.FindFirst(SecurityClaimTypes.Acr)?.Value;
        var operationContext = context.User.FindFirst(SecurityClaimTypes.OperationContext)?.Value;

        return Task.FromResult<UserInfo?>(new UserInfo(
            UserId: userId,
            Email: email,
            DisplayName: displayName,
            Roles: roles,
            Permissions: permissions,
            Acr: acr,
            OperationContext: operationContext));
    }
}
