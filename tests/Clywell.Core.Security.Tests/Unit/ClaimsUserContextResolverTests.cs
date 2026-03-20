namespace Clywell.Core.Security.Tests.Unit;

public class ClaimsUserContextResolverTests
{
    private static DefaultHttpContext CreateAuthenticatedContext(params Claim[] claims)
    {
        var identity = new ClaimsIdentity(claims, "Bearer");
        return new DefaultHttpContext { User = new ClaimsPrincipal(identity) };
    }

    private static DefaultHttpContext CreateUnauthenticatedContext() => new();

    private readonly ClaimsUserContextResolver _resolver = new();

    [Fact]
    public async Task ResolveAsync_AuthenticatedWithSubClaim_ReturnsUserInfo()
    {
        var context = CreateAuthenticatedContext(new Claim("sub", "user-123"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal("user-123", result.UserId);
    }

    [Fact]
    public async Task ResolveAsync_SetsEmailFromStandardClaim()
    {
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("email", "test@example.com"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal("test@example.com", result.Email);
    }

    [Fact]
    public async Task ResolveAsync_SetsDisplayNameFromNameClaim()
    {
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("name", "John Doe"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal("John Doe", result.DisplayName);
    }

    [Fact]
    public async Task ResolveAsync_CollectsMultipleRoleClaims()
    {
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("role", "Admin"),
            new Claim("role", "Editor"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal(2, result.Roles!.Count);
        Assert.Contains("Admin", result.Roles);
        Assert.Contains("Editor", result.Roles);
    }

    [Fact]
    public async Task ResolveAsync_CollectsPermissions()
    {
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("permission", "articles.edit"),
            new Claim("permission", "articles.delete"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal(2, result.Permissions!.Count);
        Assert.Contains("articles.edit", result.Permissions);
        Assert.Contains("articles.delete", result.Permissions);
    }

    [Fact]
    public async Task ResolveAsync_RolesAreCaseInsensitive()
    {
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("role", "Admin"),
            new Claim("role", "admin"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Single(result.Roles!);
    }

    [Fact]
    public async Task ResolveAsync_AuthenticatedWithNoSubClaim_ReturnsNull()
    {
        var context = CreateAuthenticatedContext(new Claim("email", "test@example.com"));

        var result = await _resolver.ResolveAsync(context);

        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveAsync_Unauthenticated_ReturnsNull()
    {
        var context = CreateUnauthenticatedContext();

        var result = await _resolver.ResolveAsync(context);

        Assert.Null(result);
    }

    [Fact]
    public async Task ResolveAsync_CustomUserIdClaimType_ReturnsUserInfo()
    {
        var mapping = new UserClaimMapping { UserId = "user_id" };
        var resolver = new ClaimsUserContextResolver(mapping);
        var context = CreateAuthenticatedContext(new Claim("user_id", "custom-123"));

        var result = await resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal("custom-123", result.UserId);
    }

    [Fact]
    public async Task ResolveAsync_CustomRoleClaimType_CollectsRoles()
    {
        var mapping = new UserClaimMapping { Roles = "roles" };
        var resolver = new ClaimsUserContextResolver(mapping);
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("roles", "TenantAdmin"),
            new Claim("roles", "Billing"));

        var result = await resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal(2, result.Roles!.Count);
        Assert.Contains("TenantAdmin", result.Roles);
    }

    [Fact]
    public async Task ResolveAsync_CustomPermissionClaimType_CollectsPermissions()
    {
        var mapping = new UserClaimMapping { Permissions = "scope" };
        var resolver = new ClaimsUserContextResolver(mapping);
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("scope", "articles:read"),
            new Claim("scope", "articles:write"));

        var result = await resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal(2, result.Permissions!.Count);
        Assert.Contains("articles:read", result.Permissions);
    }

    [Fact]
    public async Task ResolveAsync_SetsAcrFromClaim()
    {
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("acr", "step-up"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal("step-up", result.Acr);
    }

    [Fact]
    public async Task ResolveAsync_SetsOperationContextFromClaim()
    {
        var context = CreateAuthenticatedContext(
            new Claim("sub", "user-1"),
            new Claim("operation_context", "approve_payment"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Equal("approve_payment", result.OperationContext);
    }

    [Fact]
    public async Task ResolveAsync_AcrAndOperationContext_AreNullWhenClaimsAbsent()
    {
        var context = CreateAuthenticatedContext(new Claim("sub", "user-1"));

        var result = await _resolver.ResolveAsync(context);

        Assert.NotNull(result);
        Assert.Null(result.Acr);
        Assert.Null(result.OperationContext);
    }
}
