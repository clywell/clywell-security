namespace Clywell.Core.Security.Tests.Unit;

public class PermissionAuthorizationHandlerTests
{
    [Fact]
    public async Task HandleAsync_UserHasPermission_Succeeds()
    {
        var currentUser = new CurrentUser();
        currentUser.SetUser(new UserInfo("user-1", Permissions: new HashSet<string> { "articles.edit" }), null);

        var handler = new PermissionAuthorizationHandler(currentUser);
        var requirement = new PermissionRequirement("articles.edit");
        var context = CreateAuthorizationContext(requirement);

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleAsync_UserLacksPermission_DoesNotSucceed()
    {
        var currentUser = new CurrentUser();
        currentUser.SetUser(new UserInfo("user-1", Permissions: new HashSet<string> { "articles.view" }), null);

        var handler = new PermissionAuthorizationHandler(currentUser);
        var requirement = new PermissionRequirement("articles.edit");
        var context = CreateAuthorizationContext(requirement);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleAsync_UnauthenticatedUser_DoesNotSucceed()
    {
        var currentUser = new CurrentUser();
        var handler = new PermissionAuthorizationHandler(currentUser);
        var requirement = new PermissionRequirement("articles.edit");
        var context = CreateAuthorizationContext(requirement);

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    private static AuthorizationHandlerContext CreateAuthorizationContext(IAuthorizationRequirement requirement)
    {
        var identity = new ClaimsIdentity("Bearer");
        var principal = new ClaimsPrincipal(identity);
        return new AuthorizationHandlerContext([requirement], principal, null);
    }
}
