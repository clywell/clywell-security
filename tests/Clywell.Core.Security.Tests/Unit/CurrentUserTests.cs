namespace Clywell.Core.Security.Tests.Unit;

using System.Collections.Immutable;

public class CurrentUserTests
{
    [Fact]
    public void Default_IsNotAuthenticated()
    {
        var user = new CurrentUser();

        Assert.False(user.IsAuthenticated);
        Assert.Null(user.UserId);
        Assert.Null(user.Email);
        Assert.Null(user.DisplayName);
        Assert.Null(user.Principal);
        Assert.Empty(user.Roles);
        Assert.Empty(user.Permissions);
    }

    [Fact]
    public void SetUser_SetsAllProperties()
    {
        var user = new CurrentUser();
        var roles = new HashSet<string> { "Admin" };
        var permissions = new HashSet<string> { "articles.edit" };
        var info = new UserInfo("user-1", "test@example.com", "Test User", roles, permissions);
        var principal = new ClaimsPrincipal();

        user.SetUser(info, principal);

        Assert.True(user.IsAuthenticated);
        Assert.Equal("user-1", user.UserId);
        Assert.Equal("test@example.com", user.Email);
        Assert.Equal("Test User", user.DisplayName);
        Assert.Same(principal, user.Principal);
        Assert.Contains("Admin", user.Roles);
        Assert.Contains("articles.edit", user.Permissions);
    }

    [Fact]
    public void SetUser_WithNullRolesAndPermissions_ReturnsEmptySets()
    {
        var user = new CurrentUser();
        var info = new UserInfo("user-1");

        user.SetUser(info, null);

        Assert.True(user.IsAuthenticated);
        Assert.Empty(user.Roles);
        Assert.Empty(user.Permissions);
    }

    [Fact]
    public void IsInRole_ReturnsTrueForMatchingRole()
    {
        var user = new CurrentUser();
        var roles = new HashSet<string> { "Admin", "Editor" };
        user.SetUser(new UserInfo("user-1", Roles: roles), null);

        Assert.True(user.IsInRole("Admin"));
        Assert.True(user.IsInRole("Editor"));
    }

    [Fact]
    public void IsInRole_ReturnsFalseForNonMatchingRole()
    {
        var user = new CurrentUser();
        user.SetUser(new UserInfo("user-1", Roles: new HashSet<string> { "Admin" }), null);

        Assert.False(user.IsInRole("Editor"));
    }

    [Fact]
    public void HasPermission_ReturnsTrueForMatchingPermission()
    {
        var user = new CurrentUser();
        var permissions = new HashSet<string> { "articles.edit", "articles.delete" };
        user.SetUser(new UserInfo("user-1", Permissions: permissions), null);

        Assert.True(user.HasPermission("articles.edit"));
        Assert.True(user.HasPermission("articles.delete"));
    }

    [Fact]
    public void HasPermission_ReturnsFalseForNonMatchingPermission()
    {
        var user = new CurrentUser();
        user.SetUser(new UserInfo("user-1", Permissions: new HashSet<string> { "articles.edit" }), null);

        Assert.False(user.HasPermission("articles.delete"));
    }

    [Fact]
    public void SetUser_OverwritesPreviousUser()
    {
        var user = new CurrentUser();
        user.SetUser(new UserInfo("user-1", "first@example.com"), null);
        user.SetUser(new UserInfo("user-2", "second@example.com"), null);

        Assert.Equal("user-2", user.UserId);
        Assert.Equal("second@example.com", user.Email);
    }

    [Fact]
    public void GetProperty_ReturnsValueWhenPresent()
    {
        var user = new CurrentUser();
        var props = ImmutableDictionary<string, object>.Empty
            .Add("OrganizationId", Guid.Parse("aaaa1111-bbbb-cccc-dddd-eeee2222ffff"))
            .Add("Tier", "premium");
        user.SetUser(new UserInfo("user-1", Properties: props), null);

        Assert.Equal(Guid.Parse("aaaa1111-bbbb-cccc-dddd-eeee2222ffff"), user.GetProperty<Guid>("OrganizationId"));
        Assert.Equal("premium", user.GetProperty<string>("Tier"));
    }

    [Fact]
    public void GetProperty_ReturnsDefaultWhenKeyMissing()
    {
        var user = new CurrentUser();
        user.SetUser(new UserInfo("user-1", Properties: ImmutableDictionary<string, object>.Empty), null);

        Assert.Null(user.GetProperty<string>("Missing"));
        Assert.Equal(Guid.Empty, user.GetProperty<Guid>("Missing"));
    }

    [Fact]
    public void GetProperty_ReturnsDefaultWhenPropertiesNull()
    {
        var user = new CurrentUser();
        user.SetUser(new UserInfo("user-1"), null);

        Assert.Null(user.GetProperty<string>("Anything"));
    }

    [Fact]
    public void GetProperty_ReturnsDefaultWhenTypeMismatch()
    {
        var user = new CurrentUser();
        var props = ImmutableDictionary<string, object>.Empty.Add("Count", "not-an-int");
        user.SetUser(new UserInfo("user-1", Properties: props), null);

        Assert.Equal(0, user.GetProperty<int>("Count"));
    }

    [Fact]
    public void GetProperty_ReturnsDefaultWhenNotAuthenticated()
    {
        var user = new CurrentUser();

        Assert.Null(user.GetProperty<string>("Key"));
    }

    [Fact]
    public void Default_IpAddress_IsNull()
    {
        var user = new CurrentUser();

        Assert.Null(user.IpAddress);
    }

    [Fact]
    public void SetIpAddress_StoresAddress()
    {
        var user = new CurrentUser();

        user.SetIpAddress("192.168.1.100");

        Assert.Equal("192.168.1.100", user.IpAddress);
    }

    [Fact]
    public void SetIpAddress_CanBeSetBeforeAuthentication()
    {
        var user = new CurrentUser();
        user.SetIpAddress("10.0.0.1");

        Assert.Equal("10.0.0.1", user.IpAddress);
        Assert.False(user.IsAuthenticated);
    }
}
