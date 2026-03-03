using Microsoft.Extensions.Options;

namespace Clywell.Core.Security.Tests.Unit;

public class PermissionPolicyProviderTests
{
    private static PermissionPolicyProvider CreateProvider(AuthorizationOptions? authOptions = null)
    {
        var options = Options.Create(authOptions ?? new AuthorizationOptions());
        return new PermissionPolicyProvider(options);
    }

    [Fact]
    public async Task GetPolicyAsync_WithPermissionPrefix_ReturnsPolicy()
    {
        var provider = CreateProvider();

        var policy = await provider.GetPolicyAsync("Permission:articles.edit");

        Assert.NotNull(policy);
        Assert.Single(policy.Requirements);
        var requirement = Assert.IsType<PermissionRequirement>(policy.Requirements[0]);
        Assert.Equal("articles.edit", requirement.Permission);
    }

    [Fact]
    public async Task GetPolicyAsync_WithoutPrefix_ReturnsNull()
    {
        var provider = CreateProvider();

        var policy = await provider.GetPolicyAsync("SomeOtherPolicy");

        Assert.Null(policy);
    }

    [Fact]
    public async Task GetPolicyAsync_RegisteredPolicy_ReturnsRegisteredPolicy()
    {
        var authOptions = new AuthorizationOptions();
        authOptions.AddPolicy("CustomPolicy", b => b.RequireAuthenticatedUser());
        var provider = CreateProvider(authOptions);

        var policy = await provider.GetPolicyAsync("CustomPolicy");

        Assert.NotNull(policy);
    }

    [Fact]
    public async Task GetPolicyAsync_PermissionPrefixIsCaseSensitive()
    {
        var provider = CreateProvider();

        var policy = await provider.GetPolicyAsync("permission:articles.edit");

        Assert.Null(policy);
    }
}
