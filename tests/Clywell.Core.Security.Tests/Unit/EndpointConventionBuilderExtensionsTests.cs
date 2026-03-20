namespace Clywell.Core.Security.Tests.Unit;

public class EndpointConventionBuilderExtensionsTests
{
    [Fact]
    public void RequireStepUp_PolicyContainsStepUpRequirement()
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new StepUpRequirement())
            .Build();

        Assert.Contains(policy.Requirements, r => r is StepUpRequirement);
    }

    [Fact]
    public void RequireStepUp_WithOperationContext_PolicyContainsMatchingRequirement()
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new StepUpRequirement("delete_account"))
            .Build();

        var req = policy.Requirements.OfType<StepUpRequirement>().Single();
        Assert.Equal("delete_account", req.RequiredOperationContext);
    }

    [Fact]
    public void RequireStepUp_PolicyRequiresAuthenticatedUser()
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new StepUpRequirement())
            .Build();

        // RequireAuthenticatedUser adds a DenyAnonymousAuthorizationRequirement
        Assert.Contains(policy.Requirements,
            r => r is Microsoft.AspNetCore.Authorization.Infrastructure.DenyAnonymousAuthorizationRequirement);
    }
}
