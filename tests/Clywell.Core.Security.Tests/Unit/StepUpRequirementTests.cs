namespace Clywell.Core.Security.Tests.Unit;

public class StepUpRequirementTests
{
    [Fact]
    public void Constructor_WithNoOperationContext_RequiredOperationContextIsNull()
    {
        var requirement = new StepUpRequirement();

        Assert.Null(requirement.RequiredOperationContext);
    }

    [Fact]
    public void Constructor_WithOperationContext_SetsRequiredOperationContext()
    {
        var requirement = new StepUpRequirement("delete_account");

        Assert.Equal("delete_account", requirement.RequiredOperationContext);
    }
}