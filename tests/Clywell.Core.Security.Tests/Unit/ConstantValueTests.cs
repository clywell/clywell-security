namespace Clywell.Core.Security.Tests.Unit;

public class ConstantValueTests
{
    [Fact]
    public void SecurityHeaderNames_StepUpProof_IsCorrectString() =>
        Assert.Equal("X-Step-Up-Proof", SecurityHeaderNames.StepUpProof);
}
