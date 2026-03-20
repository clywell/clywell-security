namespace Clywell.Core.Security.Tests.Unit;

public class ConstantValueTests
{
    [Fact]
    public void AcrValues_Password_IsCorrectString() =>
        Assert.Equal("pwd", AcrValues.Password);

    [Fact]
    public void AcrValues_Mfa_IsCorrectString() =>
        Assert.Equal("mfa", AcrValues.Mfa);

    [Fact]
    public void AcrValues_StepUp_IsCorrectString() =>
        Assert.Equal("step-up", AcrValues.StepUp);

    [Fact]
    public void AcrValues_Social_IsCorrectString() =>
        Assert.Equal("social", AcrValues.Social);

    [Fact]
    public void AcrValues_ApiKey_IsCorrectString() =>
        Assert.Equal("api_key", AcrValues.ApiKey);

    [Fact]
    public void SecurityHeaderNames_StepUpProof_IsCorrectString() =>
        Assert.Equal("X-Step-Up-Proof", SecurityHeaderNames.StepUpProof);
}
