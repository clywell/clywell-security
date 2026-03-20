namespace Clywell.Core.Security.Tests.Unit;

public class StepUpAuthorizationHandlerTests
{
    private static AuthorizationHandlerContext MakeContext(StepUpRequirement requirement) =>
        new([requirement], new ClaimsPrincipal(), null);

    private static StepUpAuthorizationHandler MakeHandler(StepUpProofValidationResult result)
    {
        var validator = new Mock<IStepUpProofValidator>();
        validator.Setup(v => v.Validate(It.IsAny<string?>())).Returns(result);
        return new StepUpAuthorizationHandler(validator.Object);
    }

    [Fact]
    public async Task HandleAsync_ValidProof_NoOperationContext_Succeeds()
    {
        var handler = MakeHandler(StepUpProofValidationResult.Valid);
        var context = MakeContext(new StepUpRequirement());

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleAsync_ValidProof_WithOperationContext_Succeeds()
    {
        var validator = new Mock<IStepUpProofValidator>();
        validator.Setup(v => v.Validate("delete_account")).Returns(StepUpProofValidationResult.Valid);
        var handler = new StepUpAuthorizationHandler(validator.Object);
        var context = MakeContext(new StepUpRequirement("delete_account"));

        await handler.HandleAsync(context);

        Assert.True(context.HasSucceeded);
    }

    [Theory]
    [InlineData(StepUpProofValidationResult.Missing)]
    [InlineData(StepUpProofValidationResult.Invalid)]
    [InlineData(StepUpProofValidationResult.ContextMismatch)]
    [InlineData(StepUpProofValidationResult.Expired)]
    public async Task HandleAsync_NonValidResult_DoesNotSucceed(StepUpProofValidationResult result)
    {
        var handler = MakeHandler(result);
        var context = MakeContext(new StepUpRequirement());

        await handler.HandleAsync(context);

        Assert.False(context.HasSucceeded);
    }

    [Fact]
    public async Task HandleAsync_PassesOperationContextToValidator()
    {
        var validator = new Mock<IStepUpProofValidator>();
        validator.Setup(v => v.Validate("approve_payment")).Returns(StepUpProofValidationResult.Valid);
        var handler = new StepUpAuthorizationHandler(validator.Object);
        var context = MakeContext(new StepUpRequirement("approve_payment"));

        await handler.HandleAsync(context);

        validator.Verify(v => v.Validate("approve_payment"), Times.Once);
    }
}