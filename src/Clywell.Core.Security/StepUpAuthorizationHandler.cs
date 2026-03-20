namespace Clywell.Core.Security;

/// <summary>
/// Handles <see cref="StepUpRequirement"/> by validating the <c>X-Step-Up-Proof</c> header token.
/// The proof token is independent of the <c>Authorization</c> bearer - it asserts that
/// the user completed a step-up re-authentication immediately before this request.
/// </summary>
public sealed class StepUpAuthorizationHandler(IStepUpProofValidator proofValidator)
    : AuthorizationHandler<StepUpRequirement>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        StepUpRequirement requirement)
    {
        var result = proofValidator.Validate(requirement.RequiredOperationContext);
        if (result == StepUpProofValidationResult.Valid)
            context.Succeed(requirement);

        return Task.CompletedTask;
    }
}