namespace Clywell.Core.Security;

/// <summary>
/// ASP.NET Core authorization requirement that mandates a valid step-up proof token
/// in the <c>X-Step-Up-Proof</c> request header (<c>acr = "step-up"</c>).
/// Validation is performed by <see cref="StepUpAuthorizationHandler"/> via <see cref="IStepUpProofValidator"/>.
/// Optionally enforces a specific <c>operation_context</c> claim value.
/// </summary>
/// <param name="requiredOperationContext">
/// When set, the proof token's <c>operation_context</c> claim must equal this value exactly.
/// </param>
public sealed class StepUpRequirement(string? requiredOperationContext = null) : IAuthorizationRequirement
{
    /// <summary>When set, the token's operation_context claim must equal this value.</summary>
    public string? RequiredOperationContext { get; } = requiredOperationContext;
}