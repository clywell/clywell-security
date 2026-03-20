namespace Clywell.Core.Security;

/// <summary>
/// Validates the <c>X-Step-Up-Proof</c> header on the current HTTP request.
/// Use this in command handlers for dynamic (runtime-determined) step-up requirements;
/// for static (endpoint-declared) requirements use <see cref="EndpointConventionBuilderExtensions.RequireStepUp{TBuilder}"/>.
/// </summary>
public interface IStepUpProofValidator
{
    /// <summary>
    /// Reads and validates the <c>X-Step-Up-Proof</c> JWT from the current HTTP context.
    /// </summary>
    /// <param name="requiredOperationContext">
    /// When provided, the proof token's <c>operation_context</c> claim must equal this value exactly.
    /// </param>
    StepUpProofValidationResult Validate(string? requiredOperationContext = null);
}
