namespace Clywell.Core.Security;

/// <summary>Result of validating the <c>X-Step-Up-Proof</c> header token.</summary>
public enum StepUpProofValidationResult
{
    /// <summary>The proof token is valid, acr is "step-up", and any required operation context matches.</summary>
    Valid,

    /// <summary>The <c>X-Step-Up-Proof</c> header was absent.</summary>
    Missing,

    /// <summary>The proof token failed signature validation, is malformed, or is not a step-up proof token.</summary>
    Invalid,

    /// <summary>The proof token's <c>operation_context</c> claim does not match the required value.</summary>
    ContextMismatch,

    /// <summary>The proof token has expired.</summary>
    Expired,
}
