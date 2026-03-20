namespace Clywell.Core.Security;

/// <summary>HTTP header name constants used by the Clywell security infrastructure.</summary>
public static class SecurityHeaderNames
{
    /// <summary>
    /// Header that carries a step-up proof token alongside the normal Authorization bearer.
    /// Value: <c>X-Step-Up-Proof</c>
    /// </summary>
    public const string StepUpProof = "X-Step-Up-Proof";
}
