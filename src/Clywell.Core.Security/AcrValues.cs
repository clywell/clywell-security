namespace Clywell.Core.Security;

/// <summary>
/// Well-known Authentication Context Class Reference (acr) values stamped into JWTs.
/// These describe how the user authenticated, not what they are authorised to do.
/// </summary>
public static class AcrValues
{
    /// <summary>Password-only authentication.</summary>
    public const string Password = "pwd";

    /// <summary>Multi-factor authentication (password + TOTP or backup code).</summary>
    public const string Mfa = "mfa";

    /// <summary>Step-up re-authentication. Present only in step-up proof tokens, never in session tokens.</summary>
    public const string StepUp = "step-up";

    /// <summary>Authentication via an external OAuth/OIDC social provider.</summary>
    public const string Social = "social";

    /// <summary>Authentication via an API key.</summary>
    public const string ApiKey = "api_key";
}
