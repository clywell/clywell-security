namespace Clywell.Core.Security;

/// <summary>Well-known JWT claim type URI strings used throughout the Clywell security infrastructure.</summary>
public static class SecurityClaimTypes
{
    /// <summary>Subject identifier claim (<c>sub</c>). Carries the user's unique ID.</summary>
    public const string Subject = "sub";

    /// <summary>Email address claim (<c>email</c>).</summary>
    public const string Email = "email";

    /// <summary>Display name claim (<c>name</c>).</summary>
    public const string Name = "name";

    /// <summary>Role claim (<c>role</c>). A user may have multiple role claims.</summary>
    public const string Role = "role";

    /// <summary>Permission claim (<c>permission</c>). A user may have multiple permission claims.</summary>
    public const string Permission = "permission";

    /// <summary>
    /// Authentication Context Class Reference claim (<c>acr</c>).
    /// Describes the assurance level of the authentication event.
    /// </summary>
    public const string Acr = "acr";

    /// <summary>
    /// Operation context claim (<c>operation_context</c>).
    /// Present in step-up proof tokens to scope them to a specific sensitive operation.
    /// </summary>
    public const string OperationContext = "operation_context";

    /// <summary>Session identifier claim (<c>sid</c>). Identifies the authentication session.</summary>
    public const string Sid = "sid";
}
