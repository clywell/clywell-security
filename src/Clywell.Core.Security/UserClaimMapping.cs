namespace Clywell.Core.Security;

/// <summary>Maps JWT claim types to Clywell security concepts. Override individual properties to support non-standard claim names.</summary>
public sealed class UserClaimMapping
{
    /// <summary>Claim type used for the user identifier. Defaults to <c>sub</c>.</summary>
    public string UserId { get; set; } = SecurityClaimTypes.Subject;

    /// <summary>Claim type used for the user's email address. Defaults to <c>email</c>.</summary>
    public string Email { get; set; } = SecurityClaimTypes.Email;

    /// <summary>Claim type used for the user's display name. Defaults to <c>name</c>.</summary>
    public string DisplayName { get; set; } = SecurityClaimTypes.Name;

    /// <summary>Claim type used for role values. Defaults to <c>role</c>.</summary>
    public string Roles { get; set; } = SecurityClaimTypes.Role;

    /// <summary>Claim type used for permission values. Defaults to <c>permission</c>.</summary>
    public string Permissions { get; set; } = SecurityClaimTypes.Permission;
}
