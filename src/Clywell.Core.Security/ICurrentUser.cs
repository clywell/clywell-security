namespace Clywell.Core.Security;

/// <summary>Provides read-only access to the authenticated user's identity, roles, permissions, and token metadata for the current request.</summary>
public interface ICurrentUser
{
    /// <summary>The subject identifier (<c>sub</c> claim) of the authenticated user. <c>null</c> when the user is not authenticated.</summary>
    string? UserId { get; }

    /// <summary>The email address of the authenticated user, if present in the token.</summary>
    string? Email { get; }

    /// <summary>The display name of the authenticated user (<c>name</c> claim), if present in the token.</summary>
    string? DisplayName { get; }

    /// <summary>Authentication Context Class Reference. "step-up" when the token was issued via step-up auth.</summary>
    string? Acr { get; }

    /// <summary>The operation context claim from a step-up token, identifying the operation that required step-up.</summary>
    string? OperationContext { get; }

    /// <summary><c>true</c> when a user identity has been resolved for the current request.</summary>
    bool IsAuthenticated { get; }

    /// <summary>The remote IP address of the current request, if available.</summary>
    string? IpAddress { get; }

    /// <summary>The set of roles assigned to the authenticated user.</summary>
    IReadOnlySet<string> Roles { get; }

    /// <summary>The set of permissions granted to the authenticated user.</summary>
    IReadOnlySet<string> Permissions { get; }

    /// <summary>The underlying <see cref="ClaimsPrincipal"/> for the current request. <c>null</c> when the user is not authenticated.</summary>
    ClaimsPrincipal? Principal { get; }

    /// <summary>Returns <c>true</c> if the user holds the specified role (case-insensitive).</summary>
    bool IsInRole(string role);

    /// <summary>Returns <c>true</c> if the user holds the specified permission code (case-insensitive).</summary>
    bool HasPermission(string permission);

    /// <summary>Returns an extended property of type <typeparamref name="T"/> stored on the user context, or <c>null</c> if absent.</summary>
    T? GetProperty<T>(string key);
}
