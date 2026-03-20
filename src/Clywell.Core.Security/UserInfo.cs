using System.Collections.Immutable;

namespace Clywell.Core.Security;

/// <summary>Immutable snapshot of the authenticated user's identity and claims, populated by <see cref="IUserContextResolver"/> and stored in <see cref="CurrentUser"/>.</summary>
/// <param name="UserId">Required user identifier.</param>
/// <param name="Email">Optional email address.</param>
/// <param name="DisplayName">Optional display name.</param>
/// <param name="Roles">Optional role set.</param>
/// <param name="Permissions">Optional permission set.</param>
/// <param name="Properties">Optional additional user properties.</param>
/// <param name="Acr">Optional Authentication Context Class Reference claim value.</param>
/// <param name="OperationContext">Optional operation context claim value.</param>
public sealed record UserInfo(
    string UserId,
    string? Email = null,
    string? DisplayName = null,
    IReadOnlySet<string>? Roles = null,
    IReadOnlySet<string>? Permissions = null,
    ImmutableDictionary<string, object>? Properties = null,
    string? Acr = null,
    string? OperationContext = null);
