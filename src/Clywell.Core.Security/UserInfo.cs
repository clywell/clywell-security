using System.Collections.Immutable;

namespace Clywell.Core.Security;

public sealed record UserInfo(
    string UserId,
    string? Email = null,
    string? DisplayName = null,
    IReadOnlySet<string>? Roles = null,
    IReadOnlySet<string>? Permissions = null,
    ImmutableDictionary<string, object>? Properties = null);
