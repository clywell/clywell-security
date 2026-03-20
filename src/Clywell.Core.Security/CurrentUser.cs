using System.Collections.Frozen;

namespace Clywell.Core.Security;

internal sealed class CurrentUser : ICurrentUser
{
    private static readonly IReadOnlySet<string> EmptySet = FrozenSet<string>.Empty;

    private UserInfo? _userInfo;

    public string? UserId => _userInfo?.UserId;
    public string? Email => _userInfo?.Email;
    public string? DisplayName => _userInfo?.DisplayName;
    public string? Acr => _userInfo?.Acr;
    public string? OperationContext => _userInfo?.OperationContext;
    public bool IsAuthenticated => _userInfo is not null;
    public string? IpAddress { get; private set; }
    public IReadOnlySet<string> Roles => _userInfo?.Roles ?? EmptySet;
    public IReadOnlySet<string> Permissions => _userInfo?.Permissions ?? EmptySet;
    public ClaimsPrincipal? Principal { get; private set; }

    public bool IsInRole(string role) => Roles.Contains(role);
    public bool HasPermission(string permission) => Permissions.Contains(permission);

    public T? GetProperty<T>(string key)
    {
        if (_userInfo?.Properties is not null && _userInfo.Properties.TryGetValue(key, out var value))
            return value is T typed ? typed : default;
        return default;
    }

    internal void SetUser(UserInfo userInfo, ClaimsPrincipal? principal)
    {
        _userInfo = userInfo;
        Principal = principal;
    }

    internal void SetIpAddress(string? ipAddress) => IpAddress = ipAddress;
}
