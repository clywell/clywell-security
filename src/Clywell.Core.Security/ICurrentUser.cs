namespace Clywell.Core.Security;

public interface ICurrentUser
{
    string? UserId { get; }
    string? Email { get; }
    string? DisplayName { get; }
    bool IsAuthenticated { get; }
    string? IpAddress { get; }
    IReadOnlySet<string> Roles { get; }
    IReadOnlySet<string> Permissions { get; }
    ClaimsPrincipal? Principal { get; }
    bool IsInRole(string role);
    bool HasPermission(string permission);
    T? GetProperty<T>(string key);
}
