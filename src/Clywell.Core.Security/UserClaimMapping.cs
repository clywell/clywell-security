namespace Clywell.Core.Security;

public sealed class UserClaimMapping
{
    public string UserId { get; set; } = SecurityClaimTypes.Subject;
    public string Email { get; set; } = SecurityClaimTypes.Email;
    public string DisplayName { get; set; } = SecurityClaimTypes.Name;
    public string Roles { get; set; } = SecurityClaimTypes.Role;
    public string Permissions { get; set; } = SecurityClaimTypes.Permission;
}
