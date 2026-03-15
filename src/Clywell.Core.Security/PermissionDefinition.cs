namespace Clywell.Core.Security;

public readonly record struct PermissionDefinition(string Code, string Name, string Description, string Category)
{
    public static implicit operator string(PermissionDefinition permission) => permission.Code;

    public override string ToString() => Code;
}
