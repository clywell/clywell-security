namespace Clywell.Core.Security;

[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class HasPermissionAttribute(string permission) : AuthorizeAttribute(policy: PolicyPrefix + permission)
{
    internal const string PolicyPrefix = "Permission:";
}
