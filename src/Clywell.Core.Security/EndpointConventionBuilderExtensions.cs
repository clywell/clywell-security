namespace Clywell.Core.Security;

public static class EndpointConventionBuilderExtensions
{
    public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, string permissionCode)
        where TBuilder : IEndpointConventionBuilder
        => builder.RequireAuthorization(HasPermissionAttribute.PolicyPrefix + permissionCode);
}