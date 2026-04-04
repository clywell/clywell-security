namespace Clywell.Core.Security;

public static class EndpointConventionBuilderExtensions
{
    /// <summary>
    /// Requires the caller to hold the specified permission code.
    /// Applies the <c>Permission:&lt;permissionCode&gt;</c> authorization policy registered by
    /// <see cref="SecurityOptions.UsePermissionAuthorization"/>.
    /// </summary>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <param name="permissionCode">The permission code to require (e.g. <c>"articles.edit"</c>).</param>
    public static TBuilder RequirePermission<TBuilder>(this TBuilder builder, string permissionCode)
        where TBuilder : IEndpointConventionBuilder
        => builder.RequireAuthorization(HasPermissionAttribute.PolicyPrefix + permissionCode);

    /// <summary>
    /// Requires the caller's token to have been issued via step-up authentication (<c>acr=step-up</c>).
    /// </summary>
    /// <param name="builder">The endpoint convention builder.</param>
    /// <param name="requiredOperationContext">
    /// When provided, also verifies the token's <c>operation_context</c> claim matches this value.
    /// </param>
    public static TBuilder RequireStepUp<TBuilder>(this TBuilder builder, string? requiredOperationContext = null)
        where TBuilder : IEndpointConventionBuilder
    {
        var policy = new AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .AddRequirements(new StepUpRequirement(requiredOperationContext))
            .Build();
        return builder.RequireAuthorization(policy);
    }
}