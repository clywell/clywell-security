namespace Clywell.Core.Security;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSecurity(this IServiceCollection services, Action<SecurityOptions>? configure = null)
    {
        services.TryAddScoped<CurrentUser>();
        services.TryAddScoped<ICurrentUser>(sp => sp.GetRequiredService<CurrentUser>());

        var options = new SecurityOptions();
        configure?.Invoke(options);
        options.Apply(services);

        if (options.PermissionAuthorizationEnabled)
        {
            var permissionCodes = options.PermissionCodes;
            var claimType = options.PermissionClaimType;

            services.PostConfigure<AuthorizationOptions>(authOptions =>
            {
                foreach (var code in permissionCodes)
                {
                    authOptions.AddPolicy(
                        HasPermissionAttribute.PolicyPrefix + code,
                        policy => policy.RequireClaim(claimType, code));
                }
            });
        }

        if (options.StepUpAuthorizationEnabled)
        {
            services.AddAuthorizationCore();
            services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthorizationHandler, StepUpAuthorizationHandler>());
            services.TryAddScoped<IStepUpProofValidator, StepUpProofValidator>();
        }

        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        return services;
    }
}
