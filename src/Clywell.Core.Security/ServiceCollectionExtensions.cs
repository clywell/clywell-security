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

        services.AddAuthorizationCore();
        services.TryAddSingleton<IAuthorizationPolicyProvider, PermissionPolicyProvider>();
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthorizationHandler, PermissionAuthorizationHandler>());
        services.TryAddEnumerable(ServiceDescriptor.Scoped<IAuthorizationHandler, StepUpAuthorizationHandler>());
        services.TryAddScoped<IStepUpProofValidator, StepUpProofValidator>();

        services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();

        return services;
    }
}
