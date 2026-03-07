namespace Clywell.Core.Security;

/// <summary>
/// Configuration for <see cref="SecurityHeadersMiddleware"/>.
/// Provides sensible OWASP-recommended defaults that can be overridden per application.
/// </summary>
public sealed class SecurityHeadersOptions
{
    private string? _contentSecurityPolicy = "default-src 'self'; frame-ancestors 'none'";
    private readonly Dictionary<string, string> _routePolicies = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _customHeaders = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<string> _headersToRemove = ["Server", "X-Powered-By"];

    /// <summary>
    /// Value for the <c>X-Content-Type-Options</c> header.
    /// Set to <see langword="null"/> to suppress the header.
    /// Defaults to <c>nosniff</c>.
    /// </summary>
    public string? ContentTypeOptions { get; set; } = "nosniff";

    /// <summary>
    /// Value for the <c>X-Frame-Options</c> header.
    /// Set to <see langword="null"/> to suppress the header.
    /// Defaults to <c>DENY</c>.
    /// </summary>
    public string? FrameOptions { get; set; } = "DENY";

    /// <summary>
    /// Value for the <c>Referrer-Policy</c> header.
    /// Set to <see langword="null"/> to suppress the header.
    /// Defaults to <c>strict-origin-when-cross-origin</c>.
    /// </summary>
    public string? ReferrerPolicy { get; set; } = "strict-origin-when-cross-origin";

    /// <summary>
    /// Value for the <c>Permissions-Policy</c> header.
    /// Set to <see langword="null"/> to suppress the header.
    /// </summary>
    public string? PermissionsPolicy { get; set; } =
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), usb=()";

    internal string? ContentSecurityPolicy => _contentSecurityPolicy;
    internal IReadOnlyDictionary<string, string> RoutePolicies => _routePolicies;
    internal IReadOnlyDictionary<string, string> CustomHeaders => _customHeaders;
    internal IReadOnlyList<string> HeadersToRemove => _headersToRemove;

    /// <summary>
    /// Sets the global <c>Content-Security-Policy</c> header value as a raw string.
    /// Set to <see langword="null"/> to suppress the header.
    /// </summary>
    public SecurityHeadersOptions WithContentSecurityPolicy(string? policy)
    {
        _contentSecurityPolicy = policy;
        return this;
    }

    /// <summary>
    /// Builds and sets the global <c>Content-Security-Policy</c> header using <see cref="CspBuilder"/>.
    /// </summary>
    public SecurityHeadersOptions WithContentSecurityPolicy(Action<CspBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new CspBuilder();
        configure(builder);
        _contentSecurityPolicy = builder.Build();
        return this;
    }

    /// <summary>
    /// Registers a <c>Content-Security-Policy</c> override for requests whose path starts with
    /// <paramref name="pathPrefix"/>. The most specific prefix is matched first.
    /// </summary>
    public SecurityHeadersOptions AddRouteContentSecurityPolicy(string pathPrefix, string policy)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pathPrefix);
        ArgumentException.ThrowIfNullOrWhiteSpace(policy);
        _routePolicies[pathPrefix] = policy;
        return this;
    }

    /// <summary>
    /// Registers a <c>Content-Security-Policy</c> override for requests whose path starts with
    /// <paramref name="pathPrefix"/>, using <see cref="CspBuilder"/> to construct the policy.
    /// </summary>
    public SecurityHeadersOptions AddRouteContentSecurityPolicy(string pathPrefix, Action<CspBuilder> configure)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pathPrefix);
        ArgumentNullException.ThrowIfNull(configure);
        var builder = new CspBuilder();
        configure(builder);
        _routePolicies[pathPrefix] = builder.Build();
        return this;
    }

    /// <summary>
    /// Appends a custom response header that will be set on every response.
    /// </summary>
    public SecurityHeadersOptions AddHeader(string name, string value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        _customHeaders[name] = value;
        return this;
    }

    /// <summary>
    /// Adds a response header name to the removal list (in addition to the default
    /// <c>Server</c> and <c>X-Powered-By</c>).
    /// </summary>
    public SecurityHeadersOptions RemoveHeader(string name)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        if (!_headersToRemove.Contains(name, StringComparer.OrdinalIgnoreCase))
            _headersToRemove.Add(name);
        return this;
    }
}