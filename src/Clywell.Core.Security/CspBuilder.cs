namespace Clywell.Core.Security;

/// <summary>
/// Fluent builder for constructing Content-Security-Policy header values.
/// </summary>
public sealed class CspBuilder
{
    private readonly Dictionary<string, string[]> _directives = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>Sets the <c>default-src</c> directive.</summary>
    public CspBuilder Default(params string[] sources) => Set("default-src", sources);

    /// <summary>Sets the <c>script-src</c> directive.</summary>
    public CspBuilder Script(params string[] sources) => Set("script-src", sources);

    /// <summary>Sets the <c>style-src</c> directive.</summary>
    public CspBuilder Style(params string[] sources) => Set("style-src", sources);

    /// <summary>Sets the <c>img-src</c> directive.</summary>
    public CspBuilder Image(params string[] sources) => Set("img-src", sources);

    /// <summary>Sets the <c>font-src</c> directive.</summary>
    public CspBuilder Font(params string[] sources) => Set("font-src", sources);

    /// <summary>Sets the <c>connect-src</c> directive.</summary>
    public CspBuilder Connect(params string[] sources) => Set("connect-src", sources);

    /// <summary>Sets the <c>frame-ancestors</c> directive.</summary>
    public CspBuilder FrameAncestors(params string[] sources) => Set("frame-ancestors", sources);

    /// <summary>Sets the <c>media-src</c> directive.</summary>
    public CspBuilder Media(params string[] sources) => Set("media-src", sources);

    /// <summary>Sets the <c>object-src</c> directive.</summary>
    public CspBuilder Object(params string[] sources) => Set("object-src", sources);

    /// <summary>Sets the <c>worker-src</c> directive.</summary>
    public CspBuilder Worker(params string[] sources) => Set("worker-src", sources);

    /// <summary>Sets the <c>form-action</c> directive.</summary>
    public CspBuilder FormAction(params string[] sources) => Set("form-action", sources);

    private CspBuilder Set(string directive, string[] sources)
    {
        _directives[directive] = sources;
        return this;
    }

    /// <summary>Builds the CSP header value string.</summary>
    public string Build()
        => string.Join("; ", _directives.Select(d => $"{d.Key} {string.Join(" ", d.Value)}"));
}