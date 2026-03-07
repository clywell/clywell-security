namespace Clywell.Core.Security.Tests.Unit;

public class CspBuilderTests
{
    [Fact]
    public void Build_SingleDirective_ReturnsCorrectString()
    {
        var result = new CspBuilder().Default("'self'").Build();
        Assert.Equal("default-src 'self'", result);
    }

    [Fact]
    public void Build_MultipleDirectives_JoinsWithSemicolon()
    {
        var result = new CspBuilder()
            .Default("'self'")
            .Script("'self'", "'unsafe-inline'")
            .FrameAncestors("'none'")
            .Build();

        Assert.Contains("default-src 'self'", result);
        Assert.Contains("script-src 'self' 'unsafe-inline'", result);
        Assert.Contains("frame-ancestors 'none'", result);
    }

    [Fact]
    public void Build_DuplicateDirectiveName_LastValueWins()
    {
        var result = new CspBuilder()
            .Default("'self'")
            .Default("'none'")
            .Build();

        Assert.Equal("default-src 'none'", result);
    }

    [Fact]
    public void Build_AllDirectives_Supported()
    {
        var result = new CspBuilder()
            .Default("'self'")
            .Script("'self'")
            .Style("'self'")
            .Image("'self'")
            .Font("'self'")
            .Connect("'self'")
            .FrameAncestors("'none'")
            .Media("'self'")
            .Object("'none'")
            .Worker("'self'")
            .FormAction("'self'")
            .Build();

        Assert.Contains("script-src", result);
        Assert.Contains("style-src", result);
        Assert.Contains("img-src", result);
        Assert.Contains("font-src", result);
        Assert.Contains("connect-src", result);
        Assert.Contains("media-src", result);
        Assert.Contains("object-src", result);
        Assert.Contains("worker-src", result);
        Assert.Contains("form-action", result);
    }
}
