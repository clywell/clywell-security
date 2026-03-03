namespace Clywell.Core.Security.Tests.Unit;

public class UserContextResolutionMiddlewareTests
{
    // Wires up an HttpContext whose RequestServices contains a CurrentUser instance,
    // mirroring how ASP.NET Core creates the per-request DI scope.
    private static (DefaultHttpContext context, CurrentUser currentUser) CreateContext()
    {
        var currentUser = new CurrentUser();
        var services = new ServiceCollection();
        services.AddSingleton(currentUser);
        return (new DefaultHttpContext { RequestServices = services.BuildServiceProvider() }, currentUser);
    }

    [Fact]
    public async Task InvokeAsync_ResolvedUser_SetsCurrentUser()
    {
        var userInfo = new UserInfo("user-1", "test@example.com");
        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync(userInfo);

        var (context, currentUser) = CreateContext();
        var nextCalled = false;

        var middleware = new UserContextResolutionMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        await middleware.InvokeAsync(context, resolver.Object);

        Assert.True(currentUser.IsAuthenticated);
        Assert.Equal("user-1", currentUser.UserId);
        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_NullUser_DoesNotSetCurrentUser()
    {
        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync((UserInfo?)null);

        var (context, currentUser) = CreateContext();
        var middleware = new UserContextResolutionMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context, resolver.Object);

        Assert.False(currentUser.IsAuthenticated);
    }

    [Fact]
    public async Task InvokeAsync_AlwaysCallsNext()
    {
        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync((UserInfo?)null);

        var nextCalled = false;
        var middleware = new UserContextResolutionMiddleware(_ =>
        {
            nextCalled = true;
            return Task.CompletedTask;
        });

        var (context, _) = CreateContext();
        await middleware.InvokeAsync(context, resolver.Object);

        Assert.True(nextCalled);
    }

    [Fact]
    public async Task InvokeAsync_CallsResolverExactlyOnce()
    {
        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync(new UserInfo("user-1"));

        var (context, _) = CreateContext();
        var middleware = new UserContextResolutionMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context, resolver.Object);

        resolver.Verify(r => r.ResolveAsync(It.IsAny<HttpContext>()), Times.Once);
    }

    [Fact]
    public async Task InvokeAsync_SetsPrincipalFromHttpContext()
    {
        var claims = new[] { new Claim("sub", "user-1") };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, "Bearer"));

        var (context, currentUser) = CreateContext();
        context.User = principal;

        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(context))
            .ReturnsAsync(new UserInfo("user-1"));

        var middleware = new UserContextResolutionMiddleware(_ => Task.CompletedTask);

        await middleware.InvokeAsync(context, resolver.Object);

        Assert.Same(principal, currentUser.Principal);
    }

    [Fact]
    public async Task InvokeAsync_SetsIpAddressFromRemoteIpAddress()
    {
        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync((UserInfo?)null);

        var (context, currentUser) = CreateContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("10.0.0.1");

        var middleware = new UserContextResolutionMiddleware(_ => Task.CompletedTask);
        await middleware.InvokeAsync(context, resolver.Object);

        Assert.Equal("10.0.0.1", currentUser.IpAddress);
    }

    [Fact]
    public async Task InvokeAsync_NullRemoteIpAddress_SetsNullIpAddress()
    {
        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync((UserInfo?)null);

        var (context, currentUser) = CreateContext();
        // DefaultHttpContext has null RemoteIpAddress by default

        var middleware = new UserContextResolutionMiddleware(_ => Task.CompletedTask);
        await middleware.InvokeAsync(context, resolver.Object);

        Assert.Null(currentUser.IpAddress);
    }

    [Fact]
    public async Task InvokeAsync_SetsIpAddress_EvenWhenUserNotAuthenticated()
    {
        var resolver = new Mock<IUserContextResolver>();
        resolver.Setup(r => r.ResolveAsync(It.IsAny<HttpContext>()))
            .ReturnsAsync((UserInfo?)null);

        var (context, currentUser) = CreateContext();
        context.Connection.RemoteIpAddress = System.Net.IPAddress.Parse("172.16.0.5");

        var middleware = new UserContextResolutionMiddleware(_ => Task.CompletedTask);
        await middleware.InvokeAsync(context, resolver.Object);

        Assert.Equal("172.16.0.5", currentUser.IpAddress);
        Assert.False(currentUser.IsAuthenticated);
    }
}

