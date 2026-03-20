using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Clywell.Core.Security.Tests.Unit;

public class StepUpProofValidatorTests
{
    private static readonly RsaSecurityKey SigningKey;
    private static readonly SigningCredentials SigningCredentials;
    private static readonly TokenValidationParameters ValidationParameters;

    static StepUpProofValidatorTests()
    {
        var rsa = RSA.Create(2048);
        SigningKey = new RsaSecurityKey(rsa);
        SigningCredentials = new SigningCredentials(SigningKey, SecurityAlgorithms.RsaSha256);
        ValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = SigningKey,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,
        };
    }

    private static string CreateProofToken(
        string acr = "step-up",
        string tokenType = "step_up_proof",
        string? operationContext = null,
        DateTimeOffset? expiry = null)
    {
        var expiresAt = expiry ?? DateTimeOffset.UtcNow.AddMinutes(3);

        var claims = new List<Claim>
        {
            new("sub", "user-1"),
            new("acr", acr),
            new("token_type", tokenType),
        };
        if (operationContext is not null)
            claims.Add(new Claim("operation_context", operationContext));

        var descriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            NotBefore = expiresAt.AddMinutes(-5).UtcDateTime,
            Expires = expiresAt.UtcDateTime,
            SigningCredentials = SigningCredentials,
        };
        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        return handler.CreateEncodedJwt(descriptor);
    }

    private static StepUpProofValidator CreateValidator(string? proofToken)
    {
        var httpContext = new DefaultHttpContext();
        if (proofToken is not null)
            httpContext.Request.Headers["X-Step-Up-Proof"] = proofToken;

        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns(httpContext);

        var jwtOptions = new JwtBearerOptions { TokenValidationParameters = ValidationParameters };
        var monitor = new Mock<IOptionsMonitor<JwtBearerOptions>>();
        monitor.Setup(m => m.Get(JwtBearerDefaults.AuthenticationScheme)).Returns(jwtOptions);

        return new StepUpProofValidator(accessor.Object, monitor.Object);
    }

    [Fact]
    public void Validate_ValidProofToken_NoContext_ReturnsValid()
    {
        var token = CreateProofToken();
        var validator = CreateValidator(token);

        Assert.Equal(StepUpProofValidationResult.Valid, validator.Validate());
    }

    [Fact]
    public void Validate_ValidProofToken_MatchingContext_ReturnsValid()
    {
        var token = CreateProofToken(operationContext: "delete_account");
        var validator = CreateValidator(token);

        Assert.Equal(StepUpProofValidationResult.Valid, validator.Validate("delete_account"));
    }

    [Fact]
    public void Validate_MissingHeader_ReturnsMissing()
    {
        var validator = CreateValidator(null);

        Assert.Equal(StepUpProofValidationResult.Missing, validator.Validate());
    }

    [Fact]
    public void Validate_WhitespaceOnlyHeader_ReturnsMissing()
    {
        var validator = CreateValidator("   ");

        Assert.Equal(StepUpProofValidationResult.Missing, validator.Validate());
    }

    [Fact]
    public void Validate_ExpiredToken_ReturnsExpired()
    {
        var token = CreateProofToken(expiry: DateTimeOffset.UtcNow.AddMinutes(-1));
        var validator = CreateValidator(token);

        Assert.Equal(StepUpProofValidationResult.Expired, validator.Validate());
    }

    [Fact]
    public void Validate_WrongTokenType_ReturnsInvalid()
    {
        var token = CreateProofToken(tokenType: "access_token");
        var validator = CreateValidator(token);

        Assert.Equal(StepUpProofValidationResult.Invalid, validator.Validate());
    }

    [Fact]
    public void Validate_WrongAcr_ReturnsInvalid()
    {
        var token = CreateProofToken(acr: "pwd");
        var validator = CreateValidator(token);

        Assert.Equal(StepUpProofValidationResult.Invalid, validator.Validate());
    }

    [Fact]
    public void Validate_ContextMismatch_ReturnsContextMismatch()
    {
        var token = CreateProofToken(operationContext: "approve_payment");
        var validator = CreateValidator(token);

        Assert.Equal(StepUpProofValidationResult.ContextMismatch, validator.Validate("delete_account"));
    }

    [Fact]
    public void Validate_RequiredContextButClaimAbsentFromToken_ReturnsContextMismatch()
    {
        // Token with NO operation_context claim
        var token = CreateProofToken(operationContext: null);
        var validator = CreateValidator(token);

        Assert.Equal(StepUpProofValidationResult.ContextMismatch, validator.Validate("delete_account"));
    }

    [Fact]
    public void Validate_NullHttpContext_ReturnsMissing()
    {
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(a => a.HttpContext).Returns((HttpContext?)null);
        var monitor = new Mock<IOptionsMonitor<JwtBearerOptions>>();
        var validator = new StepUpProofValidator(accessor.Object, monitor.Object);

        Assert.Equal(StepUpProofValidationResult.Missing, validator.Validate());
    }

    [Fact]
    public void Validate_MalformedToken_ReturnsInvalid()
    {
        var validator = CreateValidator("not.a.jwt");

        Assert.Equal(StepUpProofValidationResult.Invalid, validator.Validate());
    }
}
