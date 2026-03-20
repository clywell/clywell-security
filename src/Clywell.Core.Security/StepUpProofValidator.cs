using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Clywell.Core.Security;

/// <summary>
/// Default implementation of <see cref="IStepUpProofValidator"/>.
/// Reads <see cref="SecurityHeaderNames.StepUpProof"/> from the current request, validates the JWT using the
/// same <see cref="TokenValidationParameters"/> configured for the JwtBearer scheme,
/// then checks <c>acr == "step-up"</c> and optionally the <c>operation_context</c> claim.
/// </summary>
public sealed class StepUpProofValidator(
    IHttpContextAccessor httpContextAccessor,
    IOptionsMonitor<JwtBearerOptions> jwtOptions) : IStepUpProofValidator
{
    private static readonly JwtSecurityTokenHandler TokenHandler = new() { MapInboundClaims = false };

    public StepUpProofValidationResult Validate(string? requiredOperationContext = null)
    {
        var httpContext = httpContextAccessor.HttpContext;
        if (httpContext is null)
            return StepUpProofValidationResult.Missing;

        var proofToken = httpContext.Request.Headers[SecurityHeaderNames.StepUpProof].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(proofToken))
            return StepUpProofValidationResult.Missing;

        // Reuse the same signing key / issuer validation already configured for bearer auth.
        var bearerOptions = jwtOptions.Get(JwtBearerDefaults.AuthenticationScheme);
        var tvp = bearerOptions.TokenValidationParameters.Clone();
        // Proof tokens are not issued with an audience - skip audience validation.
        tvp.ValidateAudience = false;

        try
        {
            var principal = TokenHandler.ValidateToken(proofToken, tvp, out var validatedToken);

            // Proof tokens carry a token_type discriminator so they cannot be replayed as bearers.
            var tokenType = (validatedToken as JwtSecurityToken)?.Claims
                .FirstOrDefault(c => c.Type == "token_type")?.Value;
            if (tokenType != "step_up_proof")
                return StepUpProofValidationResult.Invalid;

            var acr = principal.FindFirst(SecurityClaimTypes.Acr)?.Value;
            if (acr != "step-up")
                return StepUpProofValidationResult.Invalid;

            if (requiredOperationContext is not null)
            {
                var opCtx = principal.FindFirst(SecurityClaimTypes.OperationContext)?.Value;
                if (!string.Equals(opCtx, requiredOperationContext, StringComparison.Ordinal))
                    return StepUpProofValidationResult.ContextMismatch;
            }

            return StepUpProofValidationResult.Valid;
        }
        catch (SecurityTokenExpiredException)
        {
            return StepUpProofValidationResult.Expired;
        }
        catch (Exception)
        {
            return StepUpProofValidationResult.Invalid;
        }
    }
}
