namespace Clywell.Core.Security;

/// <summary>
/// Validates whether the authentication session identified by the token's <c>sid</c> claim
/// is still active. Implement and register via
/// <see cref="SecurityOptions.UseSessionValidation{TValidator}()"/> to enable
/// post-JWT-validation session checks.
/// </summary>
public interface ITokenSessionValidator
{
    /// <summary>
    /// Validates the session identified by <paramref name="sessionId"/>.
    /// Return <c>true</c> to allow the request; return <c>false</c> to reject it.
    /// </summary>
    /// <param name="sessionId">The <c>sid</c> claim value from the validated JWT.</param>
    /// <param name="context">The current HTTP context.</param>
    /// <param name="cancellationToken">Propagates cancellation from the request pipeline.</param>
    Task<bool> ValidateAsync(string sessionId, HttpContext context, CancellationToken cancellationToken = default);
}
