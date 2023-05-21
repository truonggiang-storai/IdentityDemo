using Identity.Application.Dtos;
using System.Security.Claims;

namespace Identity.Application.Interfaces
{
    public interface ITokenRepository
    {
        Task<TokenDto> CreateTokenAsync(UserDto user);

        ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token);
    }
}
