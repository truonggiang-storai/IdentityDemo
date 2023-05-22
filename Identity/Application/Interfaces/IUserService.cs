using Identity.Application.Dtos;
using Identity.Domain.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Application.Interfaces
{
    public interface IUserService
    {
        Task<UserDto> GetByIdAsync(string id);

        Task<UserDto> GetByEmailAsync(string email);

        IList<UserDto> GetAll();

        Task<TokenDto> RegisterAsync(UserDto user, string password, IList<string>? roles = null, IList<ClaimDto>? claims = null);

        Task<bool> AddUserToRolesAsync(string email, IList<string> roles);

        Task<bool> AddClaimAsync(string email, string claimType, string claimValue);

        Task<TokenDto> LoginAsync(string email, string password);

        Task<TokenDto> RefreshTokenAsync(TokenDto token);

        Task<bool> UpdatePasswordAsync(string id, string newPass);

        Task<bool> DeleteAsync(string id);

        Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth);

        Task<bool> LoginWith2FaAsync(string email, string password);

        Task<string> Get2FaTokenAsync(string email);

        Task<TokenDto> Verify2FaTokenAsync(string email, string code);

        Task<bool> RegisterWithEmailConfirmAsync(UserDto user, string password, IList<string>? roles = null, IList<ClaimDto>? claims = null);

        Task<bool> ResendVerificationEmail(string email);

        Task<TokenDto> VerifyEmailTokenAsync(string email, string token);

        Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password);
    }
}
