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

        Task<TokenDto> RegisterAsync(UserDto user, string password);

        Task<TokenDto> LoginAsync(string email, string password);

        Task<TokenDto> RefreshTokenAsync(TokenDto token);

        Task<bool> UpdatePasswordAsync(string id, string newPass);

        Task<bool> DeleteAsync(string id);
    }
}
