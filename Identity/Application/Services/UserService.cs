using Identity.Application.Dtos;
using Identity.Application.Interfaces;
using Identity.Domain.Exceptions;
using Identity.Domain.Models;
using Identity.Infrastructure.Database.DataRepositories;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Identity.Application.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<AppUser> _userManager;

        private readonly IPasswordHasher<AppUser> _passwordHasher;

        private readonly ITokenRepository _tokenRepository;

        private readonly IRefreshTokenRepository _refreshTokenRepository;

        private readonly IUnitOfWork _unitOfWork;

        public UserService(
            UserManager<AppUser> userManager, 
            IPasswordHasher<AppUser> passwordHasher, 
            ITokenRepository tokenRepository,
            IRefreshTokenRepository refreshTokenRepository,
            IUnitOfWork unitOfWork)
        {
            _userManager = userManager;
            _passwordHasher = passwordHasher;
            _tokenRepository = tokenRepository;
            _refreshTokenRepository = refreshTokenRepository;
            _unitOfWork = unitOfWork;
        }

        public async Task<TokenDto> RegisterAsync(UserDto user, string password)
        {
            var appUser = new AppUser
            {
                UserName = user.Name,
                Email = user.Email
            };

            ValidateUser(user, password);

            var rs = await _userManager.CreateAsync(appUser, password);

            if (rs.Succeeded)
            {
                var newUser = await _userManager.FindByEmailAsync(user.Email);

                return await _tokenRepository.CreateTokenAsync(GetUserDto(newUser));
            }

            throw new ApplicationException("Something went wrong.");
        }

        public async Task<TokenDto> LoginAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            var loginUser = await _userManager.FindByEmailAsync(email);

            if (loginUser != null)
            {
                var isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

                if (isPasswordMatched)
                {
                    return await _tokenRepository.CreateTokenAsync(GetUserDto(loginUser));
                }
            }

            throw new ArgumentException($"Invalid credential.");
        }

        public async Task<TokenDto> RefreshTokenAsync(TokenDto token)
        {
            var principal = _tokenRepository.GetPrincipalFromExpiredToken(token.Token);

            if (principal != null)
            {
                var tokenExpiryUnix = long.Parse(principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Exp).Value);
                var tokenExpiryDate = new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(tokenExpiryUnix);

                if (tokenExpiryDate <= DateTime.Now)
                {
                    var jti = principal.Claims.Single(p => p.Type == JwtRegisteredClaimNames.Jti).Value;
                    var storedRefreshToken = await _refreshTokenRepository.FindByTokenAsync(token.RefreshToken);

                    if (
                        storedRefreshToken != null &&
                        storedRefreshToken.JwtId == jti &&
                        storedRefreshToken.ExpiryDate >= DateTime.Now &&
                        storedRefreshToken.Invalidated == false &&
                        storedRefreshToken.Used == false)
                    {
                        storedRefreshToken.Used = true;
                        _refreshTokenRepository.Update(storedRefreshToken);
                        await _unitOfWork.CompleteAsync();

                        var email = principal.Claims.Single(p => p.Type == ClaimTypes.Email).Value;
                        var user = await _userManager.FindByEmailAsync(email);

                        var resource = await _tokenRepository.CreateTokenAsync(GetUserDto(user));
                        return resource;
                    }

                        
                    throw new ArgumentException("Invalid refresh token.");
                }
                    
                throw new ArgumentException("The access token has not expired yet.");
            }

            throw new ArgumentException("Invalid token.");
        }

        private void ValidateUser(UserDto user, string password)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            ValidateEmail(user.Email);
            ValidateUserName(user.Name);
            ValidatePassword(password);
        }

        private void ValidateUserName(string name)
        {
            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("Name is required.");
            }

            if (name.Length < 3)
            {
                throw new ArgumentException("Name must have at least 3 characters.");
            }
        }

        private void ValidateEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                throw new ArgumentException("Email is required.");
            }

            var emailPattern = @"^([\w\.\-]+)@([\w\-]+)((\.(\w){2,3})+)$";

            if (!Regex.IsMatch(email, emailPattern))
            {
                throw new ArgumentException("Invalid email.");
            }
        }

        private void ValidatePassword(string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password is required.");
            }

            var passwordPattern = "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$";

            if (!Regex.IsMatch(password, passwordPattern))
            {
                throw new ArgumentException("Password must have at least 8 characters, " +
                    "at least 1 uppercase letter, at least 1 lowercase letter, " +
                    "at least 1 digit and at least 1 special character.");
            }
        }

        public async Task<bool> DeleteAsync(string id)
        {
            var currentUser = await _userManager.FindByIdAsync(id);

            if (currentUser != null)
            {
                var rs = await _userManager.DeleteAsync(currentUser);

                if (rs.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new NotFoundException("User not found.");
        }

        public IList<UserDto> GetAll()
        {
            return GetUserDtos(_userManager.Users.ToList());
        }

        public async Task<UserDto> GetByEmailAsync(string email)
        {
            var rs = await _userManager.FindByEmailAsync(email);

            if (rs != null)
            {
                return GetUserDto(rs);
            }

            throw new NotFoundException("User not found.");
        }

        public async Task<UserDto> GetByIdAsync(string id)
        {
            var rs = await _userManager.FindByIdAsync(id);

            if (rs != null)
            {
                return GetUserDto(rs);
            }

            throw new NotFoundException("User not found.");
        }

        private UserDto GetUserDto(AppUser from)
        {
            return new UserDto
            {
                Id = from.Id,
                Name = from.UserName,
                Email = from.Email
            };
        }

        private IList<UserDto> GetUserDtos(List<AppUser> from)
        {
            return from.Select(u => new UserDto
            {
                Id=u.Id,
                Name = u.UserName,
                Email = u.Email
            }).ToList();
        }

        public async Task<bool> UpdatePasswordAsync(string id, string newPass)
        {
            var currentUser = await _userManager.FindByIdAsync(id);

            if (currentUser != null)
            {
                ValidatePassword(newPass);

                currentUser.PasswordHash = _passwordHasher.HashPassword(currentUser, newPass);

                var rs = await _userManager.UpdateAsync(currentUser);

                if (rs.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new NotFoundException("User not found.");
        }
    }
}
