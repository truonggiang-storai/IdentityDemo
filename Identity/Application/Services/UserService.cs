﻿using Google.Apis.Auth;
using Identity.Application.Dtos;
using Identity.Application.Interfaces;
using Identity.Domain.Enums;
using Identity.Domain.Exceptions;
using Identity.Domain.Models;
using Identity.Infrastructure.Database.DataRepositories;
using Identity.Infrastructure.Helpers;
using Identity.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Newtonsoft.Json.Linq;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.RegularExpressions;

namespace Identity.Application.Services
{
    public class UserService : IUserService
    {
        private readonly UserManager<AppUser> _userManager;

        private readonly RoleManager<IdentityRole> _roleManager;

        private readonly IPasswordHasher<AppUser> _passwordHasher;

        private readonly ITokenRepository _tokenRepository;

        private readonly IRefreshTokenRepository _refreshTokenRepository;

        private readonly IUnitOfWork _unitOfWork;

        private readonly GoogleSettings _googleSettings;

        public UserService(
            UserManager<AppUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IPasswordHasher<AppUser> passwordHasher, 
            ITokenRepository tokenRepository,
            IRefreshTokenRepository refreshTokenRepository,
            IUnitOfWork unitOfWork,
            IOptions<GoogleSettings> options)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _passwordHasher = passwordHasher;
            _tokenRepository = tokenRepository;
            _refreshTokenRepository = refreshTokenRepository;
            _unitOfWork = unitOfWork;
            _googleSettings = options.Value;
        }

        public async Task<TokenDto> RegisterAsync(UserDto user, string password, IList<string>? roles = null, IList<ClaimDto>? claims = null)
        {
            var foundUserByEmail = await _userManager.FindByEmailAsync(user.Email);
            var foundUserByUserName = await _userManager.FindByNameAsync(user.Name);

            if (foundUserByEmail == null && foundUserByUserName == null)
            {
                var appUser = new AppUser
                {
                    UserName = user.Name,
                    Email = user.Email
                };

                ValidateUser(user, password);
                ValidateRoles(roles);
                ValidateClaims(claims);

                var rs = await _userManager.CreateAsync(appUser, password);

                if (rs.Succeeded)
                {
                    var newUser = await _userManager.FindByEmailAsync(user.Email);
                    var addingRoles = roles != null && roles.Any() ? roles : new List<string>() { RolesEnum.Member.ToString() };
                    await AddRoles(newUser, addingRoles);
                    await AddClaims(newUser, claims);
                    var addedClaims = await _userManager.GetClaimsAsync(newUser);

                    return await _tokenRepository.CreateTokenAsync(GetUserDto(newUser), addingRoles, addedClaims);
                }

                throw new ApplicationException("Something went wrong.");
            }

            throw new ArgumentException("User with email exists, please try another email.");
        }

        private void ValidateRoles(IList<string> roles)
        {
            var allRoles = _roleManager.Roles.Select(r => r.Name).ToList();

            if (roles != null && roles.Any(r => !allRoles.Contains(r)))
            {
                throw new ArgumentException($"Roles must belong to this list: {string.Join(", ", allRoles)}.");
            }
        }

        private void ValidateClaims(IList<ClaimDto>? claims)
        {
            if (claims != null && claims.Any(c => string.IsNullOrEmpty(c.Type) || string.IsNullOrEmpty(c.Value)))
            {
                throw new ArgumentException($"Claim type and value must not be empty.");
            }
        }

        public async Task<bool> AddUserToRolesAsync(string email, IList<string> roles)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                ValidateRoles(roles);

                var result = await _userManager.AddToRolesAsync(user, roles);

                if (result.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exists.");
        }

        private async Task AddRoles(AppUser user, IList<string> roles)
        {
            var addRolesResult = await _userManager.AddToRolesAsync(user, roles);

            if (!addRolesResult.Succeeded)
            {
                throw new ApplicationException("Add roles failed.");
            }
        }

        private async Task AddClaims(AppUser user, IList<ClaimDto> claimsInput)
        {
            var claims = claimsInput.Select(c => new Claim(c.Type, c.Value));

            var addClaimsResult = await _userManager.AddClaimsAsync(user, claims);

            if (!addClaimsResult.Succeeded)
            {
                throw new ApplicationException("Add claims failed.");
            }
        }

        public async Task<bool> AddClaimAsync(string email, string claimType, string claimValue)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var claim = new Claim(claimType, claimValue);

                var result = await _userManager.AddClaimAsync(user, claim);

                if (result.Succeeded)
                {
                    return true;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exists.");
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
                    var roles = await _userManager.GetRolesAsync(loginUser);
                    var claims = await _userManager.GetClaimsAsync(loginUser);

                    return await _tokenRepository.CreateTokenAsync(GetUserDto(loginUser), roles, claims);
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
                        var roles = await _userManager.GetRolesAsync(user);

                        var resource = await _tokenRepository.CreateTokenAsync(GetUserDto(user), roles);
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

        public async Task<TokenDto> GoogleLogin(ExternalAuthDto externalAuth)
        {
            var payload = await VerifyGoogleTokenAsync(externalAuth);

            if (payload != null)
            {
                var user = await _userManager.FindByEmailAsync(payload.Email);
                var addingRoles = new List<string>() { RolesEnum.Member.ToString() };

                if (user == null)
                {
                    var creatingUser = new AppUser
                    {
                        UserName = payload.Email,
                        Email = payload.Email
                    };

                    var rs = await _userManager.CreateAsync(creatingUser, Guid.NewGuid().ToString());

                    if (rs.Succeeded)
                    {
                        var newUser = await _userManager.FindByEmailAsync(user.Email);
                        await AddRoles(newUser, addingRoles);

                        return await _tokenRepository.CreateTokenAsync(GetUserDto(newUser), addingRoles);
                    }

                    throw new ApplicationException("Something went wrong.");
                }

                return await _tokenRepository.CreateTokenAsync(GetUserDto(user), addingRoles);
            }

            throw new ArgumentException("Invalid external authentication.");
        }

        private async Task<GoogleJsonWebSignature.Payload> VerifyGoogleTokenAsync(ExternalAuthDto externalAuth)
        {
            var settings = new GoogleJsonWebSignature.ValidationSettings()
            {
                Audience = new List<string>() { _googleSettings.ClientId }
            };

            var payload = await GoogleJsonWebSignature.ValidateAsync(externalAuth.IdToken, settings);
            return payload;
        }

        public async Task<bool> LoginWith2FaAsync(string email, string password)
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
                    return true;
                }
            }

            throw new ArgumentException($"Invalid credential.");
        }

        public async Task<string> Get2FaTokenAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, TokenOptions.DefaultProvider);

                if (token != null)
                {
                    var emailHelper = new EmailHelper();
                    bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

                    return token;
                }

                throw new ApplicationException("Something went wrong.");
            }

            throw new ArgumentException("User doesn't exist.");
        }

        public async Task<TokenDto> Verify2FaTokenAsync(string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);

            bool verified = await _userManager.VerifyTwoFactorTokenAsync(user, TokenOptions.DefaultProvider, token);

            if (verified)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var claims = await _userManager.GetClaimsAsync(user);

                return await _tokenRepository.CreateTokenAsync(GetUserDto(user), roles, claims);
            }

            throw new ArgumentException("OTP does not match, please try again.");
        }

        public async Task<bool> RegisterWithEmailConfirmAsync(UserDto user, string password, IList<string>? roles = null, IList<ClaimDto>? claims = null)
        {
            var foundUserByEmail = await _userManager.FindByEmailAsync(user.Email);
            var foundUserByUserName = await _userManager.FindByNameAsync(user.Name);

            if (foundUserByEmail == null && foundUserByUserName == null)
            {
                var appUser = new AppUser
                {
                    UserName = user.Name,
                    Email = user.Email
                };

                ValidateUser(user, password);
                ValidateRoles(roles);
                ValidateClaims(claims);

                var rs = await _userManager.CreateAsync(appUser, password);

                if (rs.Succeeded)
                {
                    var newUser = await _userManager.FindByEmailAsync(user.Email);
                    var addingRoles = roles != null && roles.Any() ? roles : new List<string>() { RolesEnum.Member.ToString() };
                    await AddRoles(newUser, addingRoles);
                    await AddClaims(newUser, claims);

                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(newUser);

                    if (token != null)
                    {
                        var emailHelper = new EmailHelper();
                        bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

                        return true;
                    }
                }

                throw new ApplicationException("Something went wrong.");
            }

            throw new ArgumentException("User with email exists, please try another email.");
        }

        public async Task<bool> ResendVerificationEmail(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                if (token != null)
                {
                    var emailHelper = new EmailHelper();
                    bool emailResponse = emailHelper.SendEmailTwoFactorCode(user.Email, token);

                    return true;
                }

                return false;
            }

            throw new ArgumentException("User doesn't exist.");
        }

        public async Task<TokenDto> VerifyEmailTokenAsync(string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                var roles = await _userManager.GetRolesAsync(user);
                var claims = await _userManager.GetClaimsAsync(user);

                return await _tokenRepository.CreateTokenAsync(GetUserDto(user), roles, claims);
            }

            throw new ArgumentException("Email verification failed, please try again.");
        }

        public async Task<TokenDto> LoginRequireEmailConfirmAsync(string email, string password)
        {
            ValidateEmail(email);

            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty.");
            }

            var loginUser = await _userManager.FindByEmailAsync(email);

            if (loginUser != null)
            {
                var isEmailConfirmed = loginUser.EmailConfirmed;

                if (isEmailConfirmed)
                {
                    var isPasswordMatched = await _userManager.CheckPasswordAsync(loginUser, password);

                    if (isPasswordMatched)
                    {
                        var roles = await _userManager.GetRolesAsync(loginUser);
                        var claims = await _userManager.GetClaimsAsync(loginUser);

                        return await _tokenRepository.CreateTokenAsync(GetUserDto(loginUser), roles, claims);
                    }

                    throw new ArgumentException($"Invalid credential.");
                }

                throw new ArgumentException($"User have not been verified.");
            }

            throw new ArgumentException($"Invalid credential.");
        }
    }
}
