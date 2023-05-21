using Identity.Application.Dtos;
using Identity.Application.Interfaces;
using Identity.Domain.Models;
using Identity.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.Infrastructure.JwtToken
{
    public class JwtTokenRepository : ITokenRepository
    {
        private readonly JwtSettings _jwtSettings;

        private readonly IRefreshTokenRepository _refreshTokenRepository;

        private readonly IUnitOfWork _unitOfWork;

        public JwtTokenRepository(
            IOptions<JwtSettings> options, 
            IRefreshTokenRepository refreshTokenRepository, 
            IUnitOfWork unitOfWork)
        {
            _jwtSettings = options.Value;
            _refreshTokenRepository = refreshTokenRepository;
            _unitOfWork = unitOfWork;
        }

        public async Task<TokenDto> CreateTokenAsync(UserDto user)
        {
            var expiration = DateTime.UtcNow.AddSeconds(double.Parse(_jwtSettings.TokenValidityInSeconds));

            var token = CreateJwtToken(
                CreateClaims(user),
                CreateSigningCredentials(),
                expiration
            );

            var tokenHandler = new JwtSecurityTokenHandler();

            var refreshToken = new RefreshToken
            {
                Token = GenerateRefreshToken(),
                JwtId = token.Id,
                UserId = user.Id,
                CreationDate = DateTime.Now,
                ExpiryDate = DateTime.Now.AddDays(double.Parse(_jwtSettings.RefreshTokenValidityInDays))
            };

            await _refreshTokenRepository.AddAsync(refreshToken);
            await _unitOfWork.CompleteAsync();

            return new TokenDto
            {
                Token = tokenHandler.WriteToken(token),
                RefreshToken = refreshToken.Token
            };
        }

        private JwtSecurityToken CreateJwtToken(Claim[] claims, SigningCredentials credentials, DateTime expiration) =>
            new JwtSecurityToken(
                _jwtSettings.Issuer,
                _jwtSettings.Audience,
                claims,
                expires: expiration,
                signingCredentials: credentials
            );

        private Claim[] CreateClaims(UserDto user) =>
            new[] 
            {
                new Claim(JwtRegisteredClaimNames.Sub, _jwtSettings.Subject),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTime.UtcNow.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.Email, user.Email)
            };

        private SigningCredentials CreateSigningCredentials() =>
            new SigningCredentials(
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(_jwtSettings.Key)
                ),
                SecurityAlgorithms.HmacSha256
            );

        private static string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        public ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            var tokenValidationParameters = new TokenValidationParameters()
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                RequireExpirationTime = true,
                ValidateIssuerSigningKey = true,
                ValidAudience = _jwtSettings.Audience,
                ValidIssuer = _jwtSettings.Issuer,
                IssuerSigningKey = new SymmetricSecurityKey(
                        Encoding.UTF8.GetBytes(_jwtSettings.Key))
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal =
                tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);

            if (securityToken is not JwtSecurityToken jwtSecurityToken ||
                !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,
                    StringComparison.InvariantCultureIgnoreCase))
                return null;

            return principal;
        }
    }
}
