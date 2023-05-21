using Identity.Domain.Models;

namespace Identity.Application.Interfaces
{
    public interface IRefreshTokenRepository
    {
        Task AddAsync(RefreshToken token);

        Task<RefreshToken?> FindByTokenAsync(string token);

        Task InvalidateUserTokens(string userId);

        void Update(RefreshToken token);
    }
}
