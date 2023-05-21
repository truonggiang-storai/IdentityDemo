using Microsoft.AspNetCore.Identity;

namespace Identity.Domain.Models
{
    public class AppUser : IdentityUser
    {
        public virtual ICollection<RefreshToken> RefreshTokens { get; set; } = new List<RefreshToken>();
    }
}
