using Identity.Application.Dtos;

namespace Identity.Requests
{
    public class UserRegisterRequest
    {
        public string Name { get; set; }

        public string Email { get; set; }

        public string Password { get; set; }

        public ICollection<string>? Roles { get; set; } = new List<string>();

        public ICollection<ClaimDto> Claims { get; set; } = new List<ClaimDto>();
    }
}
