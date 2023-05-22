using Microsoft.AspNetCore.Authorization;

namespace Identity.Policies
{
    public class AllowSuperUserPolicy : IAuthorizationRequirement
    {
        public string UserName { get; set; }

        public AllowSuperUserPolicy(string username)
        {
            UserName = username;
        }
    }
}
