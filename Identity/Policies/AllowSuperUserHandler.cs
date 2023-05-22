using Microsoft.AspNetCore.Authorization;

namespace Identity.Policies
{
    public class AllowSuperUserHandler : AuthorizationHandler<AllowSuperUserPolicy>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, AllowSuperUserPolicy requirement)
        {
            if (requirement.UserName.Equals(context.User.Identity.Name, StringComparison.OrdinalIgnoreCase))
            {
                context.Succeed(requirement);
            }
            else
            {
                context.Fail();
            }

            return Task.CompletedTask;
        }
    }
}
