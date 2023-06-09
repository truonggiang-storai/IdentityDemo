using Identity.Application.Dtos;
using Identity.Application.Interfaces;
using Identity.Domain.Enums;
using Identity.Domain.Models;
using Identity.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/users")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [Authorize(Roles = "Admin")]
        [HttpGet("role-base-authorize")]
        public IActionResult GetRoleBaseResult() 
        {
            return Ok("Get resource by role successful.");
        }

        [Authorize(Policy = "ExampleClaimPolicy")]
        [HttpGet("claim-base-authorize")]
        public IActionResult GetClaimBaseResult()
        {
            return Ok("Get resource by claim successful.");
        }

        [Authorize(Policy = "AllowSuperUserPolicy")]
        [HttpGet("policy-base-authorize")]
        public IActionResult GetPolicyBaseResult()
        {
            return Ok("Get resource by policy successful.");
        }

        [HttpGet("{id}")]
        public async Task<UserDto> GetUserByIdAsync([FromQuery] string id)
        {
            return await _userService.GetByIdAsync(id);
        }

        [HttpGet("{email}")]
        public async Task<UserDto> GetUserByEmailAsync([FromQuery] string email)
        {
            return await _userService.GetByIdAsync(email);
        }

        [HttpGet]
        public IActionResult GetUsers()
        {
            return Ok(_userService.GetAll());
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<IActionResult> RegisterAsync(UserRegisterRequest request) 
        {
            var userDto = new UserDto
            {
                Email = request.Email,
                Name = request.Name
            };

            return Ok(await _userService.RegisterAsync(userDto, request.Password, request.Roles.ToList(), request.Claims.ToList()));
        }

        [AllowAnonymous]
        [HttpPost("register-with-email-confirmation")]
        public async Task<IActionResult> RegisterWithEmailConfirmAsync(UserRegisterRequest request)
        {
            var userDto = new UserDto
            {
                Email = request.Email,
                Name = request.Name
            };

            return Ok(await _userService.RegisterWithEmailConfirmAsync(userDto, request.Password, request.Roles.ToList(), request.Claims.ToList()));
        }

        [AllowAnonymous]
        [HttpPost("resend-email-verification")]
        public async Task<IActionResult> ResendEmailVerificationAsync([FromBody] string email)
        {
            return Ok(await _userService.ResendVerificationEmail(email));
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("add-roles")]
        public async Task<IActionResult> AddRolesAsync([FromForm] string email, [FromForm] IList<string> roles)
        {
            return Ok(await _userService.AddUserToRolesAsync(email, roles));
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("add-claim")]
        public async Task<IActionResult> AddClaimAsync(
            [FromForm] string email, 
            [FromForm] string claimType,
            [FromForm] string claimValue)
        {
            return Ok(await _userService.AddClaimAsync(email, claimType, claimValue));
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> LoginAsync([FromBody] UserLoginRequest request)
        {
            return Ok(await _userService.LoginAsync(request.Email, request.Password));
        }

        [AllowAnonymous]
        [HttpPost("login-require-email-confirmation")]
        public async Task<IActionResult> LoginRequireEmailConfirmationAsync([FromBody] UserLoginRequest request)
        {
            return Ok(await _userService.LoginRequireEmailConfirmAsync(request.Email, request.Password));
        }

        [AllowAnonymous]
        [HttpPost("google-login")]
        public async Task<IActionResult> GooleLoginAsync([FromBody] ExternalAuthDto externalAuth)
        {
            return Ok(await _userService.GoogleLogin(externalAuth));
        }

        [AllowAnonymous]
        [HttpPost("login-2fa")]
        public async Task<IActionResult> Login2FaAsync([FromBody] UserLoginRequest request)
        {
            return Ok(await _userService.LoginWith2FaAsync(request.Email, request.Password));
        }

        [AllowAnonymous]
        [HttpPost("get-2fa-token")]
        public async Task<IActionResult> Get2FaTokenAsync([FromBody] string email)
        {
            return Ok(await _userService.Get2FaTokenAsync(email));
        }

        [AllowAnonymous]
        [HttpPost("verify-2fa-token")]
        public async Task<IActionResult> Verify2FaTokenAsync([FromForm] string email, [FromForm] string code)
        {
            return Ok(await _userService.Verify2FaTokenAsync(email, code));
        }

        [AllowAnonymous]
        [HttpPost("verify-email")]
        public async Task<IActionResult> VerifyEmailAsync([FromForm] string email, [FromForm] string token)
        {
            return Ok(await _userService.VerifyEmailTokenAsync(email, token));
        }

        [AllowAnonymous]
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshTokenAsync([FromBody] TokenDto token)
        {
            return Ok(await _userService.RefreshTokenAsync(token));
        }

        [HttpPut("{id}/update-password")]
        public async Task<bool> UpdatePasswordAsync([FromRoute] string id, [FromBody] string newPass)
        {
            return await _userService.UpdatePasswordAsync(id, newPass);
        }

        [HttpDelete("{id}")]
        public async Task<bool> DeleteAsync([FromRoute] string id)
        {
            return await _userService.DeleteAsync(id);
        }
    }
}