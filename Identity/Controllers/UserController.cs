using Identity.Application.Dtos;
using Identity.Application.Interfaces;
using Identity.Requests;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/users")]
    public class UserController : ControllerBase
    {
        private IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
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

            return Ok(await _userService.RegisterAsync(userDto, request.Password));
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> LoginAsync([FromBody] UserLoginRequest request)
        {
            return Ok(await _userService.LoginAsync(request.Email, request.Password));
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