using Google.Apis.Auth;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using TEST.SocialLogin.Back.Data;
using TEST.SocialLogin.Back.Entities;
using TEST.SocialLogin.Back.Interfaces;

namespace TEST.SocialLogin.Back.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        private UserManager<ApplicationUser> _userManager { get; }
        private SignInManager<ApplicationUser> _signInManager { get; }
        private readonly IHostEnvironment _env;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        private readonly ILogger<AccountController> _logger;
        private readonly ApplicationContext _context;
        private readonly IAccountService _accountService;

        /// <summary></summary><param name="userManager"></param><param name="signInManager"></param><param name="env"></param><param name="configuration"></param><param name="emailService"></param>params><param name="logger"></param><param name="context"></param><param name="accountService"></param>
        public AccountController(
            UserManager<ApplicationUser> userManager
            , SignInManager<ApplicationUser> signInManager
            , IHostEnvironment env
            , IConfiguration configuration
            , IEmailService emailService
            , ILogger<AccountController> logger
            , ApplicationContext context
            , IAccountService accountService
            )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailService = emailService;
            _logger = logger;
            _env = env;
            _context = context;
            _accountService = accountService;
        }

        /// <summary>
        /// Logs an error with a specific format.
        /// </summary>
        /// <param name="e">Exception to log.</param>
        /// <param name="methodName">Method name to log.</param>
        private void LogErrors(Exception e, string methodName)
        {
            _logger.Log(LogLevel.Error, $"{nameof(AccountController)}.{methodName}: {e.Message}");
            _logger.Log(LogLevel.Error, $"{nameof(AccountController)}.{methodName}: {e.InnerException}");
        }

        /// <summary>
        /// This method validates if the username given is unique in the application.
        /// </summary>
        /// <param name="userName">Username to check.</param>
        /// <param name="captcha">Captcha.</param>
        /// <returns></returns>
        /// <response code="200">Username is already taken</response>
        /// <response code="204">Username available</response>
        /// <response code="400">Captcha</response>
        /// <response code="500">Internal error</response>
        [HttpGet]
        [Route("username/{userName}")]
        public async Task<IActionResult> UserNameExists(string userName, [FromQuery] string captcha)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(captcha))
                    return BadRequest("Captcha");
                if (await _accountService.ValidateUserExistsByUserName(userName))
                    return Ok("Username is already taken. Please select a different one!");
                return NoContent();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(UserNameExists));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method validates if the email given is unique in the application.
        /// </summary>
        /// <param name="email">Email to check.</param>
        /// <param name="captcha">Captcha.</param>
        /// <returns></returns>
        /// <response code="200">Email is already taken</response>
        /// <response code="204">Email available</response>
        /// <response code="400">Captcha</response>
        /// <response code="500">Internal error</response>
        [HttpGet]
        [Route("email/{email}")]
        public async Task<IActionResult> EmailExists(string email, [FromQuery] string captcha)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(captcha))
                    return BadRequest("Captcha");
                if (await _accountService.ValidateUserExistsByEmail(email))
                    return Ok("Email is already taken. Please select a different one!");
                return NoContent();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(EmailExists));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method sends a verification email to the user.
        /// </summary>
        /// <param name="email">Registered user email to send verification code.</param>
        /// <param name="captcha">Captcha.</param>
        /// <returns></returns>
        /// <response code="200">Request success</response>
        /// <response code="204">No content found</response>
        /// <response code="400">Captcha</response>
        /// <response code="500">Internal error</response>
        [HttpGet]
        [Route("send-email-validation/{email}")]
        public async Task<IActionResult> SendEmailValidationToken(string email, [FromQuery] string captcha)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(captcha))
                    return BadRequest("Captcha");
                if (!_accountService.GetUserByEmail(email, out var user))
                    return NoContent();
                if (!await _accountService.SendEmailConfirmationToken(user))
                    return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User verification email send failed! Please try again." });
                return Ok();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(SendEmailValidationToken));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method generates a token to change user password.
        /// </summary>
        /// <param name="email">User email to send remember token.</param>
        /// <param name="captcha">Captcha.</param>
        /// <returns></returns>
        /// <response code="200">Request success</response>
        /// <response code="204">No content found</response>
        /// <response code="400">Captcha</response>
        /// <response code="500">Internal error</response>
        [HttpGet]
        [Route("send-remember-password/{email}")]
        public async Task<IActionResult> RememberPassword(string email, [FromQuery] string captcha)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(captcha))
                    return BadRequest("Captcha");
                if (!_accountService.GetUserByEmail(email, out var user))
                    return NoContent();
                var tokenHash = await _accountService.GenerateHashResetToken(user);
                var emailDTO = new ConfigEmailDTO()
                {
                    From = _configuration["EmailConfiguration:User"],
                    FromName = "SocialLoginTest",
                    To = user.Email,
                    ToName = "",
                    Subject = "Remember password",
                    IsHtml = false,
                    Body = tokenHash
                };
                if (!await _emailService.SendTextEmail(emailDTO))
                    return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User remember password email send failed! Please try again." });
                return Ok();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(RememberPassword));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method registers a new user.
        /// </summary>
        /// <param name="model">Data to register a new user.</param>
        /// <returns></returns>
        /// <response code="200">Request success</response>
        /// <response code="204">No content found</response>
        /// <response code="400">BadRequest:Captcha</response>
        /// <response code="400">BadRequest:"Exists" User already exists</response>
        /// <response code="400">BadRequest:"Error" User creation failed</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] DTORegister model)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(model.Captcha))
                    return BadRequest("Captcha");
                if (await _accountService.ValidateUserExistsByEmail(model.Email))
                    return BadRequest(new { Status = "Exists", Message = "User not available!" });
                if (!_accountService.CreateUser(model.Email, model.Password, out var user))
                    return BadRequest(new { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                if (await _accountService.SendEmailConfirmationToken(user))
                    return StatusCode(StatusCodes.Status500InternalServerError, new { Status = "Error", Message = "User verification email send failed! Please try again." });
                return Ok(new { Status = "Success", Message = "User created successfully!" });
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(Register));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method verifies a user email with the token given.
        /// </summary>
        /// <param name="model">Data to verify user info.</param>
        /// <returns></returns>
        /// <response code="200">Request success</response>
        /// <response code="204">No content found</response>
        /// <response code="400">Captcha</response>
        /// <response code="401">Unauthorized request</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("email-validation")]
        public async Task<IActionResult> ValidateEmail(DTOEmailToken model)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(model.Captcha))
                    return BadRequest("Captcha");
                if (!_accountService.GetUserByEmail(model.Email, out var user))
                    return NoContent();
                if (!await _accountService.ConfirmUserEmail(user, model.Token))
                    return Unauthorized();
                return Ok();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(ValidateEmail));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This methods validates the information to sign in a user.
        /// </summary>
        /// <param name="model">Base info needed to sign in.</param>
        /// <returns></returns>
        /// <response code="200">Returns bearer token</response>
        /// <response code="204">No content found</response>
        /// <response code="400">Captcha</response>
        /// <response code="400">EmailConfirmationRequired</response>
        /// <response code="401">Unauthorized request</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] DTOLogin model)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(model.Captcha))
                    return BadRequest("Captcha");
                if (!_accountService.GetUserByEmail(model.Email, out var user))
                    return NoContent();
                if (!await _accountService.ValidateUserEmailIsConfirmed(user))
                    return BadRequest("EmailConfirmationRequired");
                if (await _accountService.ValidateUserIsLockedOut(user))
                    return Unauthorized();
                if (_accountService.LoginUser(user, model.Password, out var refreshToken))
                    return Ok(new { Status = "Token", Message = new { token = _accountService.GenerateToken(user), refreshToken } });
                await _accountService.FailsUserAccess(user);
                return Unauthorized();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(Login));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method validates the information to sign in with Facebook.
        /// </summary>
        /// <param name="model">Data to sign in user with external provider.</param>
        /// <returns></returns>
        /// <response code="200">"Token" bearer token created successfully.</response>
        /// <response code="200">"Redirect" user needs to register.</response>
        /// <response code="400">Captcha</response>
        /// <response code="400">InvalidModel</response>
        /// <response code="401">Unauthorized request</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("facebook-login")]
        public async Task<IActionResult> FacebookLogin(DTOExternalProviderLogin model)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(model.Captcha))
                    return BadRequest("Captcha");
                if (!ModelState.IsValid)
                    return BadRequest();
                var returnObject = await _accountService.ValidateFacebookToken(model);
                if (returnObject == null)
                    return Unauthorized();
                var info = new UserLoginInfo(model.Provider, returnObject.Id, model.Provider);
                var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                if (user == null)
                {
                    user = await _userManager.FindByEmailAsync(returnObject.Email);
                    if (user == null)
                        return Ok(new { Status = "Redirect", Message = returnObject });
                    await _userManager.AddLoginAsync(user, info);
                }
                var newRefreshToken = _accountService.GenerateRefreshToken();
                user.RefreshToken = newRefreshToken;
                await _context.SaveChangesAsync();
                return Ok(new { Status = "Token", Message = new { token = _accountService.GenerateToken(user), refreshToken = newRefreshToken } });
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(FacebookLogin));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method validates the information to sign in with Google.
        /// </summary>
        /// <param name="model">Data to sign in user with external provider.</param>
        /// <returns></returns>
        /// <response code="200">"Token" bearer token created successfully.</response>
        /// <response code="200">"Redirect" user needs to register.</response>
        /// <response code="400">Captcha</response>
        /// <response code="400">InvalidModel</response>
        /// <response code="401">Unauthorized request</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("google-login")]
        public async Task<IActionResult> GoogleLogin(DTOExternalProviderLogin model)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(model.Captcha))
                    return BadRequest("Captcha");
                if (!ModelState.IsValid)
                    return BadRequest();
                var returnObject = await _accountService.ValidateGoogleToken(model);
                if (returnObject == null)
                    return Unauthorized();
                var info = new UserLoginInfo(model.Provider, returnObject.Id, model.Provider);
                var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
                if (user == null)
                {
                    user = await _userManager.FindByEmailAsync(returnObject.Email);
                    if (user == null)
                        return Ok(new { Status = "Redirect", Message = returnObject });
                    await _userManager.AddLoginAsync(user, info);
                }
                var newRefreshToken = _accountService.GenerateRefreshToken();
                user.RefreshToken = newRefreshToken;
                await _context.SaveChangesAsync();
                return Ok(new { Status = "Token", Message = new { token = _accountService.GenerateToken(user), refreshToken = newRefreshToken } });
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(GoogleLogin));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method resets a user password.
        /// </summary>
        /// <param name="model">Data to reset user info.</param>
        /// <returns></returns>
        /// <response code="200">Request success</response>
        /// <response code="204">No content found</response>
        /// <response code="400">Captcha</response>
        /// <response code="401">Token not valid</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("remember-password")]
        public async Task<IActionResult> ResetPassword(DTOResetPassword model)
        {
            try
            {
                if (!await _accountService.ValidateRecaptcha(model.Captcha))
                    return BadRequest("Captcha");
                if (!_accountService.GetUserByEmail(model.Email, out var user))
                    return NoContent();
                if (!await _accountService.ResetUserPassword(user, model.Token, model.Password))
                    return Unauthorized();
                return Ok();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(ResetPassword));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method refreshes a user token
        /// </summary>
        /// <param name="model">Data to refresh Token.</param>
        /// <returns></returns>
        /// <response code="200">Request success</response>
        /// <response code="400">InvalidModel</response>
        /// <response code="400">InvalidToken</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("refresh-token")]
        public async Task<IActionResult> Refresh(DTORefreshToken model)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(model.RefreshToken) || string.IsNullOrWhiteSpace(model.Token)) return BadRequest("InvalidModel");
                var user = await _userManager.FindByIdAsync(_accountService.GetPrincipalFromExpiredToken(model.Token).Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value);
                if (user == null || user.RefreshToken != model.RefreshToken) return BadRequest("InvalidToken");
                var newRefreshToken = _accountService.GenerateRefreshToken();
                user.RefreshToken = newRefreshToken;
                await _context.SaveChangesAsync();
                return Ok(new
                {
                    token = _accountService.GenerateToken(user),
                    refreshToken = newRefreshToken
                });
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(Refresh));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// This method revokes the current refresh token.
        /// </summary>
        /// <returns></returns>
        /// <response code="204">Request success</response>
        /// <response code="400">Invalid user</response>
        /// <response code="401">Token not authorized</response>
        /// <response code="500">Internal error</response>
        [HttpPost]
        [Route("revoke-token")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> Revoke()
        {
            try
            {
                var user = await _userManager.FindByIdAsync(User.Claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier)?.Value);
                if (user == null) return BadRequest();
                user.RefreshToken = null;
                await _context.SaveChangesAsync();
                return NoContent();
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(Revoke));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }
    }
}
