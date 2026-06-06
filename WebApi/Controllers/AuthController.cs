using System.Net;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Domain.Entities;
using Domain.Enums;
using Domain.Models;
using Domain.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Options;
using WebApi.ViewModels;

namespace WebApi.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthController : ControllerBase
	{
		private readonly OAuthOptions _oAuthOptions;
		private readonly JwtOptions _jwtOptions;
		private readonly IDataProtector _jwtDataProtector;
		private readonly IDataProtector _dataProtector;
		private readonly IUserService _userService;
		private readonly ISecurityService _securityService;
		private readonly IJwtTokenService _jwtTokenService;
		private readonly IEmailService _emailService;
		private readonly ITurnstileService _turnstileService;

		public AuthController(
			IOptions<OAuthOptions> oAuthOptions,
			IOptions<Domain.Models.DataProtectionOptions> dataProtectionOptions,
			IOptions<JwtOptions> jwtOptions,
			IDataProtectionProvider dataProtectionProvider,
			IUserService userService,
			ISecurityService securityService,
			IJwtTokenService jwtTokenService,
			ITurnstileService turnstileService,
			IEmailService emailService)
		{
			_oAuthOptions = oAuthOptions.Value;
			_jwtOptions = jwtOptions.Value;
			_jwtDataProtector = dataProtectionProvider.CreateProtector(_jwtOptions.DataProtectionPurpose);
			_dataProtector = dataProtectionProvider.CreateProtector(dataProtectionOptions.Value.GeneralPurposeKey);
			_userService = userService;
			_securityService = securityService;
			_jwtTokenService = jwtTokenService;
			_emailService = emailService;
			_turnstileService = turnstileService;
		}

		[HttpPost("login")]
		public async Task<ActionResult<ApiResponseViewModel<AuthResponseViewModel>>> Login(LoginUserViewModel loginUser)
		{
			var turnstileServiceResult = await _turnstileService.Verify(loginUser.TurnstileToken);
			if (turnstileServiceResult == false)
			{
				return BadRequest(
				new ApiResponseViewModel
				{
					Success = false,
					Message = "captcha_verify_failed"
				});
			}
			User user = await _userService.FindUserByLoginAsync(loginUser.Email, Provider.Password, loginUser.Password);

			if (user == null)
			{
				return NotFound(
					new ApiResponseViewModel
					{
						Success = false,
						Message = "user_not_found"
					});
			}
			if (user.IsActive == false)
			{
				return StatusCode((int)HttpStatusCode.Forbidden,
					new ApiResponseViewModel
					{
						Success = false,
						Message = "inactive_user"
					});
			}
			if (user.IsEmailVerified == false)
			{
				return StatusCode((int)HttpStatusCode.Forbidden,
					new ApiResponseViewModel
					{
						Success = false,
						Message = "email_not_verified"
					});
			}

			JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(user);

			await _jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

			AppendCookie(Response, new AuthCookie
			{
				AccessToken = jwtToken.AccessToken,
				RefreshToken = jwtToken.RefreshToken,
			});

			return Ok(
				new ApiResponseViewModel<AuthResponseViewModel>
				{
					Success = true,
					Data = new AuthResponseViewModel
					{
						Email = user.Email,
						Name = user.Name,
						Provider = user.Provider.ToString(),
						IsEmailVerified = user.IsEmailVerified
					}
				});
		}

		[HttpGet("verify-email")]
		public async Task<ActionResult<ApiResponseViewModel>> VerifyEmail(string token)
		{
			try
			{
				var emailVerificationCode = JsonSerializer.Deserialize<EmailVerificationCode>(_dataProtector.Unprotect(Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token))));
				if (emailVerificationCode == null || emailVerificationCode.ExpiredAt < DateTime.UtcNow)
				{
					return BadRequest(new ApiResponseViewModel { Success = false, Message = "invalid_or_expired_code" });
				}

				var user = await _userService.FindUserByEmailAsync(emailVerificationCode.Email);
				if (user == null)
				{
					return NotFound(new ApiResponseViewModel { Success = false, Message = "user_not_found" });
				}

				if (user.IsEmailVerified)
				{
					return BadRequest(new ApiResponseViewModel { Success = false, Message = "email_already_verified" });
				}

				await _userService.SetEmailVerifiedAsync(user.Id);

				return Ok(new ApiResponseViewModel { Success = true, Message = "email_verified_successfully" });
			}
			catch
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "invalid_or_expired_code" });
			}
		}

		[HttpPost("reset-password")]
		public async Task<ActionResult<ApiResponseViewModel>> ResetPassword(ResetPasswordViewModel model)
		{
			var turnstileServiceResult = await _turnstileService.Verify(model.TurnstileToken);
			if (turnstileServiceResult == false)
			{
				return BadRequest(
				new ApiResponseViewModel
				{
					Success = false,
					Message = "captcha_verify_failed"
				});
			}
			try
			{
				var resetPasswordCode = JsonSerializer.Deserialize<ResetPasswordCode>(_dataProtector.Unprotect(Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Token))));
				if (resetPasswordCode == null || resetPasswordCode.ExpiredAt < DateTime.UtcNow)
				{
					return BadRequest(new ApiResponseViewModel { Success = false, Message = "invalid_or_expired_code" });
				}

				var user = await _userService.FindUserByEmailAsync(resetPasswordCode.Email);
				if (user == null)
				{
					return NotFound(new ApiResponseViewModel { Success = false, Message = "user_not_found" });
				}

				await _userService.ChangePasswordAsync(user.Id, model.NewPassword);

				return Ok(new ApiResponseViewModel { Success = true, Message = "password_reset_successfully" });
			}
			catch
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "invalid_or_expired_code" });
			}
		}

		[HttpPost("resend-verification-email")]
		public async Task<ActionResult<ApiResponseViewModel>> ResendVerificationEmail(EmailViewModel model)
		{
			var turnstileServiceResult = await _turnstileService.Verify(model.TurnstileToken);
			if (turnstileServiceResult == false)
			{
				return BadRequest(
				new ApiResponseViewModel
				{
					Success = false,
					Message = "captcha_verify_failed"
				});
			}
			var user = await _userService.FindUserByEmailAsync(model.Email);
			if (user == null)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "verification_email_sent_successfully" });
			}

			if (user.IsEmailVerified)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "verification_email_sent_successfully" });
			}
			var emailVerificationCode = new EmailVerificationCode
			{
				Email = user.Email,
				ExpiredAt = DateTime.UtcNow.AddHours(24)
			};

			var encodedVerificationCode = _dataProtector.Protect(JsonSerializer.Serialize(emailVerificationCode));
			var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(encodedVerificationCode));

			_ = Task.Run(() => _emailService.SendVerificationEmailAsync(user.Email, token));

			return Ok(new ApiResponseViewModel { Success = true, Message = "verification_email_sent_successfully" });
		}

		[HttpPost("forgot-password")]
		public async Task<ActionResult<ApiResponseViewModel>> ForgotPassword(EmailViewModel model)
		{
			var turnstileServiceResult = await _turnstileService.Verify(model.TurnstileToken);
			if (turnstileServiceResult == false)
			{
				return BadRequest(
				new ApiResponseViewModel
				{
					Success = false,
					Message = "captcha_verify_failed"
				});
			}
			var user = await _userService.FindUserByEmailAsync(model.Email);
			if (user == null)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "reset_password_email_sent_successfully" });
			}

			if (user.Provider != Provider.Password)
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "password_reset_not_allowed_for_oauth_users" });
			}

			var resetPasswordCode = new ResetPasswordCode
			{
				Email = user.Email,
				ExpiredAt = DateTime.UtcNow.AddHours(24)
			};

			var encodedResetPasswordCode = _dataProtector.Protect(JsonSerializer.Serialize(resetPasswordCode));
			var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(encodedResetPasswordCode));

			_ = Task.Run(() => _emailService.SendResetPasswordEmailAsync(user.Email, token));

			return Ok(new ApiResponseViewModel { Success = true, Message = "reset_password_email_sent_successfully" });
		}

		[HttpPost("register")]
		public async Task<ActionResult<ApiResponseViewModel<AuthResponseViewModel>>> Register(RegisterUserViewModel registerUser)
		{
			var turnstileServiceResult = await _turnstileService.Verify(registerUser.TurnstileToken);
			if (turnstileServiceResult == false)
			{
				return BadRequest(
				new ApiResponseViewModel
				{
					Success = false,
					Message = "captcha_verify_failed"
				});
			}
			if (await _userService.FindUserByEmailAsync(registerUser.Email) == null)
			{
				User newUser = new User
				{
					Name = registerUser.Name,
					Email = registerUser.Email,
					ProviderKey = _securityService.GetSha256Hash(registerUser.Password),
					Provider = Provider.Password,
					IsActive = true,
					Roles = [new Role { Name = "User" }],
					SerialNumber = _securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "")
				};

				await _userService.AddUserAsync(newUser);

				var emailVerificationCode = new EmailVerificationCode
				{
					Email = newUser.Email,
					ExpiredAt = DateTime.UtcNow.AddHours(24)
				};

				var encodedVerificationCode = _dataProtector.Protect(JsonSerializer.Serialize(emailVerificationCode));
				var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(encodedVerificationCode));

				_ = Task.Run(() => _emailService.SendVerificationEmailAsync(newUser.Email, token));

				return Ok(
					new ApiResponseViewModel<AuthResponseViewModel>
					{
						Success = true,
						Data = new AuthResponseViewModel
						{
							Email = newUser.Email,
							Name = newUser.Name,
							Provider = newUser.Provider.ToString(),
							IsEmailVerified = newUser.IsEmailVerified
						}
					}
				);
			}
			else
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "email_already_exists" });
			}
		}

		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		[HttpPost("change-password")]
		public async Task<ActionResult<ApiResponseViewModel>> ChangePassword(ChangePasswordViewModel model)
		{
			User user = await _userService.GetCurrentUserDataAsync();

			if (user.ProviderKey != _securityService.GetSha256Hash(model.OldPassword))
			{
				return BadRequest(new ApiResponseViewModel
				{
					Success = false,
					Message = "incorrect_old_password"
				});
			}

			if (await _userService.ChangePasswordAsync(user.Id, model.NewPassword))
			{
				return Ok(new ApiResponseViewModel
				{
					Success = true,
					Message = "password_changed_successfully"
				});
			}

			return BadRequest(
				new ApiResponseViewModel
				{
					Success = false,
					Message = "failed_to_change_password"
				});
		}


		[HttpGet("google-login")]
		public IActionResult GoogleLogin()
		{
			var properties = new AuthenticationProperties
			{
				RedirectUri = _oAuthOptions.GoogleCallbackURL
			};
			properties.Parameters.Add("prompt", "consent");
			return Challenge(properties, GoogleDefaults.AuthenticationScheme);
		}

		[HttpGet("google-callback")]
		public async Task<ActionResult<ApiResponseViewModel<AuthResponseViewModel>>> GoogleCallbackAsync()
		{
			var authenticateResult = await HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);

			if (!authenticateResult.Succeeded)
			{
				return BadRequest(new ApiResponseViewModel
				{
					Success = false,
					Message = "google_authentication_failed."
				});
			}

			var refreshToken = authenticateResult.Properties.GetTokenValue("refresh_token");

			var claims = authenticateResult.Principal.Claims;

			var email = claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
			ArgumentNullException.ThrowIfNull(email, nameof(email));

			var name = claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
			ArgumentNullException.ThrowIfNull(name, nameof(name));

			var nameIdentifier = claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
			ArgumentNullException.ThrowIfNull(nameIdentifier, nameof(nameIdentifier));

			var profilePicture = claims.FirstOrDefault(c => c.Type == ClaimTypes.Uri)?.Value;

			var user = await _userService.FindUserByLoginAsync(email, Provider.Google, nameIdentifier);

			if (user == null)
			{
				user = new User
				{
					Name = name,
					Email = email,
					ProviderKey = _securityService.GetSha256Hash(nameIdentifier),
					Provider = Provider.Google,
					ProviderRefreshToken = refreshToken,
					IsActive = true,
					Roles = [new Role { Name = "User" }],
					IsEmailVerified = true,
					SerialNumber = _securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "")
				};
				await _userService.AddUserAsync(user);
			}

			if (user.IsActive == false)
			{
				return Unauthorized(new ApiResponseViewModel { Success = false, Message = "inactive_user" });
			}

			JwtTokensData jwtToken = _jwtTokenService.CreateJwtTokens(user);

			await _jwtTokenService.AddUserTokenAsync(user, jwtToken.RefreshTokenSerial, jwtToken.AccessToken, null);

			AppendCookie(Response, new AuthCookie
			{
				AccessToken = jwtToken.AccessToken,
				RefreshToken = jwtToken.RefreshToken,
			});

			return Ok(
				new ApiResponseViewModel<AuthResponseViewModel>
				{
					Success = true,
					Data = new AuthResponseViewModel
					{
						Email = user.Email,
						Name = user.Name,
						ProfilePicture = profilePicture,
						Provider = user.Provider.ToString(),
						IsEmailVerified = user.IsEmailVerified
					}
				});
		}

		[HttpGet("refresh-token")]
		public async Task<ActionResult<ApiResponseViewModel<AuthResponseViewModel>>> RefreshToken()
		{
			AuthCookie? authResponse = ReadCookie(Request);
			if (authResponse == null)
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "cookie_not_found." });
			}
			string refreshToken = authResponse.RefreshToken;
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "refresh_token_not_found" });
			}

			try
			{
				(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);
				if (token == null)
				{
					return BadRequest(new ApiResponseViewModel { Success = false, Message = "invalid_refresh_token." });
				}

				var result = _jwtTokenService.CreateJwtTokens(user);
				await _jwtTokenService.AddUserTokenAsync(user, result.RefreshTokenSerial, result.AccessToken, _jwtTokenService.GetRefreshTokenSerial(refreshToken));

				AppendCookie(Response, new AuthCookie
				{
					AccessToken = result.AccessToken,
					RefreshToken = result.RefreshToken,
				});

				return Ok(
				new ApiResponseViewModel<AuthResponseViewModel>
				{
					Success = true,
					Data = new AuthResponseViewModel
					{
						Email = user.Email,
						Name = user.Name,
						Provider = user.Provider.ToString(),
						IsEmailVerified = user.IsEmailVerified
					}
				});
			}
			catch
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "invalid_refresh_token." });
			}
		}

		[HttpGet("logout")]
		public async Task<ActionResult<ApiResponseViewModel>> Logout()
		{
			AuthCookie? authResponse = ReadCookie(Request);
			if (authResponse == null)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "logged_out_successfully." });
			}
			string refreshToken = authResponse.RefreshToken;
			(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);

			if (token != null)
			{
				await _jwtTokenService.RevokeUserBearerTokensAsync(user.Id, refreshToken);
			}

			Response.Cookies.Delete(_jwtOptions.CookieName);
			return Ok(new ApiResponseViewModel { Success = true, Message = "logged_out_successfully." });
		}

		private void AppendCookie(HttpResponse response, AuthCookie authCookie)
		{
			response.Cookies.Append(_jwtOptions.CookieName, _jwtDataProtector.Protect(JsonSerializer.Serialize(authCookie)), new CookieOptions
			{
				HttpOnly = true,
				Secure = true,
				SameSite = SameSiteMode.Strict,
				Expires = DateTimeOffset.Now.AddMinutes(_jwtOptions.RefreshTokenExpirationMinutes)
			});
		}

		private AuthCookie? ReadCookie(HttpRequest request)
		{
			if (request.Cookies.TryGetValue(_jwtOptions.CookieName, out string? cookieValue))
			{
				return JsonSerializer.Deserialize<AuthCookie>(_jwtDataProtector.Unprotect(cookieValue)) ?? null;
			}
			return null;
		}
	}
}
