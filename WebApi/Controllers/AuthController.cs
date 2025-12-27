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

		public AuthController(
			IOptions<OAuthOptions> oAuthOptions,
			IOptions<Domain.Models.DataProtectionOptions> dataProtectionOptions,
			IOptions<JwtOptions> jwtOptions,
			IDataProtectionProvider dataProtectionProvider,
			IUserService userService,
			ISecurityService securityService,
			IJwtTokenService jwtTokenService,
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
		}

		[HttpPost("login")]
		public async Task<ActionResult<ApiResponseViewModel<AuthResponseViewModel>>> Login(LoginUserViewModel loginUser)
		{
			User user = await _userService.FindUserByLoginAsync(loginUser.Email, Provider.Password, loginUser.Password);

			if (user == null)
			{
				return NotFound(
					new ApiResponseViewModel
					{
						Success = false,
						Message = "User not found."
					});
			}
			if (user.IsActive == false)
			{
				return Unauthorized(
					new ApiResponseViewModel
					{
						Success = false,
						Message = "User account is inactive."
					});
			}
			if (user.IsEmailVerified == false)
			{
				return Unauthorized(
					new ApiResponseViewModel
					{
						Success = false,
						Message = "Email address is not verified."
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
			var emailVerificationCode = JsonSerializer.Deserialize<EmailVerificationCode>(_dataProtector.Unprotect(Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token))));
			if (emailVerificationCode == null || emailVerificationCode.ExpiredAt < DateTime.UtcNow)
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "Invalid or expired verification code." });
			}

			var user = await _userService.FindUserByEmailAsync(emailVerificationCode.Email);
			if (user == null)
			{
				return NotFound(new ApiResponseViewModel { Success = false, Message = "User not found." });
			}

			if (user.IsEmailVerified)
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "Email already verified." });
			}

			await _userService.SetEmailVerifiedAsync(user.Id);

			return Ok(new ApiResponseViewModel { Success = true, Message = "Email verified successfully." });
		}

		[HttpPost("reset-password")]
		public async Task<ActionResult<ApiResponseViewModel>> ResetPassword(ResetPasswordViewModel model)
		{
			var resetPasswordCode = JsonSerializer.Deserialize<ResetPasswordCode>(_dataProtector.Unprotect(Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(model.Token))));
			if (resetPasswordCode == null || resetPasswordCode.ExpiredAt < DateTime.UtcNow)
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "Invalid or expired reset password code." });
			}

			var user = await _userService.FindUserByEmailAsync(resetPasswordCode.Email);
			if (user == null)
			{
				return NotFound(new ApiResponseViewModel { Success = false, Message = "User not found." });
			}

			await _userService.ChangePasswordAsync(user.Id, model.NewPassword);

			return Ok(new ApiResponseViewModel { Success = true, Message = "Password reset successfully." });
		}

		[HttpPost("resend-verification-email")]
		public async Task<ActionResult<ApiResponseViewModel>> ResendVerificationEmail(EmailViewModel model)
		{
			var user = await _userService.FindUserByEmailAsync(model.Email);
			if (user == null)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "Verification email sent successfully." });
			}

			if (user.IsEmailVerified)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "Verification email sent successfully." });
			}
			var emailVerificationCode = new EmailVerificationCode
			{
				Email = user.Email,
				ExpiredAt = DateTime.UtcNow.AddHours(24)
			};

			var encodedVerificationCode = _dataProtector.Protect(JsonSerializer.Serialize(emailVerificationCode));
			var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(encodedVerificationCode));

			_ = Task.Run(() => _emailService.SendVerificationEmailAsync(user.Email, token));

			return Ok(new ApiResponseViewModel { Success = true, Message = "Verification email sent successfully." });
		}

		[HttpPost("forgot-password")]
		public async Task<ActionResult<ApiResponseViewModel>> ForgotPassword(EmailViewModel model)
		{
			var user = await _userService.FindUserByEmailAsync(model.Email);
			if (user == null)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "Reset password email sent successfully." });
			}

			var resetPasswordCode = new ResetPasswordCode
			{
				Email = user.Email,
				ExpiredAt = DateTime.UtcNow.AddHours(24)
			};

			var encodedResetPasswordCode = _dataProtector.Protect(JsonSerializer.Serialize(resetPasswordCode));
			var token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(encodedResetPasswordCode));

			_ = Task.Run(() => _emailService.SendResetPasswordEmailAsync(user.Email, token));

			return Ok(new ApiResponseViewModel { Success = true, Message = "Reset password email sent successfully." });
		}

		[HttpPost("register")]
		public async Task<ActionResult<ApiResponseViewModel<AuthResponseViewModel>>> Register(RegisterUserViewModel registerUser)
		{
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
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "A user with this email already exists." });
			}
		}

		[Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
		[HttpPost("change-password")]
		public async Task<ActionResult<ApiResponseViewModel>> ChangePassword(ChangePasswordViewModel model)
		{
			if (!ModelState.IsValid)
			{
				return BadRequest(ModelState);
			}

			User user = await _userService.GetCurrentUserDataAsync();

			if (user.ProviderKey != _securityService.GetSha256Hash(model.OldPassword))
			{
				return BadRequest(new ApiResponseViewModel
				{
					Success = false,
					Message = "Incorrect old password."
				});
			}

			if (await _userService.ChangePasswordAsync(user.Id, model.NewPassword))
			{
				return Ok(new ApiResponseViewModel
				{
					Success = true,
					Message = "Password changed successfully."
				});
			}

			return BadRequest(
				new ApiResponseViewModel
				{
					Success = false,
					Message = "Failed to change password."
				});
		}


		[HttpGet("google-login")]
		public IActionResult GoogleLogin()
		{
			var properties = new AuthenticationProperties
			{
				RedirectUri = _oAuthOptions.GoogleCallbackURL
			};
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
					Message =
				 "Google authentication failed."
				});
			}

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
					IsActive = true,
					Roles = [new Role { Name = "User" }],
					SerialNumber = _securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "")
				};
				await _userService.AddUserAsync(user);
			}

			if (user.IsActive == false)
			{
				return Unauthorized(new ApiResponseViewModel { Success = false, Message = "User account is inactive." });
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
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "No authentication cookie found." });
			}
			string refreshToken = authResponse.RefreshToken;
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "Refresh token is not set." });
			}

			try
			{
				(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);
				if (token == null)
				{
					return BadRequest(new ApiResponseViewModel { Success = false, Message = "Invalid refresh token." });
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
				return BadRequest(new ApiResponseViewModel { Success = false, Message = "Invalid refresh token." });
			}
		}

		[HttpGet("logout")]
		public async Task<ActionResult<ApiResponseViewModel>> Logout()
		{
			AuthCookie? authResponse = ReadCookie(Request);
			if (authResponse == null)
			{
				return Ok(new ApiResponseViewModel { Success = true, Message = "You have logged out successfully." });
			}
			string refreshToken = authResponse.RefreshToken;
			(Token token, User user) = await _jwtTokenService.FindUserAndTokenByRefreshTokenAsync(refreshToken);

			if (token != null)
			{
				await _jwtTokenService.RevokeUserBearerTokensAsync(user.Id, refreshToken);
			}

			Response.Cookies.Delete(_jwtOptions.CookieName);
			return Ok(new ApiResponseViewModel { Success = true, Message = "You have logged out successfully." });
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
