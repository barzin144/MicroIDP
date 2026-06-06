using Domain.Entities;
using Domain.Models;
using Domain.Services;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Service
{
	public class JwtTokenService : IJwtTokenService
	{
		private readonly IUserService _userService;
		private readonly ISecurityService _securityService;
		private readonly JwtOptions _jwtOptions;
		private readonly RSA _rsa;

		public JwtTokenService(IUserService userService, ISecurityService securityService, IOptions<JwtOptions> jwtOptions)
		{
			_userService = userService;
			_securityService = securityService;
			_jwtOptions = jwtOptions.Value;
			_rsa = RSA.Create();
			_rsa.ImportRSAPrivateKey(Convert.FromBase64String(_jwtOptions.PrivateKey), out _);
		}

		public async Task AddUserTokenAsync(User user, string refreshTokenSerial, string accessToken, string refreshTokenSourceSerial)
		{
			var now = DateTimeOffset.UtcNow;
			var token = new Token
			{
				RefreshTokenIdHash = _securityService.GetSha256Hash(refreshTokenSerial),
				RefreshTokenIdHashSource = string.IsNullOrWhiteSpace(refreshTokenSourceSerial) ? null : _securityService.GetSha256Hash(refreshTokenSourceSerial),
				AccessTokenHash = _securityService.GetSha256Hash(accessToken),
				RefreshTokenExpiresDateTime = now.AddMinutes(_jwtOptions.RefreshTokenExpirationMinutes),
				AccessTokenExpiresDateTime = now.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes)
			};

			await _userService.DeleteTokensWithSameRefreshTokenSourceAsync(token.RefreshTokenIdHashSource, user.Id);
			await AddUserTokenAsync(token, user.Id);
		}

		public JwtTokensData CreateJwtTokens(User user)
		{
			var (accessToken, claims) = CreateAccessToken(user);
			var (refreshTokenValue, refreshTokenSerial) = CreateRefreshToken();
			return new JwtTokensData
			{
				AccessToken = accessToken,
				Claims = claims,
				RefreshToken = refreshTokenValue,
				RefreshTokenSerial = refreshTokenSerial
			};
		}

		private (string AccessToken, IEnumerable<Claim> Claims) CreateAccessToken(User user)
		{
			string jwtIssuer = _jwtOptions.Issuer;

			List<Claim> claims = [
			new Claim(JwtRegisteredClaimNames.Jti, _securityService.CreateCryptographicallySecureGuid().ToString(), ClaimValueTypes.String, jwtIssuer),
			new Claim(JwtRegisteredClaimNames.Iss, jwtIssuer, ClaimValueTypes.String, jwtIssuer),
			new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64, jwtIssuer),
			new Claim(ClaimTypes.NameIdentifier, user.Id.ToString(), ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.Name, user.Name, ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.Email, user.Email, ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.SerialNumber, user.SerialNumber, ClaimValueTypes.String, jwtIssuer),
			new Claim(ClaimTypes.UserData, user.Id.ToString(), ClaimValueTypes.String, jwtIssuer),
			new Claim("ProviderKey", user.ProviderKey, ClaimValueTypes.String, jwtIssuer),
			new Claim("ProviderRefreshToken", user.ProviderRefreshToken, ClaimValueTypes.String, jwtIssuer)
			];

			foreach (Role role in user.Roles)
			{
				claims.Add(new Claim(ClaimTypes.Role, role.Name, ClaimValueTypes.String, jwtIssuer));
			}

			SigningCredentials credentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256);

			DateTime now = DateTime.UtcNow;

			JwtSecurityToken token = new JwtSecurityToken(
				issuer: jwtIssuer,
				audience: _jwtOptions.Audience,
				claims: claims,
				notBefore: now,
				expires: now.AddMinutes(_jwtOptions.AccessTokenExpirationMinutes),
				signingCredentials: credentials
			);

			return (new JwtSecurityTokenHandler().WriteToken(token), claims);
		}

		private (string RefreshTokenValue, string RefreshTokenSerial) CreateRefreshToken()
		{
			string jwtIssuer = _jwtOptions.Issuer;

			string refreshTokenSerial = _securityService.CreateCryptographicallySecureGuid().ToString().Replace("-", "");

			List<Claim> claims = new List<Claim>
						{
								new Claim(JwtRegisteredClaimNames.Jti, _securityService.CreateCryptographicallySecureGuid().ToString(), ClaimValueTypes.String, jwtIssuer),
								new Claim(JwtRegisteredClaimNames.Iss, jwtIssuer, ClaimValueTypes.String, jwtIssuer),
								new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64, jwtIssuer),
								new Claim(ClaimTypes.SerialNumber, refreshTokenSerial, ClaimValueTypes.String, jwtIssuer)
						};
			SigningCredentials credentials = new SigningCredentials(new RsaSecurityKey(_rsa), SecurityAlgorithms.RsaSha256);

			DateTime now = DateTime.UtcNow;
			JwtSecurityToken token = new JwtSecurityToken(
					issuer: jwtIssuer,
					audience: _jwtOptions.Audience,
					claims: claims,
					notBefore: now,
					expires: now.AddMinutes(_jwtOptions.RefreshTokenExpirationMinutes),
					signingCredentials: credentials);
			string refreshTokenValue = new JwtSecurityTokenHandler().WriteToken(token);

			return (refreshTokenValue, refreshTokenSerial);
		}

		private async Task AddUserTokenAsync(Token userToken, string userId)
		{
			if (!_jwtOptions.AllowMultipleLoginsFromTheSameUser)
			{
				await InvalidateUserTokensAsync(userId);
			}
			await DeleteExpiredTokensAsync(userId);
			await _userService.AddUserTokenByUserIdAsync(userId, userToken);
		}

		private async Task InvalidateUserTokensAsync(string userId)
		{
			await _userService.DeleteUserTokensByUserIdAsync(userId);
		}

		public string GetRefreshTokenSerial(string refreshTokenValue)
		{
			if (string.IsNullOrWhiteSpace(refreshTokenValue))
			{
				return null;
			}

			ClaimsPrincipal decodedRefreshTokenPrincipal = null;
			try
			{
				decodedRefreshTokenPrincipal = new JwtSecurityTokenHandler().ValidateToken(
						refreshTokenValue,
						new TokenValidationParameters
						{
							RequireExpirationTime = true,
							ValidateIssuer = false,
							ValidateAudience = false,
							IssuerSigningKey = new RsaSecurityKey(_rsa),
							ValidateIssuerSigningKey = true,
							ValidateLifetime = true,
							ClockSkew = TimeSpan.Zero
						},
						out _
				);
			}
			catch
			{
				throw;
			}

			return decodedRefreshTokenPrincipal?.Claims?.FirstOrDefault(c => c.Type == ClaimTypes.SerialNumber)?.Value;
		}

		public async Task<bool> DeleteExpiredTokensAsync(string userId)
		{
			return await _userService.DeleteExpiredTokensAsync(userId);
		}

		public async Task RevokeUserBearerTokensAsync(string userId, string refreshToken)
		{
			if (!string.IsNullOrWhiteSpace(userId))
			{
				if (_jwtOptions.AllowSignoutAllUserActiveClients)
				{
					await InvalidateUserTokensAsync(userId);
				}
			}

			if (!string.IsNullOrWhiteSpace(refreshToken))
			{
				var refreshTokenSerial = GetRefreshTokenSerial(refreshToken);
				if (!string.IsNullOrWhiteSpace(refreshTokenSerial))
				{
					var refreshTokenIdHashSource = _securityService.GetSha256Hash(refreshTokenSerial);
					await _userService.DeleteTokensWithSameRefreshTokenSourceAsync(refreshTokenIdHashSource, userId);
				}
			}

			await DeleteExpiredTokensAsync(userId);
		}

		public async Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken)
		{
			if (string.IsNullOrWhiteSpace(refreshToken))
			{
				throw new Exception("Invalid refresh token");
			}
			try
			{
				string refreshTokenSerial = GetRefreshTokenSerial(refreshToken);
				return await _userService.FindUserAndTokenByRefreshTokenAsync(refreshTokenSerial);
			}
			catch
			{
				throw new Exception("Invalid refresh token");
			}
		}
	}
}
