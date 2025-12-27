using Domain.Entities;
using Domain.Enums;
using Domain.Repositories;
using Domain.Services;
using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Service
{
	public class UserService : IUserService
	{
		private readonly IUserRepository _userRepository;
		private readonly IHttpContextAccessor _contextAccessor;
		private readonly ISecurityService _securityService;

		public UserService(IUserRepository userRepository, IHttpContextAccessor contextAccessor, ISecurityService securityService)
		{
			_userRepository = userRepository;
			_contextAccessor = contextAccessor;
			_securityService = securityService;
		}

		public async Task<bool> AddUserAsync(User user)
		{
			return await _userRepository.InsertOneAsync(user);
		}

		public async Task<User> FindUserByLoginAsync(string email, Provider provider, string providerKey)
		{
			string providerKeyHash = _securityService.GetSha256Hash(providerKey);
			return await _userRepository.FindUserAsync(s => s.Email == email && s.Provider == provider && s.ProviderKey == providerKeyHash);
		}

		public async ValueTask<User> FindUserByIdAsync(string userId)
		{
			return await _userRepository.FindByIdAsync(userId);
		}

		public async Task<bool> DeleteUserTokensByUserIdAsync(string userId)
		{
			return await _userRepository.DeleteUserTokensByUserIdAsync(userId);
		}

		public async Task<bool> AddUserTokenByUserIdAsync(string userId, Token token)
		{
			return await _userRepository.AddUserTokenByUserIdAsync(userId, token);
		}

		public async Task<bool> DeleteExpiredTokensAsync(string userId)
		{
			return await _userRepository.DeleteExpiredTokensAsync(userId);
		}

		public async Task<bool> DeleteTokensWithSameRefreshTokenSourceAsync(string refreshTokenIdHashSource, string userId)
		{
			return await _userRepository.DeleteTokensWithSameRefreshTokenSourceAsync(refreshTokenIdHashSource, userId);
		}

		public async Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken)
		{
			return await _userRepository.FindUserAndTokenByRefreshTokenAsync(refreshToken);
		}

		public async Task<User> FindUserByEmailAsync(string email)
		{
			return await _userRepository.FindUserAsync(x => x.Email == email);
		}

		public async Task<User> GetCurrentUserDataAsync()
		{
			ClaimsIdentity claimsIdentity = _contextAccessor.HttpContext.User.Identity as ClaimsIdentity;

			string userId = claimsIdentity?.FindFirst(ClaimTypes.UserData).Value;
			return await FindUserByIdAsync(userId);
		}

		public async Task<bool> ChangePasswordAsync(string userId, string newPassword)
		{
			string newPasswordHash = _securityService.GetSha256Hash(newPassword);
			string newSerialNumber = _securityService.CreateCryptographicallySecureGuid().ToString();

			return await _userRepository.ChangePassword(userId, newPasswordHash, newSerialNumber);
		}

		public Task<bool> SetEmailVerifiedAsync(string userId)
		{
			return _userRepository.SetEmailVerifiedAsync(userId);
		}
	}
}
