using Domain.Entities;
using System;
using System.Linq.Expressions;
using System.Threading.Tasks;

namespace Domain.Repositories
{
	public interface IUserRepository : IBaseRepository<User>
	{
		Task<User> FindUserAsync(Expression<Func<User, bool>> filter);
		Task<bool> DeleteUserTokensByUserIdAsync(string userId);
		Task<bool> SetEmailVerifiedAsync(string userId);
		Task<bool> AddUserTokenByUserIdAsync(string userId, Token token);
		Task<(Token token, User user)> FindUserAndTokenByRefreshTokenAsync(string refreshToken);
		Task<bool> DeleteExpiredTokensAsync(string userId);
		Task<bool> DeleteTokensWithSameRefreshTokenSourceAsync(string refreshTokenIdHashSource, string userId);
		Task<bool> ChangePasswordAsync(string userId, string newPasswordHash, string newSerialNumber);
	}
}
