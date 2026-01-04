using System.Threading.Tasks;

namespace Domain.Services;

public interface ITurnstileService
{
    Task<bool> Verify(string token);
}
