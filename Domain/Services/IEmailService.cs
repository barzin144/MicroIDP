using System.Threading.Tasks;

namespace Domain.Services;

public interface IEmailService
{
    Task SendEmailAsync(string to, string subject, string body, string plainTextBody = null);
    Task SendVerificationEmailAsync(string to, string verificationCode);
    Task SendResetPasswordEmailAsync(string to, string resetPasswordCode);
}
