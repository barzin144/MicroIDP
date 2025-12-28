namespace Domain.Models;

public class EmailTemplateOptions
{
    public string ResetPasswordUrl { get; set; }
    public string EmailVerificationUrl { get; set; }
    public string ApplicationName { get; set; }
}
