using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Domain.Models;
using Domain.Services;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;

namespace Service;

public class EmailService : IEmailService
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _username;
    private readonly string _password;
    private readonly IWebHostEnvironment _env;
    private readonly EmailTemplateOptions _templateOptions;
    private readonly string _applicationName;
    public EmailService(IOptions<SMTPOptions> smtpOptions, IWebHostEnvironment env, IOptions<EmailTemplateOptions> templateOptions)
    {
        _host = smtpOptions.Value.Host;
        _port = smtpOptions.Value.Port;
        _username = smtpOptions.Value.Username;
        _password = smtpOptions.Value.Password;
        _env = env;
        _templateOptions = templateOptions.Value;
        _applicationName = templateOptions.Value.ApplicationName;
    }
    public async Task SendEmailAsync(string to, string subject, string body, string plainTextBody = null)
    {
        using var client = new SmtpClient(_host, _port);
        {
            client.Credentials = new NetworkCredential(_username, _password);
            client.EnableSsl = true;
            var message = new MailMessage();
            message.From = new MailAddress("no-reply@z0ne.uk");
            message.Headers.Add("Message-Id", $"<verify-{Guid.NewGuid()}@z0ne.uk>");
            message.AlternateViews.Add(AlternateView.CreateAlternateViewFromString(body, null, "text/html"));
            message.To.Add(new MailAddress(to));
            message.Subject = subject;
            message.Body = plainTextBody ?? body;
            message.IsBodyHtml = true;
            await client.SendMailAsync(message);
        }
    }

    public async Task SendVerificationEmailAsync(string to, string verificationCode)
    {
        var emailTemplateHtml = Path.Combine(_env.ContentRootPath, "EmailTemplates", "VerificationEmailTemplate.html");
        var emailTemplatePlainText = Path.Combine(_env.ContentRootPath, "EmailTemplates", "VerificationEmailTemplate.txt");
        var bodyHtml = File.ReadAllText(emailTemplateHtml);
        var bodyPlainText = File.ReadAllText(emailTemplatePlainText);

        bodyHtml = bodyHtml
        .Replace("#verification_link#", $"{_templateOptions.EmailVerificationUrl}/?token={verificationCode}")
        .Replace("#application_name#", _applicationName);

        bodyPlainText = bodyPlainText
        .Replace("#verification_link#", $"{_templateOptions.EmailVerificationUrl}/?token={verificationCode}")
        .Replace("#application_name#", _applicationName);

        await SendEmailAsync(to, "Email Verification", bodyHtml, bodyPlainText);
    }

    public async Task SendResetPasswordEmailAsync(string to, string resetPasswordCode)
    {
        var emailTemplateHtml = Path.Combine(_env.ContentRootPath, "EmailTemplates", "ResetPasswordEmailTemplate.html");
        var emailTemplatePlainText = Path.Combine(_env.ContentRootPath, "EmailTemplates", "ResetPasswordEmailTemplate.txt");
        var bodyHtml = File.ReadAllText(emailTemplateHtml);
        var bodyPlainText = File.ReadAllText(emailTemplatePlainText);

        bodyHtml = bodyHtml
        .Replace("#reset_password_link#", $"{_templateOptions.ResetPasswordUrl}/?token={resetPasswordCode}")
        .Replace("#application_name#", _applicationName);

        bodyPlainText = bodyPlainText
        .Replace("#reset_password_link#", $"{_templateOptions.ResetPasswordUrl}/?token={resetPasswordCode}")
        .Replace("#application_name#", _applicationName);

        await SendEmailAsync(to, "Reset Password", bodyHtml, bodyPlainText);
    }
}
