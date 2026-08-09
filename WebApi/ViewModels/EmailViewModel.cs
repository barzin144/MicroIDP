using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels;

public class EmailViewModel
{
    private string _email = string.Empty;

    [Required]
    [EmailAddress]
    public required string Email
    {
        get => _email;
        set => _email = value?.Trim().ToLowerInvariant() ?? string.Empty;
    }
    [Required]
    public required string TurnstileToken { get; set; }
}
