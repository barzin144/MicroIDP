using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels;

public class ResetPasswordViewModel
{
    [Required]
    public required string Token { get; set; }

    [Required]
    [MinLength(8, ErrorMessage = "must_be_at_least_8_characters_long")]
    public required string NewPassword { get; set; }

    [Required]
    [MinLength(8, ErrorMessage = "must_be_at_least_8_characters_long")]
    [Compare(nameof(NewPassword), ErrorMessage = "new_passwords_do_not_match")]
    public required string ConfirmNewPassword { get; set; }

    [Required]
    public required string TurnstileToken { get; set; }
}
