using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels;

public class ResetPasswordViewModel
{
    [Required]
    public required string Token { get; set; }

    [Required]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters long")]
    public required string NewPassword { get; set; }
}
