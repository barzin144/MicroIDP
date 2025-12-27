using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels;

public class EmailViewModel
{
    [Required]
    [EmailAddress]
    public required string Email { get; set; }
}
