using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class LoginUserViewModel
	{
		[Required]
		public required string Email { get; set; }

		[Required]
		[MinLength((8), ErrorMessage = "must_be_at_least_8_characters_long")]
		public required string Password { get; set; }
		[Required]
		public required string TurnstileToken { get; set; }
	}
}
