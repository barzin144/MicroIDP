using System.ComponentModel.DataAnnotations;

namespace WebApi.ViewModels
{
	public class RegisterUserViewModel
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
		[MinLength((8), ErrorMessage = "must_be_at_least_8_characters_long")]
		public required string Password { get; set; }

		[Required]
		[MinLength((8), ErrorMessage = "must_be_at_least_8_characters_long")]
		[Compare(nameof(Password), ErrorMessage = "passwords_do_not_match")]
		public required string ConfirmPassword { get; set; }

		[Required]
		public required string Name { get; set; }
		[Required]
		public required string TurnstileToken { get; set; }
	}
}
