using System;

namespace Domain.Models;

public class TurnstileOptions
{
    public string SecretKey { get; set; } = string.Empty;
    public string ChallengeBaseUrl { get; set; } = string.Empty;
}
