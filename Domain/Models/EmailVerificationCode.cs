using System;

namespace Domain.Models;

public class EmailVerificationCode
{
    public DateTime ExpiredAt { get; set; }
    public string Email { get; set; }
}
