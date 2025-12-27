using System;

namespace Domain.Models;

public class ResetPasswordCode
{
    public DateTime ExpiredAt { get; set; }
    public string Email { get; set; }
}
