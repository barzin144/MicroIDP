using System;

namespace Domain.Models;

public class OAuthOptions
{
	public string GoogleCallbackURL { get; set; }
	public string GoogleConnectCallbackURL { get; set; }
}
