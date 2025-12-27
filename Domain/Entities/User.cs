using Domain.Enums;
using Domain.Models;
using System;
using System.Collections.Generic;

namespace Domain.Entities
{
	public class User : BaseEntity
	{
		public User()
		{
			Roles = new HashSet<Role>();
			Tokens = new List<Token>();
		}
		public required string Email { get; set; }
		public required Provider Provider { get; set; }
		public required string ProviderKey { get; set; }
		public required string Name { get; set; }
		public bool IsActive { get; set; }
		public bool IsEmailVerified { get; set; } = false;
		public required string SerialNumber { get; set; }

		public ICollection<Role> Roles { get; set; }
		public List<Token> Tokens { get; set; }
	}
}
