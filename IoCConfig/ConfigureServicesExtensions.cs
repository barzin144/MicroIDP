using Service;
using Domain.Models;
using Domain.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.OpenApi.Models;
using DataAccess;
using MongoDB.Driver;
using Domain.Repositories;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using System.IO;
using System.Threading.Tasks;
using System.Text.Json;
using System.Security.Claims;

namespace IoCConfig
{
	public static class ConfigureServicesExtensions
	{
		public static void AddCustomCors(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddCors(options =>
			options.AddPolicy("CorsPolicy",
			builder => builder
				.WithOrigins(configuration["Cors:Origins"])
				.AllowAnyMethod()
				.AllowAnyHeader()
				.AllowCredentials()
			));
		}

		public static void AddCustomAuthentication(this IServiceCollection services, IConfiguration configuration)
		{
			var rsa = RSA.Create();
			rsa.ImportRSAPrivateKey(Convert.FromBase64String(configuration["Jwt:PrivateKey"] ?? ""), out _);
			services.AddAuthentication(options =>
			{
				options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
				options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
			})
			.AddCookie()
			.AddGoogle(options =>
			{
				options.ClientId = configuration["OAuth:GoogleClientId"] ?? "";
				options.ClientSecret = configuration["OAuth:GoogleClientSecret"] ?? "";
				options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
				options.Events.OnCreatingTicket = ctx =>
				{
					if (ctx.User.TryGetProperty("picture", out var value))
					{
						ctx.Identity?.AddClaim(new Claim(ClaimTypes.Uri, value.ToString()));
					}
					return Task.CompletedTask;
				};
			})
			.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
			{
				options.TokenValidationParameters = new TokenValidationParameters
				{
					ValidateIssuer = true,
					ValidateAudience = true,
					ValidateLifetime = true,
					ValidateIssuerSigningKey = true,
					ValidIssuer = configuration["Jwt:Issuer"],
					ValidAudience = configuration["Jwt:Audience"],
					IssuerSigningKey = new RsaSecurityKey(rsa)
				};

				options.Events = new JwtBearerEvents
				{
					OnMessageReceived = context =>
					{
						if (context.Request.Cookies.TryGetValue(configuration["Jwt:CookieName"], out var encryptedToken))
						{
							var dataProtector = context.HttpContext.RequestServices
									.GetRequiredService<IDataProtectionProvider>()
									.CreateProtector(configuration["Jwt:DataProtectionPurpose"]);

							try
							{
								var authCookie = JsonSerializer.Deserialize<AuthCookie>(dataProtector.Unprotect(encryptedToken));
								context.Token = authCookie.AccessToken;
							}
							catch
							{
								context.Fail("Invalid or tampered token");
							}
						}

						return Task.CompletedTask;
					}
				};
			});
		}

		public static void AddCustomDataProtection(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddDataProtection()
			.PersistKeysToFileSystem(new DirectoryInfo(configuration["Jwt:DataProtectionKeysPath"]))
			.SetApplicationName(configuration["Jwt:DataProtectionApplicationName"]);
		}
		public static void AddCustomServices(this IServiceCollection services)
		{
			services.AddScoped<IJwtTokenService, JwtTokenService>();
			services.AddScoped<IUserService, UserService>();
			services.AddSingleton<ISecurityService, SecurityService>();
			services.AddScoped<IUserRepository, UserRepository>();
			services.AddHttpContextAccessor();
		}

		public static void AddCustomOptions(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddOptions<JwtOptions>().Bind(configuration.GetSection("Jwt"));
			services.AddOptions<OAuthOptions>().Bind(configuration.GetSection("OAuth"));
		}

		public static void AddCustomSwagger(this IServiceCollection services)
		{

			services.AddSwaggerGen(options =>
			{
				options.SwaggerDoc("v1", new OpenApiInfo
				{
					Title = "Micro IDP API Document",
					Version = "v1"
				});
			});
		}

		public static void AddCustomMongoDbService(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddSingleton<IMongoClient>(s => new MongoClient(configuration.GetConnectionString("MongoDb")));
			services.AddScoped<IMongoDbContext>(s => new MongoDbContext(s.GetRequiredService<IMongoClient>(), configuration["DbName"]));
		}
	}
}
