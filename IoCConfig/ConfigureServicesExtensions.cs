using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;
using DataAccess;
using Domain.Models;
using Domain.Repositories;
using Domain.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.Google;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using MongoDB.Driver;
using Service;

namespace IoCConfig
{
	public static class ConfigureServicesExtensions
	{
		public static void AddCustomCors(this IServiceCollection services, IConfiguration configuration)
		{
			services.AddCors(options =>
				options.AddPolicy(
					"CorsPolicy",
					builder =>
						builder
							.WithOrigins(configuration["Cors:Origins"])
							.AllowAnyMethod()
							.AllowAnyHeader()
							.AllowCredentials()
				)
			);
		}

		public static void AddCustomAuthentication(
			this IServiceCollection services,
			IConfiguration configuration
		)
		{
			var rsa = RSA.Create();
			var scopes = configuration.GetSection("OAuth:Scopes").Get<List<string>>() ?? new List<string>();
			rsa.ImportRSAPrivateKey(
				Convert.FromBase64String(configuration["Jwt:PrivateKey"] ?? ""),
				out _
			);
			services
				.AddAuthentication(options =>
				{
					options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
					options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
				})
				.AddCookie()
				.AddGoogle(options =>
				{
					options.ClientId = configuration["OAuth:GoogleClientId"] ?? "";
					options.ClientSecret = configuration["OAuth:GoogleClientSecret"] ?? "";
					options.SaveTokens = true;
					options.AccessType = "offline";
					foreach (string scope in scopes)
					{
						options.Scope.Add(scope);
					}
					options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
					options.Events.OnCreatingTicket = ctx =>
					{
						if (ctx.User.TryGetProperty("picture", out var value))
						{
							ctx.Identity?.AddClaim(new Claim(ClaimTypes.Uri, value.ToString()));
						}
						return Task.CompletedTask;
					};
					options.Events.OnRemoteFailure = ctx =>
					{
						ctx.Response.Redirect(configuration["OAuth:GoogleCallbackURL"]);
						ctx.HandleResponse();
						return Task.CompletedTask;
					};
				})
				.AddJwtBearer(
					JwtBearerDefaults.AuthenticationScheme,
					options =>
					{
						options.TokenValidationParameters = new TokenValidationParameters
						{
							ValidateIssuer = true,
							ValidateAudience = true,
							ValidateLifetime = true,
							ValidateIssuerSigningKey = true,
							ValidIssuer = configuration["Jwt:Issuer"],
							ValidAudience = configuration["Jwt:Audience"],
							IssuerSigningKey = new RsaSecurityKey(rsa),
						};

						options.Events = new JwtBearerEvents
						{
							OnMessageReceived = context =>
							{
								if (
									context.Request.Cookies.TryGetValue(
										configuration["Jwt:CookieName"],
										out var encryptedToken
									)
								)
								{
									var dataProtector = context
										.HttpContext.RequestServices.GetRequiredService<IDataProtectionProvider>()
										.CreateProtector(configuration["Jwt:DataProtectionPurpose"]);

									try
									{
										var authCookie = JsonSerializer.Deserialize<AuthCookie>(
											dataProtector.Unprotect(encryptedToken)
										);
										context.Token = authCookie.AccessToken;
									}
									catch
									{
										context.Fail("Invalid or tampered token");
									}
								}

								return Task.CompletedTask;
							},
						};
					}
				);
		}

		public static void AddCustomDataProtection(
			this IServiceCollection services,
			IConfiguration configuration
		)
		{
			services
				.AddDataProtection()
				.PersistKeysToFileSystem(new DirectoryInfo(configuration["Jwt:DataProtectionKeysPath"]))
				.SetApplicationName(configuration["Jwt:DataProtectionApplicationName"]);
		}

		public static void AddCustomServices(this IServiceCollection services)
		{
			services.AddScoped<IJwtTokenService, JwtTokenService>();
			services.AddScoped<IUserService, UserService>();
			services.AddSingleton<ISecurityService, SecurityService>();
			services.AddScoped<IUserRepository, UserRepository>();
			services.AddScoped<IEmailService, EmailService>();
			services.AddHttpContextAccessor();
		}

		public static void AddTurnstileService(
			this IServiceCollection services,
			IConfiguration configuration
		)
		{
			var turnstileOptions = new TurnstileOptions();
			configuration.GetSection("Turnstile").Bind(turnstileOptions);
			services.AddSingleton(turnstileOptions);
			services.AddHttpClient<ITurnstileService, TurnstileService>(client =>
			{
				client.BaseAddress = new Uri(turnstileOptions.ChallengeBaseUrl);
			});
		}

		public static void AddCustomOptions(
			this IServiceCollection services,
			IConfiguration configuration
		)
		{
			services.AddOptions<JwtOptions>().Bind(configuration.GetSection("Jwt"));
			services.AddOptions<OAuthOptions>().Bind(configuration.GetSection("OAuth"));
			services.AddOptions<SMTPOptions>().Bind(configuration.GetSection("SMTP"));
			services.AddOptions<EmailTemplateOptions>().Bind(configuration.GetSection("EmailTemplate"));
			services
				.AddOptions<Domain.Models.DataProtectionOptions>()
				.Bind(configuration.GetSection("DataProtection"));
		}

		public static void AddCustomSwagger(this IServiceCollection services)
		{
			services.AddSwaggerGen(options =>
			{
				options.SwaggerDoc(
					"v1",
					new OpenApiInfo { Title = "Micro IDP API Document", Version = "v1" }
				);
			});
		}

		public static void AddCustomMongoDbService(
			this IServiceCollection services,
			IConfiguration configuration
		)
		{
			services.AddSingleton<IMongoClient>(s => new MongoClient(
				configuration.GetConnectionString("MongoDb")
			));
			services.AddScoped<IMongoDbContext>(s => new MongoDbContext(
				s.GetRequiredService<IMongoClient>(),
				configuration["DbName"]
			));
		}
	}
}
