using IoCConfig;
using Microsoft.AspNetCore.Mvc;
using Serilog;
using WebApi.ViewModels;

var builder = WebApplication.CreateBuilder(args);

var services = builder.Services;
var configuration = builder.Configuration;
Log.Logger = new LoggerConfiguration().ReadFrom.Configuration(configuration).CreateLogger();

services.AddCustomOptions(configuration);
services.AddCustomDataProtection(configuration);
services.AddCustomServices();
services.AddCustomAuthentication(configuration);
services.AddCustomCors(configuration);
services.AddControllers().ConfigureApiBehaviorOptions(options =>
{
	options.InvalidModelStateResponseFactory = context =>
	{
		var errors = context.ModelState.Values.SelectMany(x => x.Errors).Select(x => x.ErrorMessage);

		return new BadRequestObjectResult(new ApiResponseViewModel
		{
			Success = false,
			Message = string.Join("\n", errors)
		});
	};
});
services.AddCustomSwagger();
services.AddCustomMongoDbService(configuration);
services.AddSerilog();

var app = builder.Build();

if (configuration.GetValue<bool>("EnableSwagger"))
{
	app.UseSwagger();
	app.UseSwaggerUI();
}

app.UseCors("CorsPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.UseSerilogRequestLogging();
app.MapControllers();

app.Run();