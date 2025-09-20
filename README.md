# Micro IDP Service

## Features

- Sign up/in with Email
- Sign up/in with Google

## Run in Docker

### Generate certificate to host application with Docker over HTTPS

#### Windows

```shell
dotnet dev-certs https -ep %USERPROFILE%\.aspnet\https\aspnetapp.pfx -p <CREDENTIAL_PLACEHOLDER>
dotnet dev-certs https --trust
```

In the preceding commands, replace `<CREDENTIAL_PLACEHOLDER>` with a password.

#### Linux

```shell
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout aspnetcore.key -out aspnetcore.crt -subj "/CN=localhost"
openssl pkcs12 -export -out aspnetcore.pfx -inkey aspnetcore.key -in aspnetcore.crt
```

Replace **_ASPNETCORE_Kestrel\_\_Certificates\_\_Default\_\_Password_** with the certificate password in `.env`.

Replace the volume mount source with the generated certificate path in `docker-compose.yml`:

```yml
volumes:
  - type: bind
    source: ./aspnetcore.pfx
    target: /https/aspnetcore.pfx
```

To share data protection keys for encrypting and decrypting cookies, create an empty folder and bind it into the Docker container:

```yml
volumes:
  - type: bind
    source: ./DataProtectionKeys
    target: /app/DataProtectionKeys
```

### Generate Private and Public Key

#### C# Interactive

```csharp
using System.Security.Cryptography;
using (var rsa = RSA.Create(2048))
{
    // Export the private key
    var privateKey = rsa.ExportRSAPrivateKey();
    var privateKeyBase64 = Convert.ToBase64String(privateKey);
    Console.WriteLine("Private Key:");
    Console.WriteLine(privateKeyBase64);

    // Export the public key
    var publicKey = rsa.ExportRSAPublicKey();
    var publicKeyBase64 = Convert.ToBase64String(publicKey);
    Console.WriteLine("\nPublic Key:");
    Console.WriteLine(publicKeyBase64);
}
```

#### Bash

```shell
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl pkey -in private_key.pem -outform DER | base64 -w 0

openssl rsa -pubout -in private_key.pem -out public_key.pem
openssl pkey -in public_key.pem -outform DER | base64 -w 0
```

Replace the `PRIVATE_KEY` placeholder in `.env` with the generated private key.

### Sign in with Google Configuration

1. Create an OAuth 2.0 client in [Google Cloud Console](https://console.cloud.google.com).
2. Replace **_OAuth\_\_GoogleClientId_** placeholder in `.env`.
3. Replace **_OAuth\_\_GoogleClientSecret_** placeholder in `.env`.
4. Replace **_OAuth\_\_GoogleCallBackURL_** placeholder in `.env` with your client app's Google callback page (this page should call `https://IDP_SERVER_URL/api/auth/google-callback` to get JWT).

### Run IDP

```shell
docker compose up --wait
```

## Client App

### Add Jwt Section to Your `appsettings.json`

```json
"Jwt": {
    "PublicKey": "PUBLIC_KEY",
    "Issuer": "https://localhost:8001",
    "Audience": "http://localhost:5010",
    "DataProtectionApplicationName": "microidp",
    "DataProtectionKeysPath": "./DataProtectionKeys",
    "CookieName": "SAME AS IDP .env Jwt__CookieName",
    "DataProtectionPurpose": "SAME AS IDP .env Jwt__DataProtectionPurpose"
}
```

Replace the `PUBLIC_KEY` placeholder with the generated public key.

### Install JwtBearer Package

```shell
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
```

### Add Authentication Middleware

```csharp

services.AddDataProtection()
	.PersistKeysToFileSystem(new DirectoryInfo(configuration["Jwt:DataProtectionKeysPath"] ?? ""))
	.SetApplicationName(configuration["Jwt:DataProtectionApplicationName"] ?? "");

var rsa = RSA.Create();
rsa.ImportRSAPublicKey(Convert.FromBase64String(configuration["Jwt:PublicKey"] ?? ""), out _);

services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
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
```
