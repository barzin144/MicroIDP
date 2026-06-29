# MicroIDP

A lightweight Identity Provider (IDP) service built with ASP.NET Core and MongoDB. It handles user authentication and issues RSA-signed JWTs stored in encrypted HTTP-only cookies, making it easy to integrate with any client application.

## Features

- Register and sign in with email and password
- Sign in with Google OAuth 2.0
- Email verification on registration
- Forgot password / reset password via email
- JWT access tokens signed with RSA key pair
- Encrypted HTTP-only cookie storage (ASP.NET Core Data Protection)
- Automatic token refresh
- Cloudflare Turnstile CAPTCHA protection on sensitive endpoints
- Swagger UI (enabled in development)

## Architecture

The solution follows a clean architecture pattern:

| Project | Description |
|---|---|
| `Domain` | Entities, interfaces, models, and enums |
| `DataAccess` | MongoDB repository implementations |
| `Service` | Business logic (user, JWT, email, security, Turnstile) |
| `IoCConfig` | Dependency injection wiring |
| `WebApi` | ASP.NET Core Web API (controllers, view models, email templates) |
| `Service.test` | Unit tests |

## API Endpoints

All endpoints are under `/api/auth`.

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/login` | — | Sign in with email and password |
| `POST` | `/register` | — | Create a new account |
| `GET` | `/logout` | — | Sign out and revoke tokens |
| `GET` | `/refresh-token` | — | Refresh the access token from cookie |
| `GET` | `/user` | JWT | Get current user info |
| `POST` | `/change-password` | JWT | Change password |
| `POST` | `/forgot-password` | — | Send a password reset email |
| `POST` | `/reset-password` | — | Reset password using emailed token |
| `POST` | `/resend-verification-email` | — | Resend the email verification link |
| `GET` | `/verify-email` | — | Verify email with token from link |
| `GET` | `/google-login` | — | Redirect to Google OAuth consent |
| `GET` | `/google-callback` | — | Handle Google OAuth callback |

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and Docker Compose
- A [Google Cloud](https://console.cloud.google.com) project with OAuth 2.0 credentials (for Google sign-in)
- A [Cloudflare Turnstile](https://www.cloudflare.com/products/turnstile/) site key and secret key
- An SMTP server for sending emails

## Run in Docker

### 1. Generate an HTTPS Certificate

#### Windows

```shell
dotnet dev-certs https -ep %USERPROFILE%\.aspnet\https\aspnetapp.pfx -p <CERT_PASSWORD>
dotnet dev-certs https --trust
```

#### Linux

```shell
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout aspnetcore.key -out aspnetcore.crt -subj "/CN=localhost"
openssl pkcs12 -export -out aspnetcore.pfx \
  -inkey aspnetcore.key -in aspnetcore.crt
```

Update the volume mount in `docker-compose.yml` to point to the generated `.pfx` file:

```yml
volumes:
  - type: bind
    source: ./aspnetcore.pfx
    target: /https/aspnetcore.pfx
```

### 2. Create the Data Protection Keys Folder

This folder is shared between containers so that cookies can be encrypted/decrypted across restarts:

```shell
mkdir DataProtectionKeys
```

Ensure it is mounted in `docker-compose.yml`:

```yml
volumes:
  - type: bind
    source: ./DataProtectionKeys
    target: /app/DataProtectionKeys
```

### 3. Generate the RSA Key Pair

JWTs are signed with a private key and verified by client apps using the corresponding public key.

#### Option A — Jupyter Notebook (recommended)

Open and run `generate-RSA.ipynb` included in the repository.

#### Option B — C# Interactive

```csharp
using System.Security.Cryptography;
using (var rsa = RSA.Create(2048))
{
    var privateKey = rsa.ExportRSAPrivateKey();
    Console.WriteLine("Private Key:");
    Console.WriteLine(Convert.ToBase64String(privateKey));

    var publicKey = rsa.ExportRSAPublicKey();
    Console.WriteLine("\nPublic Key:");
    Console.WriteLine(Convert.ToBase64String(publicKey));
}
```

#### Option C — Bash / OpenSSL

```shell
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl pkey -in private_key.pem -outform DER | base64 -w 0

openssl rsa -pubout -in private_key.pem -out public_key.pem
openssl rsa -pubin -in public_key.pem -outform DER | base64 -w 0
```

### 4. Create a `.env` File

Create a `.env` file in the repository root with the following variables:

```env
# HTTPS certificate
ASPNETCORE_Kestrel__Certificates__Default__Path=/https/aspnetcore.pfx
ASPNETCORE_Kestrel__Certificates__Default__Password=<CERT_PASSWORD>

# RSA private key (base64-encoded DER)
Jwt__PrivateKey=<PRIVATE_KEY>

# JWT settings
Jwt__Issuer=https://localhost:8001
Jwt__Audience=http://localhost:5010
Jwt__AccessTokenExpirationMinutes=5
Jwt__RefreshTokenExpirationMinutes=60
Jwt__CookieName=microidp
Jwt__DataProtectionApplicationName=microidp
Jwt__DataProtectionPurpose=JwtCookieEncryption
Jwt__DataProtectionKeysPath=./DataProtectionKeys
Jwt__AllowMultipleLoginsFromTheSameUser=true
Jwt__AllowSignoutAllUserActiveClients=true

# MongoDB
ConnectionStrings__MongoDb=mongodb://microidp:microidp@mongo:27017
DbName=MicroIDP

# SMTP
SMTP__Host=<SMTP_HOST>
SMTP__Port=587
SMTP__Username=<SMTP_USERNAME>
SMTP__Password=<SMTP_PASSWORD>

# Email templates
EmailTemplate__ResetPasswordUrl=https://localhost:8001/reset-password
EmailTemplate__EmailVerificationUrl=https://localhost:8001/verify-email
EmailTemplate__ApplicationName=MicroIDP

# Google OAuth
OAuth__GoogleClientId=<GOOGLE_CLIENT_ID>
OAuth__GoogleClientSecret=<GOOGLE_CLIENT_SECRET>
OAuth__GoogleCallbackURL=<CLIENT_APP_GOOGLE_CALLBACK_URL>

# Cloudflare Turnstile
Turnstile__SecretKey=<TURNSTILE_SECRET_KEY>

# Data Protection
DataProtection__GeneralPurposeKey=<RANDOM_SECRET_STRING>
```

### 5. Configure Google Sign-In

1. Create an OAuth 2.0 client ID in [Google Cloud Console](https://console.cloud.google.com).
2. Add `https://localhost:8001/api/auth/google-callback` (or your production URL) as an authorised redirect URI.
3. Set `OAuth__GoogleClientId` and `OAuth__GoogleClientSecret` in `.env`.
4. Set `OAuth__GoogleCallbackURL` to the page in **your client app** that Google redirects to after consent. That page should then call `GET https://IDP_SERVER_URL/api/auth/google-callback` to receive the JWT cookie.

### 6. Start the Service

```shell
docker compose up --wait
```

The API will be available at `https://localhost:8001`. Swagger UI is served at `https://localhost:8001/swagger` when `EnableSwagger` is `true`.

## Integrating with a Client App

Client apps validate JWTs using only the **public key**. The access token is never exposed to JavaScript — it lives inside an encrypted, HTTP-only, `Secure`, `SameSite=Strict` cookie managed by MicroIDP.

### 1. Add Jwt Section to `appsettings.json`

```json
"Jwt": {
    "PublicKey": "<PUBLIC_KEY>",
    "Issuer": "https://localhost:8001",
    "Audience": "http://localhost:5010",
    "DataProtectionApplicationName": "microidp",
    "DataProtectionKeysPath": "./DataProtectionKeys",
    "CookieName": "microidp",
    "DataProtectionPurpose": "JwtCookieEncryption"
}
```

`CookieName` and `DataProtectionPurpose` must match the values used by MicroIDP.

### 2. Install Required Packages

```shell
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.AspNetCore.DataProtection
```

### 3. Register Authentication Middleware

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
                if (context.Request.Cookies.TryGetValue(configuration["Jwt:CookieName"] ?? "", out var encryptedToken))
                {
                    var dataProtector = context.HttpContext.RequestServices
                        .GetRequiredService<IDataProtectionProvider>()
                        .CreateProtector(configuration["Jwt:DataProtectionPurpose"] ?? "");

                    try
                    {
                        var authCookie = JsonSerializer.Deserialize<AuthCookie>(
                            dataProtector.Unprotect(encryptedToken));
                        context.Token = authCookie?.AccessToken;
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

The `DataProtectionKeys` folder must be the **same shared folder** mounted into the MicroIDP container so that keys are identical on both sides.

## License

See [LICENSE](LICENSE).
