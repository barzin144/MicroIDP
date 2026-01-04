using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using Domain.Models;
using Domain.Services;

namespace Service;

public class TurnstileVerifyResponse
{
    public bool Success { get; set; }
}
public class TurnstileService : ITurnstileService
{
    private readonly HttpClient _httpClient;
    private readonly TurnstileOptions _turnstileSettings;

    public TurnstileService(HttpClient httpClient, TurnstileOptions turnstileSettings)
    {
        _httpClient = httpClient;
        _turnstileSettings = turnstileSettings;
    }
    public async Task<bool> Verify(string token)
    {
        var formData = new Dictionary<string, string> { { "secret", _turnstileSettings.SecretKey }, { "response", token } };

        var content = new FormUrlEncodedContent(formData);

        try
        {
            var response = await _httpClient.PostAsync("/turnstile/v0/siteverify", content);

            if (response.IsSuccessStatusCode)
            {
                var responseBody = await response.Content.ReadFromJsonAsync<TurnstileVerifyResponse>();
                if (responseBody?.Success == true)
                {
                    return true;
                }
            }
        }
        catch { }

        return false;
    }
}
