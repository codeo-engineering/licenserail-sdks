using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace LicenseRail.Management;

public sealed class ApiRequestException(int status, string code, string message, JsonNode? body) : Exception(message)
{
    public int Status { get; } = status;
    public string Code { get; } = code;
    public JsonNode? Body { get; } = body;
}

/// <summary>Server-side client for /api/v2. Needs a secret API key: never ship it in an app.</summary>
public sealed class ManagementClient(string apiKey, Uri? baseUrl = null, string? environment = null, HttpClient? http = null)
{
    private readonly HttpClient _http = http ?? new HttpClient();
    private readonly Uri _base = baseUrl ?? new Uri("https://api.licenserail.com");

    public async Task<JsonNode?> RequestAsync(HttpMethod method, string path, object? body = null, IDictionary<string, string>? headers = null,
        CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(method, new Uri(_base, "/api/v2" + path));
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", apiKey);
        if (environment is not null) req.Headers.Add("X-Environment", environment);
        if (method != HttpMethod.Get) req.Headers.Add("Idempotency-Key", Guid.NewGuid().ToString());
        foreach (var (k, v) in headers ?? new Dictionary<string, string>()) req.Headers.Add(k, v);
        if (body is not null) req.Content = new StringContent(JsonSerializer.Serialize(body, new JsonSerializerOptions(JsonSerializerDefaults.Web)), Encoding.UTF8, "application/json");
        using HttpResponseMessage res = await _http.SendAsync(req, ct).ConfigureAwait(false);
        string text = await res.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        JsonNode? json = text.Length > 0 ? JsonNode.Parse(text) : null;
        if (!res.IsSuccessStatusCode)
            throw new ApiRequestException((int)res.StatusCode, json?["error"]?["code"]?.GetValue<string>() ?? "error",
                json?["error"]?["message"]?.GetValue<string>() ?? $"HTTP {(int)res.StatusCode}", json);
        return json;
    }

    public Task<JsonNode?> CreateProductAsync(string code, string name, CancellationToken ct = default) =>
        RequestAsync(HttpMethod.Post, "/products", new { code, name }, null, ct);
    public Task<JsonNode?> CreateCustomerAsync(string name, CancellationToken ct = default) =>
        RequestAsync(HttpMethod.Post, "/customers", new { name }, null, ct);
    public Task<JsonNode?> CreateLicensesAsync(object body, CancellationToken ct = default) => RequestAsync(HttpMethod.Post, "/licenses", body, null, ct);
    public Task<JsonNode?> GetLicenseAsync(string id, CancellationToken ct = default) => RequestAsync(HttpMethod.Get, $"/licenses/{id}", null, null, ct);
    public Task<JsonNode?> RevokeLicenseAsync(string id, string? approvalId = null, CancellationToken ct = default) =>
        RequestAsync(HttpMethod.Post, $"/licenses/{id}/revoke", null, approvalId is null ? null : new Dictionary<string, string> { ["Approval-Id"] = approvalId }, ct);

    /// <summary>Verifies a Standard Webhooks signature with the endpoint's whsec_ secret.</summary>
    public static bool VerifyWebhook(string secret, string id, string timestamp, string signature, string body, TimeSpan? tolerance = null)
    {
        if (!long.TryParse(timestamp, out long ts) || Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - ts) > (tolerance ?? TimeSpan.FromMinutes(5)).TotalSeconds)
            return false;
        byte[] key = Convert.FromBase64String(secret.StartsWith("whsec_", StringComparison.Ordinal) ? secret[6..] : secret);
        string expected = Convert.ToBase64String(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes($"{id}.{timestamp}.{body}")));
        return signature.Split(' ').Any(s => s.StartsWith("v1,", StringComparison.Ordinal)
            && CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(s[3..]), Encoding.ASCII.GetBytes(expected)));
    }
}
