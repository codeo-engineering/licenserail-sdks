using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace LicenseRail;

public sealed class LicenseClientOptions
{
    /// <summary>Base URL of the licensing service, e.g. https://api.licenserail.com</summary>
    public required Uri ServerUrl { get; init; }
    /// <summary>Your organization ID from the dashboard (ten_...; part of every device identity).</summary>
    public required string Vendor { get; init; }
    /// <summary>The product code from the dashboard.</summary>
    public required string Product { get; init; }
    /// <summary>The environment's public key (PEM).</summary>
    public required string PublicKeyPem { get; init; }
    /// <summary>License file and run history folder; default: a per-user folder.</summary>
    public string? StorageDirectory { get; init; }
    public string? AppVersion { get; init; }
    /// <summary>Refresh online on every check (default: only when the token says it is due).</summary>
    public bool RefreshOnStartup { get; init; }
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromSeconds(10);
    public string? MachineName { get; init; }
}

public sealed record ActivationResult(bool Success, string? ErrorCode, string Message);

/// <summary>Read-only view of the current license.</summary>
public sealed class License(LicensePayload payload)
{
    public LicensePayload Payload { get; } = payload;
    public string Key => Payload.LicenseKey;
    public string Customer => Payload.Customer;
    public string Kind => Payload.Kind;
    public DateTimeOffset? ExpiresAt => Payload.ExpiresAt;
    public DateTimeOffset OfflineUntil => Payload.OfflineUntil;
    public bool IsTest => Payload.Test == true;
    public bool IsFloating => Payload.Floating == true;
    public IReadOnlyList<string> Features => Payload.Entitlements ?? [];
    public System.Text.Json.Nodes.JsonObject? Metadata => Payload.Metadata;
    public bool HasFeature(string code) => Features.Contains(code);
}

/// <summary>Current state: the evaluation plus the license it was made on.</summary>
public sealed record LicenseState(LicenseStatus Status, License? License)
{
    public bool IsValid => Status == LicenseStatus.Valid;
}

/// <summary>
/// Licensing for a vendor's app: offline verification on every start, online refresh when due, activation, deactivation and
/// floating leases. Needs only the public key; never put an API key in an app.
/// </summary>
public sealed class LicenseClient : IDisposable
{
    public static readonly IReadOnlySet<string> RevokingCodes = new HashSet<string>
    {
        "license_not_found", "license_suspended", "license_expired", "activation_revoked", "wrong_machine", "invalid_token", "license_revoked",
    };

    private readonly LicenseClientOptions _options;
    private readonly HttpClient _http;
    private readonly ECDsa _key;
    private readonly Lazy<MachineFingerprint> _fingerprint;
    private readonly TimeProvider _clock;
    private readonly string _dir;
    private Timer? _heartbeat;

    public LicenseClient(LicenseClientOptions options) : this(options, null, null, null) { }

    /// <summary>For tests: custom fingerprint, clock and HTTP handler.</summary>
    public LicenseClient(LicenseClientOptions options, Func<MachineFingerprint>? fingerprint, TimeProvider? clock, HttpMessageHandler? handler)
    {
        _options = options;
        _key = LicenseToken.ImportKey(options.PublicKeyPem);
        _fingerprint = new(fingerprint ?? (() => Fingerprints.Collect(options.Vendor, options.Product)));
        _clock = clock ?? TimeProvider.System;
        _http = handler is null ? new HttpClient() : new HttpClient(handler, disposeHandler: false);
        _http.BaseAddress = options.ServerUrl;
        _http.Timeout = options.RequestTimeout;
        _dir = options.StorageDirectory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "licenserail", options.Product);
    }

    public LicenseState Current { get; private set; } = new(LicenseStatus.Missing, null);
    public string? LastServerMessage { get; private set; }

    /// <summary>Offline evaluation only.</summary>
    public LicenseState EvaluateLocal()
    {
        string? token = Read("license.lic");
        if (token is null)
            return Current = new(LicenseStatus.Missing, null);
        LicensePayload? payload = LicenseToken.Verify(token, _key);
        DateTimeOffset now = _clock.GetUtcNow();
        DateTimeOffset? lastSeen = DecodeHistory(Read("license.seen"));
        LicenseEvaluation e = LicenseEvaluator.Evaluate(payload, _options.Product, _fingerprint.Value, now, lastSeen);
        if (e.Status is LicenseStatus.Valid or LicenseStatus.Expired or LicenseStatus.OfflineTooLong && (lastSeen is null || now > lastSeen))
            Write("license.seen", EncodeHistory(now));
        return Current = new(e.Status, payload is null ? null : new License(payload));
    }

    /// <summary>Call on startup: evaluates offline, refreshes online when due or when only the server can clear the state.</summary>
    public async Task<LicenseState> CheckAsync(CancellationToken ct = default)
    {
        LicenseState state = EvaluateLocal();
        bool due = state.IsValid && (_options.RefreshOnStartup || _clock.GetUtcNow() >= state.License!.Payload.RefreshAfter);
        if (due || state.Status is LicenseStatus.Expired or LicenseStatus.Suspended or LicenseStatus.OfflineTooLong or LicenseStatus.ClockTampered or LicenseStatus.Unverified)
        {
            string[]? anomalies = state.Status switch
            {
                LicenseStatus.ClockTampered => ["clock_rollback"],
                LicenseStatus.Unverified => ["history_missing"],
                _ => null,
            };
            try { await RefreshAsync(anomalies, ct).ConfigureAwait(false); }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException) { }
            state = EvaluateLocal();
        }
        if (state.License?.IsTest == true)
            Console.Error.WriteLine("[licenserail] Test license: not for production use.");
        return state;
    }

    public async Task<ActivationResult> ActivateAsync(string licenseKey, string? machineName = null, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(licenseKey))
            return new(false, "bad_request", "Enter the license key.");
        var body = new
        {
            licenseKey = licenseKey.Trim(), product = _options.Product, fingerprint = _fingerprint.Value,
            machineName = machineName ?? _options.MachineName ?? Environment.MachineName, appVersion = _options.AppVersion,
        };
        try
        {
            var (ok, token, error) = await PostAsync("api/client/v2/activate", body, ct).ConfigureAwait(false);
            if (!ok && error?.Code == "bad_request" && error.Message.Contains("floating", StringComparison.OrdinalIgnoreCase))
                (ok, token, error) = await PostAsync("api/client/v2/floating/checkout", body, ct).ConfigureAwait(false);
            if (!ok)
                return new(false, error?.Code, error?.Message ?? "Server error.");
            if (!SaveIfValid(token!))
                return new(false, "invalid_token", "The server returned an invalid license.");
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new(false, "network", "Could not connect to the license server.");
        }
        LicenseState state = EvaluateLocal();
        if (state.License?.IsFloating == true)
            StartHeartbeat();
        return state.IsValid ? new(true, null, "The license has been activated.") : new(false, state.Status.ToString(), state.Status.ToString());
    }

    public Task<ActivationResult> CheckoutAsync(string licenseKey, CancellationToken ct = default) => ActivateAsync(licenseKey, null, ct);

    public Task<ActivationResult> ReleaseAsync(CancellationToken ct = default) => DeactivateAsync(ct);

    public async Task<ActivationResult> DeactivateAsync(CancellationToken ct = default)
    {
        StopHeartbeat();
        string? token = Read("license.lic");
        if (token is null)
            return new(true, null, "There is no license on this device.");
        bool floating = LicenseToken.Verify(token, _key)?.Floating == true;
        try
        {
            var (ok, _, error) = await PostAsync(floating ? "api/client/v2/floating/release" : "api/client/v2/deactivate",
                new { token, fingerprint = _fingerprint.Value }, ct).ConfigureAwait(false);
            if (!ok && (error is null || !RevokingCodes.Contains(error.Code)))
                return new(false, error?.Code, error?.Message ?? "Server error.");
            Delete("license.lic");
            return ok || error!.Code != "wrong_machine" ? new(true, null, "The license has been removed from this device.") : new(false, error.Code, error.Message);
        }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException)
        {
            return new(false, "network", "Removing the license needs an internet connection.");
        }
    }

    public Task RefreshAsync(CancellationToken ct = default) => RefreshAsync(null, ct);

    private async Task RefreshAsync(string[]? anomalies, CancellationToken ct)
    {
        string? token = Read("license.lic");
        if (token is null)
            return;
        bool floating = LicenseToken.Verify(token, _key)?.Floating == true;
        var (ok, fresh, error) = await PostAsync(floating ? "api/client/v2/floating/heartbeat" : "api/client/v2/refresh",
            new { token, fingerprint = _fingerprint.Value, appVersion = _options.AppVersion, anomalies }, ct).ConfigureAwait(false);
        if (ok)
            SaveIfValid(fresh!);
        else if (error is not null && (RevokingCodes.Contains(error.Code) || error.Code == "lease_expired"))
        {
            Delete("license.lic");
            LastServerMessage = error.Message;
        }
    }

    private void StartHeartbeat()
    {
        StopHeartbeat();
        if (Current.License is not { IsFloating: true } l)
            return;
        TimeSpan half = TimeSpan.FromTicks(Math.Max(TimeSpan.FromSeconds(30).Ticks, (l.OfflineUntil - l.Payload.IssuedAt).Ticks / 2));
        _heartbeat = new Timer(_ => { try { RefreshAsync().GetAwaiter().GetResult(); } catch (Exception) { } }, null, half, half);
    }

    private void StopHeartbeat()
    {
        _heartbeat?.Dispose();
        _heartbeat = null;
    }

    private sealed record ErrorBody(string Code, string Message);
    private sealed record TokenBody(string Token);

    private async Task<(bool Ok, string? Token, ErrorBody? Error)> PostAsync(string path, object body, CancellationToken ct)
    {
        using HttpResponseMessage r = await _http.PostAsJsonAsync(path, body, LicenseToken.JsonOptions, ct).ConfigureAwait(false);
        if (r.StatusCode == System.Net.HttpStatusCode.NoContent)
            return (true, null, null);
        if (r.IsSuccessStatusCode)
            return (true, (await r.Content.ReadFromJsonAsync<TokenBody>(LicenseToken.JsonOptions, ct).ConfigureAwait(false))?.Token, null);
        try
        {
            return (false, null, await r.Content.ReadFromJsonAsync<ErrorBody>(LicenseToken.JsonOptions, ct).ConfigureAwait(false));
        }
        catch (JsonException)
        {
            return (false, null, null);
        }
    }

    private bool SaveIfValid(string token)
    {
        if (LicenseToken.Verify(token, _key) is not { } p || !string.Equals(p.Product, _options.Product, StringComparison.OrdinalIgnoreCase))
            return false;
        Write("license.lic", token);
        Write("license.seen", EncodeHistory(_clock.GetUtcNow()));
        return true;
    }

    private byte[] HistoryKey => SHA256.HashData(Encoding.UTF8.GetBytes($"{_options.Vendor}:run-history:{_options.Product}:{_fingerprint.Value.MachineId}:{_fingerprint.Value.BoardId}"));

    private string Mac(string ms) => Convert.ToHexString(HMACSHA256.HashData(HistoryKey, Encoding.ASCII.GetBytes(ms)))[..32];

    private string EncodeHistory(DateTimeOffset at)
    {
        string ms = at.ToUnixTimeMilliseconds().ToString(CultureInfo.InvariantCulture);
        return ms + "." + Mac(ms);
    }

    private DateTimeOffset? DecodeHistory(string? value)
    {
        string[]? parts = value?.Trim().Split('.');
        if (parts is not { Length: 2 } || !long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out long ms))
            return null;
        return CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(parts[1]), Encoding.ASCII.GetBytes(Mac(parts[0])))
            ? DateTimeOffset.FromUnixTimeMilliseconds(ms) : null;
    }

    private string? Read(string name)
    {
        try { return File.Exists(Path.Combine(_dir, name)) ? File.ReadAllText(Path.Combine(_dir, name)).Trim() : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private void Write(string name, string value)
    {
        Directory.CreateDirectory(_dir);
        File.WriteAllText(Path.Combine(_dir, name), value);
    }

    private void Delete(string name)
    {
        try { File.Delete(Path.Combine(_dir, name)); } catch (IOException) { }
    }

    public void Dispose()
    {
        StopHeartbeat();
        _http.Dispose();
        _key.Dispose();
    }
}
