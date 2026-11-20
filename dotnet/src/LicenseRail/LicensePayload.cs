using System.Text.Json.Serialization;

namespace LicenseRail;

public static class LicenseKinds
{
    public const string Full = "full";
    public const string Trial = "trial";
}

/// <summary>License content signed by the server and stored on disk by the client.</summary>
public sealed record LicensePayload
{
    public required Guid LicenseId { get; init; }
    public required Guid ActivationId { get; init; }
    public required string LicenseKey { get; init; }
    public required string Product { get; init; }
    public required string Customer { get; init; }
    public required string Kind { get; init; }

    /// <summary>Exact expiry time of the license. null means perpetual.</summary>
    public DateTimeOffset? ExpiresAt { get; init; }

    public required DateTimeOffset IssuedAt { get; init; }

    /// <summary>After this time the client tries to refresh with the server (and keeps working if that fails).</summary>
    public required DateTimeOffset RefreshAfter { get; init; }

    /// <summary>The last moment the license stays valid if the server can't be reached at all.</summary>
    public required DateTimeOffset OfflineUntil { get; init; }

    public required MachineFingerprint Fingerprint { get; init; }

    /// <summary>
    /// Suspended from the dashboard. The client keeps this signed file instead of deleting it, so it can say why the add-in is
    /// locked and pick the license up again on its own once it is resumed.
    /// </summary>
    public bool Suspended { get; init; }

    // v2 fields. Each is omitted when null, property by property, so a payload without them serializes to exactly the v1
    // bytes (a payload-wide "omit defaults" would also drop v1 values such as "suspended": false).

    /// <summary>The environment whose key signed the token. Absent in legacy tokens (resolved to the legacy Live environment).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public Guid? EnvironmentId { get; init; }

    /// <summary>True only for Test environment tokens.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Test { get; init; }

    /// <summary>Enabled feature codes, sorted; absent when there are none.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public IReadOnlyList<string>? Entitlements { get; init; }

    /// <summary>License metadata (a JSON object).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public System.Text.Json.Nodes.JsonObject? Metadata { get; init; }

    /// <summary>True for a floating lease.</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public bool? Floating { get; init; }

    /// <summary>End of the floating lease (equals <see cref="OfflineUntil"/>).</summary>
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public DateTimeOffset? LeaseExpiresAt { get; init; }
}
