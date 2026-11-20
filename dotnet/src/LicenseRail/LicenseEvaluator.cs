namespace LicenseRail;

public enum LicenseStatus
{
    Valid,
    Missing,
    InvalidSignature,
    WrongProduct,
    WrongMachine,
    Expired,
    OfflineTooLong,
    ClockTampered,
    /// <summary>The license file is there but the client's run history is gone (deleted to hide a clock rollback); only the server can clear it.</summary>
    Unverified,
    /// <summary>The server suspended the license; the file stays on the computer until the license is resumed.</summary>
    Suspended,
}

public sealed record LicenseEvaluation(LicenseStatus Status, LicensePayload? Payload)
{
    public bool IsValid => Status == LicenseStatus.Valid;
}

/// <summary>Pure license check that needs no internet. The client runs it on every startup.</summary>
public static class LicenseEvaluator
{
    /// <summary>The clock going back slightly during NTP sync is normal; this much is tolerated.</summary>
    public static readonly TimeSpan ClockTolerance = TimeSpan.FromMinutes(10);

    /// <summary>
    /// The license's issue time is based on the server clock. The computer's clock may lag behind the server (wrong time zone,
    /// battery); this comparison allows a wider margin so the license isn't rejected right after activation.
    /// </summary>
    public static readonly TimeSpan IssuedAtTolerance = TimeSpan.FromDays(1);

    /// <param name="lastSeen">
    /// When the client last ran (to detect a clock that was turned back). The client records it every time it saves a license,
    /// so null next to a license means the record was removed: <see cref="LicenseStatus.Unverified"/>.
    /// </param>
    public static LicenseEvaluation Evaluate(
        LicensePayload? payload, string product, MachineFingerprint machine, DateTimeOffset now, DateTimeOffset? lastSeen)
    {
        if (payload is null)
            return new(LicenseStatus.InvalidSignature, null);
        if (!string.Equals(payload.Product, product, StringComparison.OrdinalIgnoreCase))
            return new(LicenseStatus.WrongProduct, payload);
        if (!payload.Fingerprint.Matches(machine))
            return new(LicenseStatus.WrongMachine, payload);
        if (payload.Suspended)
            return new(LicenseStatus.Suspended, payload);
        if (lastSeen is not { } seen)
            return new(LicenseStatus.Unverified, payload);

        // If the license appears to be issued in the future, or time has gone back since the last run, the clock was turned back.
        if (now + IssuedAtTolerance < payload.IssuedAt || now + ClockTolerance < seen)
            return new(LicenseStatus.ClockTampered, payload);

        if (payload.ExpiresAt is { } expires && now >= expires)
            return new(LicenseStatus.Expired, payload);
        if (now >= payload.OfflineUntil)
            return new(LicenseStatus.OfflineTooLong, payload);

        return new(LicenseStatus.Valid, payload);
    }
}
