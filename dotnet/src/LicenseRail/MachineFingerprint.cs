using System.Text.Json.Serialization;

namespace LicenseRail;

/// <summary>
/// Hashed components that identify a computer. Raw hardware info never reaches the server.
/// </summary>
/// <param name="MachineId">Windows MachineGuid (changes when the OS is reinstalled); /etc/machine-id on Linux.</param>
/// <param name="DiskId">Volume serial number (Windows) or filesystem UUID of the system drive.</param>
/// <param name="HostName">Computer name.</param>
/// <param name="BoardId">SMBIOS system UUID from the firmware. Unlike the other three it can't be changed from the OS.</param>
/// <param name="Os">
/// windows, macos, linux, android or ios. Optional and last on purpose: legacy clients don't send it (null = Windows), and the
/// API binds requests with required constructor parameters, so a required one would reject every legacy request.
/// </param>
public sealed record MachineFingerprint(
    string MachineId,
    string DiskId,
    string HostName,
    string BoardId,
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? Os = null)
{
    /// <summary>Value sent for a component that couldn't be read. Never counts as a match.</summary>
    public const string Unavailable = "none";

    /// <summary>
    /// Whether <paramref name="other"/> is the computer this fingerprint was registered for. Call it on the registered fingerprint.
    /// <para>If the registered computer has a board ID, it must match plus one of the other three: the license survives
    /// an OS reinstall or a new disk, but registry, disk serial and computer name, all editable from the OS,
    /// can't move it to another computer. Without a board ID, 2 of the other 3 must match. When both sides name their
    /// operating system, it must be the same.</para>
    /// </summary>
    public bool Matches(MachineFingerprint other)
    {
        if (Os is { Length: > 0 } mine && other.Os is { Length: > 0 } theirs
            && !string.Equals(mine, theirs, StringComparison.OrdinalIgnoreCase))
            return false;

        int matches = 0;
        if (Same(MachineId, other.MachineId)) matches++;
        if (Same(DiskId, other.DiskId)) matches++;
        if (Same(HostName, other.HostName)) matches++;

        // Deliberately one-sided: a computer that reports "none" can't sidestep a registered board ID.
        return IsAvailable(BoardId)
            ? Same(BoardId, other.BoardId) && matches >= 1
            : matches >= 2;
    }

    private static bool IsAvailable(string? value) => !string.IsNullOrEmpty(value) && value != Unavailable;

    private static bool Same(string? a, string? b) => IsAvailable(a) && string.Equals(a, b, StringComparison.Ordinal);
}
