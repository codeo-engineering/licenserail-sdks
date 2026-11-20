using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace LicenseRail;

/// <summary>Collects the hashed device fingerprint on Windows, macOS and Linux. Raw values never leave the device.</summary>
public static partial class Fingerprints
{
    /// <summary>
    /// <c>hex(SHA256(vendor + ":" + product + ":" + part + ":" + upper(trim(raw))))</c>; blank → "none". <paramref name="vendor"/> is the
    /// organization ID (ten_..., never changes).
    /// </summary>
    public static string Hash(string vendor, string product, string part, string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return MachineFingerprint.Unavailable;
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"{vendor}:{product}:{part}:{raw.Trim().ToUpperInvariant()}"))).ToLowerInvariant();
    }

    public static MachineFingerprint Collect(string vendor, string product)
    {
        (string? machine, string? disk, string? host, string? board, string os) =
            OperatingSystem.IsWindows() ? Windows() : OperatingSystem.IsMacOS() ? MacOs() : Linux();
        if (board is not null && Placeholder().IsMatch(board.Replace("-", "")))
            board = null;
        return new MachineFingerprint(Hash(vendor, product, "machine", machine), Hash(vendor, product, "disk", disk), Hash(vendor, product, "host", host),
            Hash(vendor, product, "board", board), os);
    }

    private static (string?, string?, string?, string?, string) Windows()
    {
        string? machine = Match(Run("reg", "query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid /reg:64"), @"MachineGuid\s+REG_SZ\s+(\S+)");
        Match vol = Regex.Match(Run("cmd", $"/c vol {Environment.GetEnvironmentVariable("SystemDrive") ?? "C:"}") ?? "", "([0-9A-F]{4})-([0-9A-F]{4})", RegexOptions.IgnoreCase);
        string? board = Run("powershell", "-NoProfile -Command \"(Get-CimInstance Win32_ComputerSystemProduct).UUID\"")?.Trim();
        return (machine, vol.Success ? (vol.Groups[1].Value + vol.Groups[2].Value).ToUpperInvariant() : null, Environment.MachineName, board, "windows");
    }

    private static (string?, string?, string?, string?, string) MacOs()
    {
        string io = Run("ioreg", "-rd1 -c IOPlatformExpertDevice") ?? "";
        string? volume = Match(Run("diskutil", "info /"), @"Volume UUID:\s*([0-9A-F-]+)");
        string host = Run("scutil", "--get LocalHostName")?.Trim() is { Length: > 0 } h ? h : Environment.MachineName;
        return (Match(io, "\"IOPlatformSerialNumber\"\\s*=\\s*\"([^\"]+)\""), volume, host, Match(io, "\"IOPlatformUUID\"\\s*=\\s*\"([^\"]+)\""), "macos");
    }

    private static (string?, string?, string?, string?, string) Linux()
    {
        string? machine = ReadFirst("/etc/machine-id", "/var/lib/dbus/machine-id");
        string? disk = null;
        foreach (string line in (ReadFirst("/proc/self/mountinfo") ?? "").Split('\n'))
        {
            string[] f = line.Split(' ');
            int dash = Array.IndexOf(f, "-");
            if (f.Length > 4 && f[4] == "/" && dash > 0 && dash + 2 < f.Length)
            {
                disk = Run("blkid", $"-s UUID -o value {f[dash + 2]}")?.Trim() is { Length: > 0 } u ? u : null;
                break;
            }
        }
        return (machine, disk, Environment.MachineName, ReadFirst("/sys/class/dmi/id/product_uuid"), "linux");
    }

    private static string? Match(string? text, string pattern) =>
        text is null ? null : Regex.Match(text, pattern, RegexOptions.IgnoreCase) is { Success: true } m ? m.Groups[1].Value : null;

    private static string? ReadFirst(params string[] paths)
    {
        foreach (string p in paths)
        {
            try
            {
                if (File.Exists(p) && File.ReadAllText(p).Trim() is { Length: > 0 } v)
                    return v;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        return null;
    }

    private static string? Run(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true });
            if (p is null) return null;
            string output = p.StandardOutput.ReadToEnd();
            return p.WaitForExit(5000) ? output : null;
        }
        catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException)
        {
            return null;
        }
    }

    [GeneratedRegex("^[0F]+$", RegexOptions.IgnoreCase)]
    private static partial Regex Placeholder();
}
