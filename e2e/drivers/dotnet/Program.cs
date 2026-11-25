using System.Text.Json;
using LicenseRail;

string Env(string name) => Environment.GetEnvironmentVariable(name) ?? "";
string[] d = Env("LR_DEVICE").Split(',');
using var client = new LicenseClient(new LicenseClientOptions
{
    ServerUrl = new Uri(Env("LR_URL")), Vendor = Env("LR_VENDOR"), Product = Env("LR_PRODUCT"), PublicKeyPem = File.ReadAllText(Env("LR_PUBLIC_KEY_FILE")),
    StorageDirectory = Env("LR_STORAGE"), AppVersion = "1.2.3", RequestTimeout = TimeSpan.FromSeconds(int.Parse(Env("LR_TIMEOUT"))),
}, d.Length == 4 ? () => new MachineFingerprint(d[0], d[1], d[2], d[3], "linux") : null, null, null);

object result;
switch (args[0])
{
    case "activate": result = Out(await client.ActivateAsync(args[1])); break;
    case "deactivate": result = Out(await client.DeactivateAsync()); break;
    case "refresh":
        try { await client.RefreshAsync(); result = new { success = true }; }
        catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException or JsonException) { result = new { success = false, errorCode = "network", message = ex.Message }; }
        break;
    default:
        LicenseState s = await client.CheckAsync();
        result = new { status = s.Status.ToString(), features = s.License?.Features ?? [], test = s.License?.IsTest ?? false };
        break;
}
Console.WriteLine(JsonSerializer.Serialize(result));

static object Out(ActivationResult r) => new { success = r.Success, errorCode = r.ErrorCode, message = r.Message };
