// Minimal app: dotnet run -- <license-key> [--deactivate]  (env: LICENSERAIL_URL, LICENSERAIL_PRODUCT, LICENSERAIL_PUBLIC_KEY_FILE)
using LicenseRail;

using var client = new LicenseClient(new LicenseClientOptions
{
    ServerUrl = new Uri(Environment.GetEnvironmentVariable("LICENSERAIL_URL") ?? "https://api.licenserail.com"),
    Vendor = Environment.GetEnvironmentVariable("LICENSERAIL_VENDOR") ?? "ten_6f1a7e2c3b4d4e5f8a9b0c1d2e3f4a5b",
    Product = Environment.GetEnvironmentVariable("LICENSERAIL_PRODUCT") ?? "my-app",
    PublicKeyPem = File.ReadAllText(Environment.GetEnvironmentVariable("LICENSERAIL_PUBLIC_KEY_FILE") ?? "public-key.pem"),
    AppVersion = "1.0.0",
    StorageDirectory = Environment.GetEnvironmentVariable("LICENSERAIL_STORAGE"),
});

LicenseState state = await client.CheckAsync();
Console.WriteLine($"startup: {state.Status}");
if (!state.IsValid && args.FirstOrDefault(a => !a.StartsWith("--")) is { } key)
{
    ActivationResult activation = await client.ActivateAsync(key);
    Console.WriteLine($"activate: {activation.Success} {activation.Message}");
    state = await client.CheckAsync();
}
Console.WriteLine($"status: {state.Status}, export: {client.Current.License?.HasFeature("export")}");
if (args.Contains("--deactivate"))
    Console.WriteLine($"deactivate: {(await client.DeactivateAsync()).Message}");
