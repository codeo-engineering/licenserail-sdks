using System.Text.Json;
using System.Text.Json.Nodes;
using LicenseRail;

namespace LicenseRail.Tests;

public class VectorTests
{
    private static JsonNode Load(string name)
    {
        string dir = AppContext.BaseDirectory;
        while (!Directory.Exists(Path.Combine(dir, "test-vectors"))) dir = Path.GetDirectoryName(dir)!;
        return JsonNode.Parse(File.ReadAllText(Path.Combine(dir, "test-vectors", name)))!;
    }

    private static MachineFingerprint Fp(JsonNode n) =>
        new(n["machineId"]!.GetValue<string>(), n["diskId"]!.GetValue<string>(), n["hostName"]!.GetValue<string>(), n["boardId"]!.GetValue<string>(),
            n["os"]?.GetValue<string>());

    [Fact]
    public void Tokens()
    {
        JsonNode v = Load("tokens.json");
        using var key = LicenseToken.ImportKey(v["publicKeyPem"]!.GetValue<string>());
        foreach (JsonNode c in v["cases"]!.AsArray()!)
        {
            LicensePayload? p = LicenseToken.Verify(c["token"]!.GetValue<string>(), key);
            Assert.True((p is not null) == c["expect"]!["signatureValid"]!.GetValue<bool>(), c["name"]!.GetValue<string>());
            if (c["expect"]!["payload"] is JsonObject expected)
            {
                JsonNode actual = JsonNode.Parse(JsonSerializer.Serialize(p, LicenseToken.JsonOptions))!;
                foreach (var (k, val) in expected)
                    Assert.True(JsonNode.DeepEquals(val, actual[k]), $"{c["name"]}: {k}");
            }
        }
    }

    [Fact]
    public void Fingerprint()
    {
        foreach (JsonNode c in Load("fingerprint.json")["cases"]!.AsArray()!)
            Assert.Equal(c["hash"]!.GetValue<string>(), Fingerprints.Hash(c["product"]!.GetValue<string>(), c["part"]!.GetValue<string>(), c["raw"]?.GetValue<string>()));
    }

    [Fact]
    public void Match()
    {
        foreach (JsonNode c in Load("match.json")["cases"]!.AsArray()!)
            Assert.True(Fp(c["registered"]!).Matches(Fp(c["presented"]!)) == c["matches"]!.GetValue<bool>(), c["name"]!.GetValue<string>());
    }

    [Fact]
    public void Evaluate()
    {
        JsonNode v = Load("evaluate.json");
        using var key = LicenseToken.ImportKey(v["publicKeyPem"]!.GetValue<string>());
        foreach (JsonNode c in v["cases"]!.AsArray()!)
        {
            LicenseStatus status = LicenseEvaluator.Evaluate(LicenseToken.Verify(c["token"]!.GetValue<string>(), key), c["product"]!.GetValue<string>(),
                Fp(c["machine"]!), DateTimeOffset.Parse(c["now"]!.GetValue<string>()),
                c["lastSeen"] is { } ls ? DateTimeOffset.Parse(ls.GetValue<string>()) : null).Status;
            Assert.True(status.ToString() == c["status"]!.GetValue<string>(), $"{c["name"]}: {status}");
        }
    }
}
