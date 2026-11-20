// Writes the shared test vectors every SDK must pass (token-spec.md §6). Deterministic: a fixed test key, fixed ids and times.
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Codeo.Licensing;

string outDir = args.Length > 0 ? args[0] : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../../test-vectors"));
Directory.CreateDirectory(outDir);
var indented = new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

// Test-only keys (never used by any environment). Committed so vectors can be regenerated identically.
const string TestKeyPem = """
-----BEGIN PRIVATE KEY-----
(removed from history)
-----END PRIVATE KEY-----
""";
using ECDsa key = LoadOrCreate(TestKeyPem);
using ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256);
string publicPem = key.ExportSubjectPublicKeyInfoPem();

var t0 = new DateTimeOffset(2026, 11, 20, 10, 0, 0, TimeSpan.Zero);
var fp = new MachineFingerprint(Hash("acme", "demo-app", "machine", "MACHINE-1"), Hash("acme", "demo-app", "disk", "1A2B3C4D"),
    Hash("acme", "demo-app", "host", "DESKTOP-01"), Hash("acme", "demo-app", "board", "4C4C4544-0042-3510-8048-B4C04F4E4D32"));

LicensePayload V1(Action<LicensePayloadBuilder>? edit = null)
{
    var b = new LicensePayloadBuilder
    {
        P = new LicensePayload
        {
            LicenseId = Guid.Parse("0f8fad5b-d9cb-469f-a165-70867728950e"),
            ActivationId = Guid.Parse("7c9e6679-7425-40de-944b-e07fc1f90ae7"),
            LicenseKey = "ABCDE-FGHJK-MNPQR-STUVW",
            Product = "demo-app",
            Customer = "Acme Ltd",
            Kind = "full",
            ExpiresAt = null,
            IssuedAt = t0,
            RefreshAfter = t0.AddDays(1),
            OfflineUntil = t0.AddDays(30),
            Fingerprint = fp,
            Suspended = false,
        },
    };
    edit?.Invoke(b);
    return b.P;
}

LicensePayload v2Payload = V1(b => b.P = b.P with
{
    EnvironmentId = Guid.Parse("3f2504e0-4f89-41d3-9a0c-0305e82c3301"),
    Test = true,
    Entitlements = ["export", "pro"],
    Metadata = new JsonObject { ["seats"] = 5, ["tier"] = "gold" },
    LicenseKey = "TEST-ABCDE-FGHJK-MNPQR-STUVW",
    OfflineUntil = t0.AddHours(24),
    RefreshAfter = t0.AddHours(1),
    Fingerprint = fp with { Os = "linux" },
});
LicensePayload floating = V1(b => b.P = b.P with
{
    EnvironmentId = Guid.Parse("3f2504e0-4f89-41d3-9a0c-0305e82c3302"),
    Floating = true,
    LeaseExpiresAt = t0.AddMinutes(30),
    OfflineUntil = t0.AddMinutes(30),
    RefreshAfter = t0.AddMinutes(15),
});

string v1Token = LicenseToken.Sign(V1(), key);
string v2Token = LicenseToken.Sign(v2Payload, key);
string floatingToken = LicenseToken.Sign(floating, key);
string otherKeyToken = LicenseToken.Sign(V1(), other);
string tamperedBody = TamperBody(v1Token);
string tamperedSig = TamperSignature(v1Token);
string futureField = SignRaw(Insert(JsonSerializer.Serialize(V1(), LicenseToken.JsonOptions), "\"someFutureField\":{\"x\":[1,2]}"), key);

var tokens = new
{
    description = "Signature check with publicKeyPem (ECDSA P-256, SHA-256, IEEE P1363 r||s). payload = the expected decoded fields (subset).",
    publicKeyPem = publicPem,
    cases = new object[]
    {
        new { name = "v1 legacy payload", token = v1Token, expect = new { signatureValid = true, payload = Payload(V1()) } },
        new { name = "v2 payload with entitlements, metadata, test flag and os", token = v2Token, expect = new { signatureValid = true, payload = Payload(v2Payload) } },
        new { name = "floating lease", token = floatingToken, expect = new { signatureValid = true, payload = Payload(floating) } },
        new { name = "unknown future field is ignored", token = futureField, expect = new { signatureValid = true, payload = Payload(V1()) } },
        new { name = "tampered body", token = tamperedBody, expect = new { signatureValid = false } },
        new { name = "tampered signature", token = tamperedSig, expect = new { signatureValid = false } },
        new { name = "signed by another key", token = otherKeyToken, expect = new { signatureValid = false } },
        new { name = "no dot", token = "abc", expect = new { signatureValid = false } },
        new { name = "three parts", token = "a.b.c", expect = new { signatureValid = false } },
        new { name = "empty", token = "", expect = new { signatureValid = false } },
    },
};
Write("tokens.json", tokens);

// Fingerprint hashing.
var raws = new (string Vendor, string Product, string Part, string? Raw)[]
{
    ("acme", "demo-app", "machine", "6f1a7e2c-3b4d-4e5f-8a9b-0c1d2e3f4a5b"),
    ("acme", "demo-app", "disk", "1A2B3C4D"),
    ("acme", "demo-app", "host", "desktop-01"),
    ("acme", "demo-app", "host", "  Desktop-01  "),
    ("acme", "demo-app", "board", " 4c4c4544-0042-3510-8048-b4c04f4e4d32 "),
    ("acme", "other-app", "board", "4C4C4544-0042-3510-8048-B4C04F4E4D32"),
    ("other-vendor", "demo-app", "board", "4C4C4544-0042-3510-8048-B4C04F4E4D32"),
    ("acme", "demo-app", "disk", ""),
    ("acme", "demo-app", "disk", "   "),
    ("acme", "demo-app", "board", null),
    ("acme", "demo-app", "host", "çağatay-pc"),
};
Write("fingerprint.json", new
{
    description = "component = lowercase_hex(SHA256(utf8(vendor + \":\" + product + \":\" + part + \":\" + upper(trim(raw))))); vendor = the organization's slug (fixed for life); missing or blank raw = \"none\". upper is invariant (Unicode) uppercase.",
    cases = raws.Select(r => new { vendor = r.Vendor, product = r.Product, part = r.Part, raw = r.Raw, hash = Hash(r.Vendor, r.Product, r.Part, r.Raw) }).ToArray(),
});

// Matching.
object F(string m, string d, string h, string b, string? os = null) => new { machineId = m, diskId = d, hostName = h, boardId = b, os };
MachineFingerprint M(string m, string d, string h, string b, string? os = null) => new(m, d, h, b, os);
var matchCases = new (string Name, MachineFingerprint R, MachineFingerprint P)[]
{
    ("identical", M("a", "b", "c", "d"), M("a", "b", "c", "d")),
    ("board + one other", M("a", "b", "c", "d"), M("x", "b", "y", "d")),
    ("board alone is not enough", M("a", "b", "c", "d"), M("x", "y", "z", "d")),
    ("three others without board match fails when board registered", M("a", "b", "c", "d"), M("a", "b", "c", "e")),
    ("no board registered: two of three", M("a", "b", "c", "none"), M("a", "b", "z", "q")),
    ("no board registered: one of three fails", M("a", "b", "c", "none"), M("a", "y", "z", "none")),
    ("none never matches none", M("none", "none", "c", "none"), M("none", "none", "c", "none")),
    ("presented none cannot sidestep registered board", M("a", "b", "c", "d"), M("a", "b", "c", "none")),
    ("same os", M("a", "b", "c", "d", "macos"), M("a", "b", "x", "d", "macos")),
    ("os mismatch fails", M("a", "b", "c", "d", "windows"), M("a", "b", "c", "d", "linux")),
    ("os case-insensitive", M("a", "b", "c", "d", "Windows"), M("a", "b", "c", "d", "windows")),
    ("legacy registered without os matches presented os", M("a", "b", "c", "d"), M("a", "b", "c", "d", "windows")),
    ("empty string never matches", M("", "b", "c", "none"), M("", "y", "c", "none")),
};
Write("match.json", new
{
    description = "registered.Matches(presented): board registered → board equal AND ≥1 of machine/disk/host; else ≥2 of 3. 'none'/empty never match. os compared case-insensitively only when both sides have one.",
    cases = matchCases.Select(c => new
    {
        name = c.Name,
        registered = F(c.R.MachineId, c.R.DiskId, c.R.HostName, c.R.BoardId, c.R.Os),
        presented = F(c.P.MachineId, c.P.DiskId, c.P.HostName, c.P.BoardId, c.P.Os),
        matches = c.R.Matches(c.P),
    }).ToArray(),
});

// Offline evaluation.
string suspendedToken = LicenseToken.Sign(V1(b => b.P = b.P with { Suspended = true }), key);
string expiringToken = LicenseToken.Sign(V1(b => b.P = b.P with { ExpiresAt = t0.AddDays(10) }), key);
var otherMachine = new MachineFingerprint(Hash("acme", "demo-app", "machine", "X"), Hash("acme", "demo-app", "disk", "Y"), Hash("acme", "demo-app", "host", "Z"), Hash("acme", "demo-app", "board", "W"));
var evalCases = new (string Name, string Token, string Product, MachineFingerprint Machine, DateTimeOffset Now, DateTimeOffset? LastSeen)[]
{
    ("valid", v1Token, "demo-app", fp, t0.AddHours(2), t0.AddHours(1)),
    ("product name is case-insensitive", v1Token, "DEMO-APP", fp, t0.AddHours(2), t0.AddHours(1)),
    ("invalid signature", tamperedBody, "demo-app", fp, t0.AddHours(2), t0.AddHours(1)),
    ("wrong product", v1Token, "other-app", fp, t0.AddHours(2), t0.AddHours(1)),
    ("wrong machine", v1Token, "demo-app", otherMachine, t0.AddHours(2), t0.AddHours(1)),
    ("suspended", suspendedToken, "demo-app", fp, t0.AddHours(2), t0.AddHours(1)),
    ("no run history → unverified", v1Token, "demo-app", fp, t0.AddHours(2), null),
    ("clock set back before last run", v1Token, "demo-app", fp, t0.AddHours(2), t0.AddHours(3)),
    ("clock within tolerance (10 min)", v1Token, "demo-app", fp, t0.AddHours(2), t0.AddHours(2).AddMinutes(9)),
    ("issued in the future beyond 1 day", v1Token, "demo-app", fp, t0.AddDays(-2), t0.AddDays(-3)),
    ("expired", expiringToken, "demo-app", fp, t0.AddDays(11), t0.AddDays(10)),
    ("offline too long", v1Token, "demo-app", fp, t0.AddDays(31), t0.AddDays(30)),
    ("test token valid within 24 h", v2Token, "demo-app", fp with { Os = "linux" }, t0.AddHours(23), t0.AddHours(22)),
    ("test token offline after 24 h", v2Token, "demo-app", fp with { Os = "linux" }, t0.AddHours(25), t0.AddHours(24)),
    ("floating lease valid", floatingToken, "demo-app", fp, t0.AddMinutes(20), t0.AddMinutes(19)),
    ("floating lease ended", floatingToken, "demo-app", fp, t0.AddMinutes(31), t0.AddMinutes(30)),
};
Write("evaluate.json", new
{
    description = "evaluate(verify(token, publicKeyPem from tokens.json), product, machine, now, lastSeen) → status. Order: InvalidSignature, WrongProduct, WrongMachine, Suspended, Unverified (lastSeen null), ClockTampered (now + 1 day < issuedAt, or now + 10 min < lastSeen), Expired, OfflineTooLong, Valid.",
    publicKeyPem = publicPem,
    cases = evalCases.Select(c => new
    {
        name = c.Name,
        token = c.Token,
        product = c.Product,
        machine = F(c.Machine.MachineId, c.Machine.DiskId, c.Machine.HostName, c.Machine.BoardId, c.Machine.Os),
        now = c.Now,
        lastSeen = c.LastSeen,
        status = LicenseEvaluator.Evaluate(LicenseToken.Verify(c.Token, key), c.Product, c.Machine, c.Now, c.LastSeen).Status.ToString(),
    }).ToArray(),
});
Console.WriteLine($"Wrote vectors to {outDir}");

void Write(string name, object value) =>
    File.WriteAllText(Path.Combine(outDir, name), JsonSerializer.Serialize(value, indented).ReplaceLineEndings("\n") + "\n");

static string Hash(string vendor, string product, string part, string? raw)
{
    if (string.IsNullOrWhiteSpace(raw)) return MachineFingerprint.Unavailable;
    return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes($"{vendor}:{product}:{part}:{raw.Trim().ToUpperInvariant()}")));
}

static JsonNode Payload(LicensePayload p) => JsonNode.Parse(JsonSerializer.Serialize(p, LicenseToken.JsonOptions))!;

static string B64(byte[] d) => Convert.ToBase64String(d).TrimEnd('=').Replace('+', '-').Replace('/', '_');
static byte[] UnB64(string s) { s = s.Replace('-', '+').Replace('_', '/'); return Convert.FromBase64String(s + new string('=', (4 - s.Length % 4) % 4)); }

static string SignRaw(string json, ECDsa k)
{
    string body = B64(Encoding.UTF8.GetBytes(json));
    return body + "." + B64(k.SignData(Encoding.ASCII.GetBytes(body), HashAlgorithmName.SHA256));
}

static string Insert(string json, string member) => "{" + member + "," + json[1..];

static string TamperBody(string token)
{
    string[] p = token.Split('.');
    string json = Encoding.UTF8.GetString(UnB64(p[0])).Replace("\"Acme Ltd\"", "\"Evil Ltd\"");
    return B64(Encoding.UTF8.GetBytes(json)) + "." + p[1];
}

static string TamperSignature(string token)
{
    string[] p = token.Split('.');
    byte[] sig = UnB64(p[1]);
    sig[10] ^= 0x01;
    return p[0] + "." + B64(sig);
}

static ECDsa LoadOrCreate(string pem)
{
    var k = ECDsa.Create();
    k.ImportFromPem(pem);
    return k;
}

sealed class LicensePayloadBuilder
{
    public required LicensePayload P { get; set; }
}
