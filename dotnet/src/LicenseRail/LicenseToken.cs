using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace LicenseRail;

/// <summary>
/// License file format: <c>base64url(json) + "." + base64url(ECDSA P-256 signature)</c>.
/// The private key stays on the server only; the client verifies with the public key alone.
/// </summary>
public static class LicenseToken
{
    public static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static string Sign(LicensePayload payload, ECDsa privateKey)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
        string encodedBody = Base64Url.Encode(body);
        byte[] signature = privateKey.SignData(Encoding.ASCII.GetBytes(encodedBody), HashAlgorithmName.SHA256);
        return encodedBody + "." + Base64Url.Encode(signature);
    }

    /// <summary>Verifies the signature and returns the content. Returns null if the signature is invalid or the format is malformed.</summary>
    public static LicensePayload? Verify(string token, ECDsa publicKey)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        string[] parts = token.Trim().Split('.');
        if (parts.Length != 2)
            return null;

        try
        {
            byte[] signature = Base64Url.Decode(parts[1]);
            if (!publicKey.VerifyData(Encoding.ASCII.GetBytes(parts[0]), signature, HashAlgorithmName.SHA256))
                return null;

            return JsonSerializer.Deserialize<LicensePayload>(Base64Url.Decode(parts[0]), JsonOptions);
        }
        catch (Exception ex) when (ex is FormatException or JsonException or CryptographicException)
        {
            return null;
        }
    }

    public static ECDsa ImportKey(string pem)
    {
        ECDsa key = ECDsa.Create();
        key.ImportFromPem(pem);
        return key;
    }
}
