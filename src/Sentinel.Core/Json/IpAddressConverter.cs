using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Sentinel.Core.Json;

/// <summary>
/// Serializes <see cref="IPAddress"/> as its string form. The default reflection-based
/// serializer enumerates public properties, and reading <c>ScopeId</c> throws
/// <see cref="SocketException"/> for IPv4 addresses — which broke evidence/IPC
/// serialization for network scans.
/// </summary>
public sealed class IpAddressConverter : JsonConverter<IPAddress>
{
    public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        string? text = reader.GetString();
        return text is not null && IPAddress.TryParse(text, out var addr) ? addr : null;
    }

    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(value.ToString());
    }
}