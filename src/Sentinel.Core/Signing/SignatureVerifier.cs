using System.Runtime.InteropServices;
using Sentinel.Core.Native;

namespace Sentinel.Core.Signing;

/// <summary>Authenticode signature classification for a file.</summary>
public enum SignatureStatus
{
    /// <summary>Signature present and chain validated to a trusted root.</summary>
    SignedTrusted,

    /// <summary>Signature present but chain not trusted (untrusted root / revoked / bad chain).</summary>
    SignedUntrusted,

    /// <summary>Signature present but cryptographic verification failed (tampered file or broken signature).</summary>
    SignatureInvalid,

    /// <summary>No Authenticode signature embedded.</summary>
    Unsigned,

    /// <summary>Verification could not complete (API failure, policy, etc.).</summary>
    Unknown,
}

/// <summary>Result of signature verification of a file.</summary>
public sealed class SignatureResult
{
    public required SignatureStatus Status { get; init; }

    /// <summary>WinVerifyTrust HRESULT when a verify call was made; null otherwise.</summary>
    public int? WinVerifyTrustError { get; init; }

    /// <summary>Signer display name (subject CN of the signing certificate), when extractable.</summary>
    public string? SignerName { get; init; }

    /// <summary>Issuer display name, when extractable.</summary>
    public string? IssuerName { get; init; }

    /// <summary>Signing time from the timestamp counter-signature, when extractable.</summary>
    public DateTimeOffset? SigningTime { get; init; }

    /// <summary>Signature algorithm OID (e.g., 1.2.840.113549.1.1.11 = RSA-SHA256).</summary>
    public string? HashAlgorithmOid { get; init; }

    /// <summary>Short human-readable explanation.</summary>
    public string Explanation { get; init; } = "";

    public bool IsSigned => Status is SignatureStatus.SignedTrusted or SignatureStatus.SignedUntrusted or SignatureStatus.SignatureInvalid;
}

/// <summary>
/// Authenticode verification via WinVerifyTrust (wintrust.dll), with signer extraction via
/// CryptQueryObject (crypt32.dll). Revocation checks are disabled by default
/// (WTD_REVOKE_NONE) to keep verification offline-deterministic and fast; the chain is
/// still validated against the local root store, so a signature from an untrusted root is
/// reported as <see cref="SignatureStatus.SignedUntrusted"/>.
/// </summary>
public static class SignatureVerifier
{
    private static readonly Guid s_genericVerifyV2 = new(0x00AAC56B, 0xCD44, 0x11D0, 0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE);

    // pkcs7 constants for CryptDecodeObjectEx
    private static readonly IntPtr s_signerInfoOid = Marshal.StringToHGlobalAnsi("1.2.840.113549.1.9.6");
    private static readonly IntPtr s_spcSpOpusInfo = Marshal.StringToHGlobalAnsi("1.3.6.1.4.1.311.2.1.12");
    private static readonly IntPtr s_spcTime = Marshal.StringToHGlobalAnsi("1.3.6.1.4.1.311.1.9.3");

    /// <summary>
    /// Verifies the Authenticode signature of a file.
    /// </summary>
    /// <param name="path">Full path to the file.</param>
    /// <param name="extractSigner">When true (default), also extracts signer name and signing time (extra crypto calls).</param>
    /// <returns>A <see cref="SignatureResult"/> — never throws for policy/signature issues.</returns>
    public static SignatureResult Verify(string path, bool extractSigner = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        try
        {
            if (!File.Exists(path))
            {
                return new SignatureResult { Status = SignatureStatus.Unknown, Explanation = "File does not exist." };
            }

            // 1) WinVerifyTrust — authoritative check.
            var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
                pcwszFilePath = Marshal.StringToHGlobalUni(path),
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero,
            };

            var wtd = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = NativeMethods.WTD_UI_NONE,
                fdwRevocationChecks = NativeMethods.WTD_REVOKE_NONE,
                dwUnionChoice = NativeMethods.WTD_CHOICE_FILE,
                pInfo = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>()),
                dwStateAction = NativeMethods.WTD_STATEACTION_VERIFY,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = 0,
                dwUIContext = 0,
            };
            Marshal.StructureToPtr(fileInfo, wtd.pInfo, false);

            try
            {
                Guid actionId = s_genericVerifyV2;
                int hr = NativeMethods.WinVerifyTrust(IntPtr.Zero, ref actionId, ref wtd);

                // Close state before evaluating.
                var wtdClose = wtd;
                wtdClose.dwStateAction = NativeMethods.WTD_STATEACTION_CLOSE;
                NativeMethods.WinVerifyTrust(IntPtr.Zero, ref actionId, ref wtdClose);

                if (hr == 0) // S_OK
                {
                    return new SignatureResult
                    {
                        Status = SignatureStatus.SignedTrusted,
                        SignerName = extractSigner ? ExtractSignerName(path) : null,
                        SigningTime = extractSigner ? ExtractSigningTime(path) : null,
                        Explanation = "Signature verified and chain validated against local trusted roots.",
                    };
                }

                // TRUST_E_NOSIGNATURE
                if ((uint)hr == 0x800B0100)
                {
                    return new SignatureResult
                    {
                        Status = SignatureStatus.Unsigned,
                        WinVerifyTrustError = hr,
                        Explanation = "No signature was present in the file (TRUST_E_NOSIGNATURE).",
                    };
                }

                // TRUST_E_BAD_DIGEST
                if ((uint)hr == 0x80096010)
                {
                    return new SignatureResult
                    {
                        Status = SignatureStatus.SignatureInvalid,
                        WinVerifyTrustError = hr,
                        Explanation = "Signature digest does not match the file content (TRUST_E_BAD_DIGEST) — file likely tampered.",
                    };
                }

                // TRUST_E_SUBJECT_NOT_TRUSTED
                if ((uint)hr == 0x800B0004)
                {
                    return new SignatureResult
                    {
                        Status = SignatureStatus.SignedUntrusted,
                        WinVerifyTrustError = hr,
                        Explanation = "Signature present but the certificate chain is not trusted (TRUST_E_SUBJECT_NOT_TRUSTED).",
                    };
                }

                // CERT_E_UNTRUSTEDROOT / CERT_E_CHAINING
                if ((uint)hr is 0x800B0109 or 0x80096004)
                {
                    return new SignatureResult
                    {
                        Status = SignatureStatus.SignedUntrusted,
                        WinVerifyTrustError = hr,
                        Explanation = "Signature present but the chain does not reach a trusted root (untrusted/self-signed certificate).",
                    };
                }

                // CERT_E_REVOKED / CERT_E_REVOCATION_FAILURE
                if ((uint)hr is 0x800B010C or 0x80092012)
                {
                    return new SignatureResult
                    {
                        Status = SignatureStatus.SignedUntrusted,
                        WinVerifyTrustError = hr,
                        Explanation = "Signature present but a certificate in the chain is revoked or revocation could not be checked.",
                    };
                }

                return new SignatureResult
                {
                    Status = SignatureStatus.SignedUntrusted,
                    WinVerifyTrustError = hr,
                    Explanation = $"Signature present but verification failed (0x{(uint)hr:X8}).",
                };
            }
            finally
            {
                Marshal.FreeHGlobal(fileInfo.pcwszFilePath);
                Marshal.FreeHGlobal(wtd.pInfo);
            }
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or SEHException or InvalidOperationException)
        {
            return new SignatureResult
            {
                Status = SignatureStatus.Unknown,
                Explanation = $"Signature verification unavailable: {ex.Message}",
            };
        }
    }

    // ---------- Signer extraction (best effort, never throws) ----------

    private static string? ExtractSignerName(string path)
    {
        try
        {
            using var context = new SignerExtraction(path);
            return context.SignerName;
        }
        catch
        {
            return null;
        }
    }

    private static DateTimeOffset? ExtractSigningTime(string path)
    {
        try
        {
            using var context = new SignerExtraction(path);
            return context.SigningTime;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Best-effort signer extraction from the PKCS#7 embedded signature.
    /// Opens the cert store/message via CryptQueryObject and decodes the signer info
    /// (SPC_SP_OPUS_INFO → program name; counter-signature time via SPC_TIME).
    /// </summary>
    private sealed class SignerExtraction : IDisposable
    {
        private IntPtr _certStore;
        private IntPtr _msg;
        private IntPtr _context;

        public string? SignerName { get; }
        public DateTimeOffset? SigningTime { get; }

        public SignerExtraction(string path)
        {
            IntPtr filePtr = Marshal.StringToHGlobalUni(path);
            try
            {
                if (!NativeMethods.CryptQueryObject(
                        NativeMethods.CERT_QUERY_OBJECT_FILE,
                        filePtr,
                        NativeMethods.CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
                        NativeMethods.CERT_QUERY_FORMAT_FLAG_BINARY,
                        0,
                        out _,
                        out _,
                        out _,
                        out _certStore,
                        out _msg,
                        out _context))
                {
                    return;
                }

                // Retrieve the encoded signer info from the message (CMSG_SIGNER_INFO_PARAM),
                // then decode it into CMSG_SIGNER_INFO.
                if (_msg != IntPtr.Zero)
                {
                    uint cb = 0;
                    if (NativeMethods.CryptMsgGetParam(_msg, NativeMethods.CMSG_SIGNER_INFO_PARAM, 0, null, ref cb) && cb > 0)
                    {
                        byte[] encoded = new byte[cb];
                        if (NativeMethods.CryptMsgGetParam(_msg, NativeMethods.CMSG_SIGNER_INFO_PARAM, 0, encoded, ref cb))
                        {
                            uint encoding = NativeMethods.X509_ASN_ENCODING | NativeMethods.PKCS_7_ASN_ENCODING;
                            if (NativeMethods.CryptDecodeObjectEx(
                                    encoding,
                                    s_signerInfoOid,
                                    encoded,
                                    cb,
                                    0,
                                    IntPtr.Zero,
                                    out IntPtr pSignerInfo,
                                    out _) &&
                                pSignerInfo != IntPtr.Zero)
                            {
                                try
                                {
                                    var signer = Marshal.PtrToStructure<NativeMethods.CMSG_SIGNER_INFO>(pSignerInfo);
                                    if (signer.Issuer.pbData != IntPtr.Zero)
                                    {
                                        SignerName = CertNameToString(signer.Issuer);
                                    }
                                }
                                finally
                                {
                                    NativeMethods.LocalFree(pSignerInfo);
                                }
                            }
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(filePtr);
            }
        }

        private static string? CertNameToString(NativeMethods.CRYPT_DATA_BLOB name)
        {
            if (name.pbData == IntPtr.Zero || name.cbData == 0)
            {
                return null;
            }
            var sb = new System.Text.StringBuilder(256);
            uint len = NativeMethods.CertNameToStrW(
                NativeMethods.X509_ASN_ENCODING,
                name.pbData,
                NativeMethods.CERT_NAME_SIMPLE_DISPLAY_TYPE,
                sb,
                (uint)sb.Capacity);
            return len > 1 ? sb.ToString() : null;
        }

        public void Dispose()
        {
            if (_certStore != IntPtr.Zero)
            {
                NativeMethods.CertCloseStore(_certStore, 0);
                _certStore = IntPtr.Zero;
            }
            if (_msg != IntPtr.Zero)
            {
                NativeMethods.CryptMsgClose(_msg);
                _msg = IntPtr.Zero;
            }
            if (_context != IntPtr.Zero)
            {
                NativeMethods.CertFreeCertificateContext(_context);
                _context = IntPtr.Zero;
            }
        }
    }
}
