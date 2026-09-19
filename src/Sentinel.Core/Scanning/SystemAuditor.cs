using System.Runtime.InteropServices;
using System.Security.Principal;
using Sentinel.Core.Models;
using Sentinel.Core.Native;

namespace Sentinel.Core.Scanning;

/// <summary>
/// Read-only system security audit: OS version/build, patch recency, Windows
/// Defender state, firewall status (read-only), UAC configuration, local
/// administrators, RDP/SMB exposure and listening public ports.
/// </summary>
public sealed class SystemAuditor
{
    private readonly bool _useWmi;

    public SystemAuditor(bool useWmi = true)
    {
        _useWmi = useWmi;
    }

    public SystemAuditResult Audit()
    {
        var findings = new List<string>(16);
        var result = new SystemAuditResult
        {
            AuditedAtUtc = DateTime.UtcNow,
        };
        string? error = null;

        try
        {
            result = CollectOsInfo(result, findings);
            result = CollectUpdates(result, findings);
            result = CollectDefender(result, findings);
            result = CollectFirewall(result, findings);
            result = CollectUac(result, findings);
            result = CollectAccounts(result, findings);
            result = CollectExposure(result, findings);
            result = CollectMisc(result);
        }
        catch (Exception ex)
        {
            error = ex.Message;
        }

        return result with
        {
            Findings = findings,
            Error = error,
        };
    }

    // ---------------- OS ----------------

    private SystemAuditResult CollectOsInfo(SystemAuditResult r, List<string> findings)
    {
        try
        {
            var os = Environment.OSVersion;
            r = r with { OsVersion = os.VersionString };

            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key is not null)
            {
                r = r with
                {
                    OsBuild = key.GetValue("CurrentBuildNumber")?.ToString(),
                    OsEdition = key.GetValue("ProductName")?.ToString(),
                    IsServer = (key.GetValue("InstallationType")?.ToString() ?? "").Contains("Server", StringComparison.OrdinalIgnoreCase),
                    InstallDateUtc = key.GetValue("InstallDate") is long install ? DateTimeOffset.FromUnixTimeSeconds(install).UtcDateTime : null,
                };
            }
        }
        catch
        {
            // best-effort
        }

        try
        {
            r = r with { LastBootUtc = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64) };
        }
        catch
        {
            // ignore
        }

        if (r.DaysSinceLastUpdate is null && r.LastUpdateInstalledUtc is not null)
        {
            r = r with { DaysSinceLastUpdate = (int)(DateTime.UtcNow - r.LastUpdateInstalledUtc.Value).TotalDays };
        }
        _ = findings;
        return r;
    }

    // ---------------- Windows Update posture ----------------

    private SystemAuditResult CollectUpdates(SystemAuditResult r, List<string> findings)
    {
        // Primary: Windows Update COM API (Microsoft.Update.Session) - works on
        // consumer and server SKUs without the WU WMI namespace.
        try
        {
            var sessionType = Type.GetTypeFromProgID("Microsoft.Update.Session");
            if (sessionType is not null)
            {
                dynamic session = Activator.CreateInstance(sessionType)!;
                try
                {
                    dynamic searcher = session.CreateUpdateSearcher();
                    int total = (int)searcher.GetTotalHistoryCount();
                    if (total > 0)
                    {
                        dynamic history = searcher.QueryHistory(0, Math.Min(total, 10));
                        DateTime? lastInstall = null;
                        foreach (var item in history)
                        {
                            DateTime date = (DateTime)item.Date;
                            if (lastInstall is null || date > lastInstall)
                            {
                                lastInstall = date;
                            }
                        }
                        if (lastInstall is not null)
                        {
                            r = r with
                            {
                                LastUpdateInstalledUtc = lastInstall,
                                DaysSinceLastUpdate = (int)(DateTime.UtcNow - lastInstall.Value).TotalDays,
                            };
                        }
                    }
                }
                finally
                {
                    Marshal.FinalReleaseComObject(session);
                }
            }
        }
        catch
        {
            // WU API unavailable (rare) - fall back to registry below
        }

        if (r.LastUpdateInstalledUtc is null)
        {
            try
            {
                // Fallback: the "LastSuccessTime" from the Update Manager (registry-based).
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
                if (key?.GetValue("LastSuccessTime") is string last)
                {
                    if (DateTime.TryParse(last, out var dt))
                    {
                        r = r with
                        {
                            LastUpdateInstalledUtc = dt,
                            DaysSinceLastUpdate = (int)(DateTime.UtcNow - dt).TotalDays,
                        };
                    }
                }
            }
            catch
            {
                // ignore
            }
        }

        if (r.DaysSinceLastUpdate is int days && days > 30)
        {
            findings.Add($"No Windows updates installed in the last {days} days.");
        }
        return r;
    }

    // ---------------- Defender ----------------

    private SystemAuditResult CollectDefender(SystemAuditResult r, List<string> findings)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "root\\Microsoft\\Windows\\Defender", "SELECT * FROM MSFT_MpComputerStatus");
            using var results = searcher.Get();
            foreach (System.Management.ManagementObject o in results)
            {
                bool rt = Convert.ToBoolean(SafeGet(o, "RealTimeProtectionEnabled") ?? false);
                bool bm = Convert.ToBoolean(SafeGet(o, "BehaviorMonitorEnabled") ?? false);
                bool oa = Convert.ToBoolean(SafeGet(o, "OnAccessProtectionEnabled") ?? false);
                bool nis = Convert.ToBoolean(SafeGet(o, "NISEnabled") ?? false);
                bool ioav = Convert.ToBoolean(SafeGet(o, "IoavProtectionEnabled") ?? false);
                string status = $"real-time={(rt ? "on" : "off")}, behavior={(bm ? "on" : "off")}, on-access={(oa ? "on" : "off")}, nis={(nis ? "on" : "off")}, ioav={(ioav ? "on" : "off")}";
                r = r with
                {
                    DefenderEnabled = Convert.ToBoolean(SafeGet(o, "AntivirusEnabled") ?? false),
                    DefenderStatus = status,
                    DefenderSignatureVersion = SafeGet(o, "AntivirusSignatureVersion")?.ToString(),
                };
                // Direct signature age when available (uint seconds? actually days on
                // MSFT_MpComputerStatus); otherwise parse the CIM datetime.
                object? sigAge = SafeGet(o, "AntivirusSignatureAge");
                if (sigAge is not null)
                {
                    try
                    {
                        var age = Convert.ToInt32(sigAge);
                        r = r with { DefenderSignatureAge = DateTime.Now.AddDays(-age) };
                        if (age > 7)
                        {
                            findings.Add($"Windows Defender signatures are {age} days old.");
                        }
                    }
                    catch
                    {
                        // ignore
                    }
                }
                else
                {
                    string? sigRaw = SafeGet(o, "AntivirusSignatureLastUpdated")?.ToString();
                    if (sigRaw is not null)
                    {
                        try
                        {
                            // CIM_DATETIME string, e.g. "20260807203008.000000+000"
                            var sig = System.Management.ManagementDateTimeConverter.ToDateTime(sigRaw);
                            r = r with { DefenderSignatureAge = sig };
                            int age = (int)(DateTime.Now - sig).TotalDays;
                            if (age > 7)
                            {
                                findings.Add($"Windows Defender signatures are {age} days old.");
                            }
                        }
                        catch
                        {
                            // unparseable signature date - ignore
                        }
                    }
                }
                if (r.DefenderEnabled == false)
                {
                    findings.Add("Windows Defender real-time protection is DISABLED.");
                }
                break;
            }
        }
        catch
        {
            // Defender may be absent (Server Core) or WMI restricted
        }
        return r;
    }

    private static object? SafeGet(System.Management.ManagementBaseObject o, string property)
    {
        try
        {
            return o[property];
        }
        catch
        {
            // property may not exist on this SKU/build
            return null;
        }
    }

    // ---------------- Firewall (read-only) ----------------

    private SystemAuditResult CollectFirewall(SystemAuditResult r, List<string> findings)
    {
        try
        {
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
            if (policyType is null)
            {
                return r;
            }
            dynamic policy = Activator.CreateInstance(policyType)!;
            try
            {
                bool domain = (bool)policy.FirewallEnabled(1); // NET_FW_PROFILE2_DOMAIN
                bool priv = (bool)policy.FirewallEnabled(2);   // NET_FW_PROFILE2_PRIVATE
                bool pub = (bool)policy.FirewallEnabled(4);    // NET_FW_PROFILE2_PUBLIC
                r = r with
                {
                    FirewallEnabled = domain && priv && pub,
                    FirewallPublicEnabled = pub,
                    FirewallPrivateEnabled = priv,
                    FirewallDomainEnabled = domain,
                };
                try
                {
                    r = r with { FirewallRuleCount = policy.Rules.Count };
                }
                catch
                {
                    // rules enumeration may fail without admin
                }
                if (r.FirewallEnabled == false)
                {
                    findings.Add("Windows Firewall is DISABLED.");
                }
            }
            finally
            {
                Marshal.FinalReleaseComObject(policy);
            }
        }
        catch
        {
            // COM unavailable (rare) - firewall state unknown
        }
        return r;
    }

    // ---------------- UAC ----------------

    private SystemAuditResult CollectUac(SystemAuditResult r, List<string> findings)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System");
            if (key is null)
            {
                return r;
            }
            int? consent = key.GetValue("ConsentPromptBehaviorAdmin") as int?;
            int? enableLua = key.GetValue("EnableLUA") as int?;
            r = r with
            {
                UacLevel = consent,
                UacEnabled = enableLua == 1,
            };
            if (enableLua != 1)
            {
                findings.Add("UAC (LUA) is DISABLED - all processes run with full privileges.");
            }
            else if (consent is 0)
            {
                findings.Add("UAC is set to 'never notify' - elevation is silent.");
            }
        }
        catch
        {
            // ignore
        }
        return r;
    }

    // ---------------- Accounts ----------------

    private SystemAuditResult CollectAccounts(SystemAuditResult r, List<string> findings)
    {
        var admins = new List<string>();
        try
        {
            using var nta = new System.DirectoryServices.AccountManagement.PrincipalContext(
                System.DirectoryServices.AccountManagement.ContextType.Machine);
            var group = System.DirectoryServices.AccountManagement.GroupPrincipal.FindByIdentity(
                nta, "Administrators");
            if (group is not null)
            {
                foreach (var member in group.GetMembers(true))
                {
                    admins.Add(member.SamAccountName ?? member.Name ?? member.ToString() ?? "?");
                }
            }
        }
        catch
        {
            // principal enumeration may fail on non-domain or restricted systems
        }
        r = r with
        {
            LocalAdminCount = admins.Count,
            LocalAdmins = admins,
        };
        if (admins.Count == 0)
        {
            findings.Add("Could not enumerate local administrators (access denied).");
        }

        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT Name, Disabled FROM Win32_UserAccount WHERE LocalAccount=True");
            using var users = searcher.Get();
            foreach (System.Management.ManagementObject u in users)
            {
                string? name = u["Name"]?.ToString();
                if (string.Equals(name, "Guest", StringComparison.OrdinalIgnoreCase))
                {
                    bool disabled = Convert.ToBoolean(u["Disabled"] ?? true);
                    r = r with { GuestEnabled = !disabled };
                    if (!disabled)
                    {
                        findings.Add("The Guest account is ENABLED.");
                    }
                }
            }
        }
        catch
        {
            // ignore
        }
        return r;
    }

    // ---------------- Exposure ----------------

    private SystemAuditResult CollectExposure(SystemAuditResult r, List<string> findings)
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            r = r with { RdpEnabled = (key?.GetValue("fDenyTSConnections") as int?) == 0 };
        }
        catch
        {
            // ignore
        }
        if (r.RdpEnabled)
        {
            findings.Add("Remote Desktop is enabled.");
        }

        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters");
            if (key is not null)
            {
                int? autoShare = key.GetValue("AutoShareWks") as int?;
                r = r with { SmbEnabled = true };
                _ = autoShare;
            }
        }
        catch
        {
            // ignore
        }

        // Public listening ports (from the network snapshot).
        try
        {
            var net = new NetworkScanner();
            var snap = net.Capture();
            var publicPorts = snap.Connections
                .Where(c => c.IsListening && !c.IsLoopback && c.LocalAddress.Equals(System.Net.IPAddress.Any) == false && c.LocalAddress.Equals(System.Net.IPAddress.IPv6Any) == false)
                .Select(c => c.LocalPort)
                .Distinct()
                .OrderBy(p => p)
                .ToList();
            r = r with { PublicListeningPorts = publicPorts };
            if (publicPorts.Count > 0)
            {
                findings.Add($"Listening on public interfaces: {string.Join(", ", publicPorts)}.");
            }
        }
        catch
        {
            // ignore
        }
        return r;
    }

    // ---------------- Misc ----------------

    private SystemAuditResult CollectMisc(SystemAuditResult r)
    {
        try
        {
            r = r with { IsAdministrator = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator) };
        }
        catch
        {
            // ignore
        }

        try
        {
            r = r with { SecureBootEnabled = Convert.ToBoolean(Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\SecureBoot\State")?.GetValue("UEFISecureBootEnabled") ?? false) };
        }
        catch
        {
            // ignore
        }

        try
        {
            r = r with { TpmPresent = File.Exists(@"C:\Windows\System32\tpmvsc.dll") };
        }
        catch
        {
            // ignore
        }
        return r;
    }
}