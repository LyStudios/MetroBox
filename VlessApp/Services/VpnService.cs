using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.Networking;
using Windows.Networking.Connectivity;
using Windows.Networking.Vpn;
using Windows.Storage;

namespace VlessApp.Services
{
    /// <summary>
    /// Сервис управления профилем и проверки состояния системного VPN-туннеля.
    /// </summary>
    public sealed class VpnService
    {
        public const string ProfileName = "VLESS Client";
        private IVpnProfile _cachedProfile;

        public void InvalidateProfileCache()
        {
            _cachedProfile = null;
        }

        public async Task<IVpnProfile> FindOwnProfileAsync()
        {
            if (_cachedProfile != null) return _cachedProfile;

            string fam = Package.Current.Id.FamilyName;
            try
            {
                var agent = new VpnManagementAgent();
                var profiles = await agent.GetProfilesAsync();

                var matches = new List<VpnPlugInProfile>();
                foreach (var pr in profiles)
                {
                    if (pr is VpnPlugInProfile plug)
                    {
                        // СИСТЕМНЫЙ ФИКС: Если PFN пустой (баг ручного создания профиля в Windows 10 Mobile)
                        // или совпадает с нашим текущим PFN — это наш рабочий профиль.
                        if (string.IsNullOrEmpty(plug.VpnPluginPackageFamilyName) ||
                            string.Equals(plug.VpnPluginPackageFamilyName, fam, StringComparison.OrdinalIgnoreCase))
                        {
                            matches.Add(plug);
                        }
                    }
                }

                if (matches.Count > 1)
                {
                    AppLog.W($"[VPN SERVICE] Найдено профилей: {matches.Count}, удаляю лишние дубликаты...");
                    // Оставляем первый профиль, а лишние дубликаты пытаемся удалить из системы
                    for (int i = matches.Count - 1; i >= 1; i--)
                    {
                        try
                        {
                            var delSt = await agent.DeleteProfileAsync(matches[i]);
                            AppLog.W($"  удаление дубликата '{matches[i].ProfileName}': {delSt}");
                            if (delSt == VpnManagementErrorStatus.Ok)
                            {
                                matches.RemoveAt(i);
                            }
                        }
                        catch (Exception ex)
                        {
                            AppLog.W($"  не удалось удалить дубликат '{matches[i].ProfileName}': {ex.Message}");
                        }
                    }

                    // Если первый удалить не пытались, но второй остался (например, первый был системным, а второй созданным через API),
                    // проверим возможность удалить первый, если их всё ещё больше одного.
                    if (matches.Count > 1)
                    {
                        try
                        {
                            var delSt0 = await agent.DeleteProfileAsync(matches[0]);
                            AppLog.W($"  удаление дубликата[0] '{matches[0].ProfileName}': {delSt0}");
                            if (delSt0 == VpnManagementErrorStatus.Ok)
                            {
                                matches.RemoveAt(0);
                            }
                        }
                        catch { }
                    }
                }

                if (matches.Count > 0)
                {
                    _cachedProfile = matches[0];
                    return matches[0];
                }
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[PROFILE] GetProfilesAsync failed: {ex.Message}");
            }
            return null;
        }

        public async Task<int> CountMatchingProfilesAsync()
        {
            string fam = Package.Current.Id.FamilyName;
            int count = 0;
            try
            {
                var agent = new VpnManagementAgent();
                var profiles = await agent.GetProfilesAsync();
                foreach (var pr in profiles)
                {
                    if (pr is VpnPlugInProfile plug)
                    {
                        if (string.IsNullOrEmpty(plug.VpnPluginPackageFamilyName) ||
                            string.Equals(plug.VpnPluginPackageFamilyName, fam, StringComparison.OrdinalIgnoreCase))
                        {
                            count++;
                        }
                    }
                }
            }
            catch { }
            return count;
        }

        public void WriteSettings(VlessProfile p)
        {
            var s = ApplicationData.Current.LocalSettings.Values;
            // Имя нужно фоновой задаче только для живой плитки — на подключение не влияет.
            s["v_Name"] = p.Name ?? "";
            s["v_Address"] = p.Address ?? "";
            s["v_Port"] = p.Port;
            s["v_Uuid"] = p.Uuid ?? "";
            s["v_Type"] = p.Type ?? "tcp";
            s["v_Security"] = p.Security ?? "reality";
            s["v_Sni"] = p.Sni ?? "";
            s["v_PublicKey"] = p.PublicKey ?? "";
            s["v_ShortId"] = p.ShortId ?? "";
            s["v_Path"] = p.Path ?? "";
            s["v_Host"] = p.Host ?? "";
            s["v_Flow"] = p.Flow ?? "";
            s["v_Alpn"] = p.Alpn ?? "";
            s["v_XhttpMode"] = string.IsNullOrEmpty(p.Mode) ? "auto" : p.Mode;
            s["v_Extra"] = p.Extra ?? "";
            s["v_Fp"] = p.Fp ?? "";

            // Второе звено цепочки Amnezia: реле доводит только до этого узла,
            // а он проверяет уже свои ключи REALITY — поэтому нужны все параметры,
            // а не только адрес.
            s["v_ChainExitHost"] = p.AmneziaExitHost ?? "";
            s["v_ChainExitPort"] = p.AmneziaExitPort;
            s["v_ChainExitUuid"] = p.AmneziaExitUuid ?? "";
            s["v_ChainExitPublicKey"] = p.AmneziaExitPublicKey ?? "";
            s["v_ChainExitSni"] = p.AmneziaExitSni ?? "";
            s["v_ChainExitShortId"] = p.AmneziaExitShortId ?? "";
            s["v_ChainExitFlow"] = p.AmneziaExitFlow ?? "";
            s["v_AwgConfig"] = p.IsAmneziaWg ? (p.AwgConfig ?? "") : "";

            // Shadowsocks/Outline: без этих трёх ключей фоновая задача не знает ни шифра,
            // ни пароля — профиль импортировался бы, но соединение не поднималось.
            s["v_SsMethod"] = p.IsShadowsocks ? (p.Method ?? "") : "";
            s["v_SsPassword"] = p.IsShadowsocks ? (p.Password ?? "") : "";
            s["v_SsPrefix"] = p.IsShadowsocks ? (p.SsPrefix ?? "") : "";

            // Адрес TUN-интерфейса, по которому интерфейс понимает, что туннель поднят.
            s["v_TunIp"] = p.IsAmneziaWg ? (AwgAddressOf(p.AwgConfig) ?? "") : "11.16.1.1";
            s["v_DebugLog"] = false;
        }

        // Первый IPv4 из строки Address в [Interface] — им поднимается TUN у AmneziaWG.
        private static string AwgAddressOf(string conf)
        {
            if (string.IsNullOrEmpty(conf)) return null;
            foreach (var rawLine in conf.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n'))
            {
                string line = rawLine.Trim();
                if (!line.StartsWith("Address", StringComparison.OrdinalIgnoreCase)) continue;
                int eq = line.IndexOf('=');
                if (eq <= 0) continue;
                foreach (var part in line.Substring(eq + 1).Split(','))
                {
                    string ip = part.Split('/')[0].Trim();
                    if (ip.Length > 0 && ip.IndexOf(':') < 0) return ip;
                }
            }
            return null;
        }

        public static bool IsVpnProfileConnectedByIana()
        {
            try
            {
                var connections = NetworkInformation.GetConnectionProfiles();
                foreach (var conn in connections)
                {
                    if (conn?.NetworkAdapter != null)
                    {
                        uint type = conn.NetworkAdapter.IanaInterfaceType;
                        if (type == 131 || type == 150)
                        {
                            var level = conn.GetNetworkConnectivityLevel();
                            if (level == NetworkConnectivityLevel.InternetAccess ||
                                level == NetworkConnectivityLevel.ConstrainedInternetAccess)
                            {
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        public static bool IsVpnInterfaceActive()
        {
            try
            {
                // У VLESS адрес туннеля всегда 11.16.1.1, а у AmneziaWG — свой из конфига
                // (например 10.8.1.47), поэтому держим актуальный адрес в v_TunIp.
                string tunIp = ApplicationData.Current.LocalSettings.Values["v_TunIp"] as string;
                if (string.IsNullOrEmpty(tunIp)) tunIp = "11.16.1.1";

                var hostNames = NetworkInformation.GetHostNames();
                foreach (var hn in hostNames)
                {
                    if (hn.Type == HostNameType.Ipv4)
                    {
                        if (hn.RawName == tunIp || hn.RawName == "11.16.1.1")
                        {
                            return true;
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        public static VpnManagementConnectionStatus ReadVpnState(VpnPlugInProfile plug)
        {
            bool traceOfTunnel;
            try { traceOfTunnel = IsVpnInterfaceActive() || IsVpnProfileConnectedByIana(); }
            catch { traceOfTunnel = false; }

            if (!traceOfTunnel) return VpnManagementConnectionStatus.Disconnected;

            try
            {
                if (plug != null) return plug.ConnectionStatus;
            }
            catch { }

            bool pluginSaysUp = false;
            try
            {
                pluginSaysUp = (ApplicationData.Current.LocalSettings.Values["v_TunnelUp"] as bool?) ?? false;
            }
            catch { }

            return pluginSaysUp
                ? VpnManagementConnectionStatus.Connected
                : VpnManagementConnectionStatus.Disconnected;
        }

        public async Task<VpnManagementConnectionStatus> CheckStatusAsync()
        {
            var mine = await FindOwnProfileAsync();
            if (mine is VpnPlugInProfile plug)
            {
                var ask = Task.Run(() => ReadVpnState(plug));
                if (await Task.WhenAny(ask, Task.Delay(3000)) != ask)
                    return VpnManagementConnectionStatus.Disconnected;

                return ask.Result;
            }
            return VpnManagementConnectionStatus.Disconnected;
        }

        public async Task<bool> ForceDisconnectActiveProfilesAsync()
        {
            try
            {
                var agent = new VpnManagementAgent();
                var profiles = await agent.GetProfilesAsync();
                if (profiles.Count == 0)
                {
                    Debug.WriteLine("[VPN SERVICE] Профилей нет — отключать нечего.");
                    return false;
                }

                bool any = false;
                foreach (var p in profiles)
                {
                    try
                    {
                        var status = await agent.DisconnectProfileAsync(p);
                        AppLog.W($"  отключение профиля '{p.ProfileName}': {status}");
                        any = true;
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"[VPN SERVICE] Ошибка отключения {p.ProfileName}: {ex.Message}");
                    }
                }
                return any;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"[VPN SERVICE ERROR] {ex.Message}");
                return false;
            }
        }

        public async Task<VpnManagementErrorStatus> ConnectProfileAsync(IVpnProfile profile)
        {
            if (profile == null) return VpnManagementErrorStatus.Other;
            try
            {
                var agent = new VpnManagementAgent();
                return await agent.ConnectProfileAsync(profile);
            }
            catch (Exception ex)
            {
                AppLog.W($"  Ошибка запуска профиля: {ex.Message}");
                return VpnManagementErrorStatus.Other;
            }
        }

        public async Task<VpnManagementErrorStatus> DisconnectProfileAsync(IVpnProfile profile)
        {
            if (profile == null) return VpnManagementErrorStatus.Ok;
            try
            {
                var agent = new VpnManagementAgent();
                return await agent.DisconnectProfileAsync(profile);
            }
            catch (Exception ex)
            {
                AppLog.W($"  Ошибка отключения профиля: {ex.Message}");
                return VpnManagementErrorStatus.Other;
            }
        }
    }
}
