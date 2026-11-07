using System;
using System.Threading;
using System.Threading.Tasks;
using VlessVpnTask;

namespace VlessApp.Services
{
    /// <summary>
    /// Проверка реальной доступности узлов (REALITY/TLS хендшейк, WireGuard/AmneziaWG Noise-проба, TCP-пинг).
    /// </summary>
    public static class PingService
    {
        public static async Task PingAsync(VlessProfile profile, CancellationToken ct = default)
        {
            if (profile == null) return;

            if (profile.AmneziaNotIssued)
            {
                profile.CleanPingText = "Не выдан";
                return;
            }

            profile.CleanPingText = "Проверка...";

            try
            {
                int rtt = -1;

                if (profile.IsAmneziaWg)
                {
                    if (!string.IsNullOrEmpty(profile.AwgConfig))
                    {
                        rtt = await NodeProbe.ProbeAwgAsync(profile.AwgConfig, 3000).AsTask(ct);
                    }
                    else if (!string.IsNullOrEmpty(profile.Address) && profile.Port > 0)
                    {
                        rtt = await NodeProbe.ProbeTcpAsync(profile.Address, profile.Port, 3000).AsTask(ct);
                    }
                }
                else if (!string.IsNullOrEmpty(profile.Address) && profile.Port > 0)
                {
                    rtt = await NodeProbe.ProbeVlessAsync(
                        profile.Address,
                        profile.Port,
                        profile.Type,
                        profile.Security,
                        profile.Sni,
                        profile.PublicKey,
                        profile.ShortId,
                        profile.Path,
                        profile.Host,
                        3000
                    ).AsTask(ct);
                }
                else
                {
                    profile.CleanPingText = "Нет адреса";
                    return;
                }

                    if (rtt >= 0)
                    {
                        profile.CleanPingText = $"{rtt} мс";
                    }
                    else
                    {
                        profile.CleanPingText = "Таймаут (🔴)";
                    }
            }
            catch (OperationCanceledException)
            {
                // Отменено пользователем
            }
            catch (Exception)
            {
                profile.CleanPingText = "Ошибка (🔴)";
            }
        }
    }
}
