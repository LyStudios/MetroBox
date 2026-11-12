using System;
using System.IO;

namespace VlessVpnTask
{
    // Порт TrafficState + XtlsFilterTls из xray-core (proxy/proxy.go).
    // Состояние общее на соединение: ServerHello приходит в нисходящем потоке,
    // а решение о команде принимается в восходящем, поэтому VisionWrap и
    // VisionUnpad обязаны смотреть в один и тот же объект.
    //
    // Смысл всей этой машинерии один: xtls-rprx-vision «отпускает» поток в raw
    // (команда DIRECT) ТОЛЬКО если сайт согласовал TLS 1.3 с подходящим шифром.
    // На TLS 1.2 обёртка закрывается командой END, а splice не включается —
    // именно этого различия у нас не было, и все TLS 1.2-соединения (в частности
    // возобновлённые сессии speedtest.net) получали DIRECT там, где эталон шлёт END.
    internal sealed class VisionTrafficState
    {
        public bool IsTLS;
        public bool IsTLS12orAbove;
        public bool EnableXtls;
        public ushort Cipher;
        public int RemainingServerHello = -1;
        public int NumberOfPacketToFilter = 8;

        private bool _verdictLogged;

        // supported_versions = TLS 1.3, в том виде, в каком оно лежит в ServerHello.
        private static readonly byte[] Tls13SupportedVersions = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };

        private static bool Contains(byte[] hay, int hayLen, byte[] needle)
        {
            int last = hayLen - needle.Length;
            for (int i = 0; i <= last; i++)
            {
                int j = 0;
                while (j < needle.Length && hay[i + j] == needle[j]) j++;
                if (j == needle.Length) return true;
            }
            return false;
        }

        // Шифры TLS 1.3. xray включает xtls, если шифр найден в этом наборе и не
        // равен TLS_AES_128_CCM_8_SHA256 (0x1305). Если ServerHello оказался короче
        // 79 байт, шифр не разбирается вовсе и остаётся 0 — тогда xtls не включится.
        private static bool CipherAllowsXtls(ushort c)
        {
            return c == 0x1301 || c == 0x1302 || c == 0x1303 || c == 0x1304;
        }

        public void FilterTls(byte[] b, int len)
        {
            NumberOfPacketToFilter--;
            if (len >= 6)
            {
                if (b[0] == 0x16 && b[1] == 0x03 && b[2] == 0x03 && b[5] == 0x02)
                {
                    RemainingServerHello = ((b[3] << 8) | b[4]) + 5;
                    IsTLS12orAbove = true;
                    IsTLS = true;
                    if (len >= 79 && RemainingServerHello >= 79)
                    {
                        int sessionIdLen = b[43];
                        if (43 + sessionIdLen + 3 <= len)
                            Cipher = (ushort)((b[43 + sessionIdLen + 1] << 8) | b[43 + sessionIdLen + 2]);
                    }
                    else
                    {
                        FileLog.Important($"[VISION TLS] Короткий ServerHello: буфер {len}б, " +
                                          $"запись {RemainingServerHello}б — шифр не разбираем (TLS 1.2 или старее).");
                    }
                }
                else if (b[0] == 0x16 && b[1] == 0x03 && b[5] == 0x01)
                {
                    IsTLS = true;
                }
            }

            if (RemainingServerHello > 0)
            {
                int end = RemainingServerHello;
                if (end > len) end = len;
                RemainingServerHello -= len;
                if (Contains(b, end, Tls13SupportedVersions))
                {
                    if (CipherAllowsXtls(Cipher)) EnableXtls = true;
                    Verdict("TLS 1.3");
                    NumberOfPacketToFilter = 0;
                    return;
                }
                if (RemainingServerHello <= 0)
                {
                    Verdict("TLS 1.2");
                    NumberOfPacketToFilter = 0;
                }
            }
        }

        private void Verdict(string version)
        {
            if (_verdictLogged) return;
            _verdictLogged = true;
            FileLog.Important($"[VISION TLS] Сайт согласовал {version}, шифр 0x{Cipher:x4} → " +
                              $"обёртка закроется командой {(EnableXtls ? "DIRECT (xtls включён)" : "END (xtls выключен)")}.");
        }
    }

}
