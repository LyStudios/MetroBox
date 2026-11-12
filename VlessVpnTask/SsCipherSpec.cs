using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using System.Runtime.InteropServices.WindowsRuntime;

namespace VlessVpnTask
{
    // Параметры AEAD-шифра Shadowsocks (SIP004/SIP007).
    internal sealed class SsCipherSpec
    {
        public string Name;
        public int KeyLen;
        public int SaltLen;   // для классического AEAD длина соли == длине ключа
        public bool IsChaCha;

        // Возвращает null для неподдерживаемого шифра (в т.ч. для устаревших
        // потоковых rc4/aes-cfb и для Shadowsocks-2022, где нужен BLAKE3).
        public static SsCipherSpec Resolve(string method)
        {
            string m = (method ?? "").Trim().ToLowerInvariant();
            switch (m)
            {
                case "chacha20-ietf-poly1305":
                case "chacha20-poly1305":
                    return new SsCipherSpec { Name = m, KeyLen = 32, SaltLen = 32, IsChaCha = true };
                case "aes-256-gcm":
                    return new SsCipherSpec { Name = m, KeyLen = 32, SaltLen = 32, IsChaCha = false };
                case "aes-192-gcm":
                    return new SsCipherSpec { Name = m, KeyLen = 24, SaltLen = 24, IsChaCha = false };
                case "aes-128-gcm":
                    return new SsCipherSpec { Name = m, KeyLen = 16, SaltLen = 16, IsChaCha = false };
                default:
                    return null;
            }
        }

        public static bool IsSupported(string method) { return Resolve(method) != null; }
    }

}
