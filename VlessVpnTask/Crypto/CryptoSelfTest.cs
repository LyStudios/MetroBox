using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Windows.ApplicationModel;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using System.Runtime.InteropServices.WindowsRuntime;

namespace VlessVpnTask
{
    internal static class CryptoSelfTest
    {
        public static void RunAll()
        {
            FileLog.W("--- Running Cryptographic Self-Tests ---");
            try
            {
                byte[] testPriv = HexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
                byte[] testPub = HexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
                byte[] testShared = Curve25519.GetSharedSecret(testPriv, testPub);
                Assert("X25519", "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742", BytesToHex(testShared));

                byte[] shaBorderInput = Encoding.ASCII.GetBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
                byte[] shaBorderHash = Tls13Crypto.Sha256(shaBorderInput);
                Assert("SHA-256", "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1", BytesToHex(shaBorderHash));

                byte[] hmac512Key = Encoding.ASCII.GetBytes("key");
                byte[] hmac512Data = Encoding.ASCII.GetBytes("The quick brown fox jumps over the lazy dog");
                byte[] hmac512Hash = Tls13Crypto.HmacSha512(hmac512Key, hmac512Data);
                Assert("HMAC-SHA-512", "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a", BytesToHex(hmac512Hash));

                FileLog.W("--- End of Cryptographic Self-Tests (SUCCESS) ---");
            }
            catch (Exception ex)
            {
                FileLog.W($"[CRITICAL] Self-Test Exception: {ex.Message}");
            }
        }

        private static void Assert(string name, string expected, string actual)
        {
            if (expected != actual)
            {
                FileLog.W($"[CRITICAL ERROR] Тест {name} ПРОВАЛЕН!");
                FileLog.W($"Ожидали: {expected}");
                FileLog.W($"Получили: {actual}");
            }
            else
            {
                FileLog.W($"[INFO] Тест {name} пройден успешно (SUCCESS).");
            }
        }

        public static byte[] HexToBytes(string hex)
        {
            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < hex.Length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static string BytesToHex(byte[] bytes)
        {
            if (bytes == null) return "";
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }
}
