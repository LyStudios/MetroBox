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
    internal static class SsCrypto
    {
        // Мастер-ключ Shadowsocks выводится из пароля по схеме OpenSSL EVP_BytesToKey
        // (MD5 без соли, одна итерация) — так делают все клиенты, менять нельзя.
        public static byte[] EvpBytesToKey(string password, int keyLen)
        {
            byte[] pw = Encoding.UTF8.GetBytes(password ?? "");
            var md5 = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Md5);

            byte[] key = new byte[keyLen];
            byte[] prev = new byte[0];
            int filled = 0;
            while (filled < keyLen)
            {
                byte[] input = new byte[prev.Length + pw.Length];
                System.Buffer.BlockCopy(prev, 0, input, 0, prev.Length);
                System.Buffer.BlockCopy(pw, 0, input, prev.Length, pw.Length);

                prev = md5.HashData(CryptographicBuffer.CreateFromByteArray(input)).ToArray();

                int take = Math.Min(prev.Length, keyLen - filled);
                System.Buffer.BlockCopy(prev, 0, key, filled, take);
                filled += take;
            }
            return key;
        }

        public static byte[] HmacSha1(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha1);
            var cryptoKey = provider.CreateKey(CryptographicBuffer.CreateFromByteArray(key));
            return CryptographicEngine.Sign(cryptoKey, CryptographicBuffer.CreateFromByteArray(data)).ToArray();
        }

        // HKDF-SHA1 — им Shadowsocks выводит сессионный подключ из мастер-ключа и соли.
        public static byte[] HkdfSha1(byte[] ikm, byte[] salt, byte[] info, int outLen)
        {
            byte[] prk = HmacSha1(salt, ikm);

            byte[] okm = new byte[outLen];
            byte[] t = new byte[0];
            int pos = 0;
            byte counter = 1;
            while (pos < outLen)
            {
                byte[] input = new byte[t.Length + info.Length + 1];
                System.Buffer.BlockCopy(t, 0, input, 0, t.Length);
                System.Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = counter;

                t = HmacSha1(prk, input);

                int take = Math.Min(t.Length, outLen - pos);
                System.Buffer.BlockCopy(t, 0, okm, pos, take);
                pos += take;
                counter++;
            }
            return okm;
        }
    }

}
