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
    internal static class Tls13Crypto
    {
        public const int HashLen = 32;

        public static readonly SymmetricKeyAlgorithmProvider AesGcmProvider =
        SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);

        public static CryptographicKey CreateAesGcmKey(byte[] keyBytes)
        {
            return AesGcmProvider.CreateSymmetricKey(ToBuffer(keyBytes));
        }

        public static byte[] AesGcmEncrypt(byte[] key, byte[] nonce, byte[] aad, byte[] plain)
        {
            var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
            var cryptoKey = provider.CreateSymmetricKey(ToBuffer(key));
            var encryptedAndAuthenticated = CryptographicEngine.EncryptAndAuthenticate(cryptoKey, ToBuffer(plain), ToBuffer(nonce), ToBuffer(aad));
            var c = FromBuffer(encryptedAndAuthenticated.EncryptedData);
            var t = FromBuffer(encryptedAndAuthenticated.AuthenticationTag);
            var result = new byte[c.Length + t.Length];
            Array.Copy(c, 0, result, 0, c.Length);
            Array.Copy(t, 0, result, c.Length, t.Length);
            return result;
        }

        public static byte[] AesGcmDecrypt(byte[] key, byte[] nonce, byte[] aad, byte[] cipherAndTag)
        {
            if (cipherAndTag == null || cipherAndTag.Length < 16) throw new ArgumentException("Bad AES-GCM data.");
            var c = new byte[cipherAndTag.Length - 16];
            var tag = new byte[16];
            Array.Copy(cipherAndTag, 0, c, 0, c.Length);
            Array.Copy(cipherAndTag, c.Length, tag, 0, 16);
            var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
            var cryptoKey = provider.CreateSymmetricKey(ToBuffer(key));
            IBuffer plain = CryptographicEngine.DecryptAndAuthenticate(cryptoKey, ToBuffer(c), ToBuffer(nonce), ToBuffer(tag), ToBuffer(aad));
            return FromBuffer(plain);
        }

        public static byte[] AesGcmEncryptWithKey(CryptographicKey cryptoKey, byte[] nonce, byte[] aad, byte[] plain)
        {
            var encryptedAndAuthenticated = CryptographicEngine.EncryptAndAuthenticate(cryptoKey, ToBuffer(plain), ToBuffer(nonce), ToBuffer(aad));
            var c = FromBuffer(encryptedAndAuthenticated.EncryptedData);
            var t = FromBuffer(encryptedAndAuthenticated.AuthenticationTag);
            var result = new byte[c.Length + t.Length];
            Array.Copy(c, 0, result, 0, c.Length);
            Array.Copy(t, 0, result, c.Length, t.Length);
            return result;
        }

        public static byte[] AesGcmDecryptWithKey(CryptographicKey cryptoKey, byte[] nonce, byte[] aad, byte[] cipherAndTag)
        {
            if (cipherAndTag == null || cipherAndTag.Length < 16) throw new ArgumentException("Bad AES-GCM data.");
            var c = new byte[cipherAndTag.Length - 16];
            var tag = new byte[16];
            Array.Copy(cipherAndTag, 0, c, 0, c.Length);
            Array.Copy(cipherAndTag, c.Length, tag, 0, 16);
            IBuffer plain = CryptographicEngine.DecryptAndAuthenticate(cryptoKey, ToBuffer(c), ToBuffer(nonce), ToBuffer(tag), ToBuffer(aad));
            return FromBuffer(plain);
        }

        public static byte[] RandomBytes(int count)
        {
            IBuffer buffer = CryptographicBuffer.GenerateRandom((uint)count);
            return buffer.ToArray();
        }

        public static byte[] Sha256(byte[] data)
        {
            var provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            IBuffer hash = provider.HashData(ToBuffer(data));
            return FromBuffer(hash);
        }

        public static byte[] HmacSha256(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
            var cryptoKey = provider.CreateKey(ToBuffer(key));
            return FromBuffer(CryptographicEngine.Sign(cryptoKey, ToBuffer(data)));
        }

        public static byte[] HmacSha512(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha512);
            var cryptoKey = provider.CreateKey(ToBuffer(key));
            return FromBuffer(CryptographicEngine.Sign(cryptoKey, ToBuffer(data)));
        }

        // ===== хеш-агностичные примитивы =====
        // TLS 1.3 привязывает KDF к хешу выбранного шифра: 0x1301 → SHA-256,
        // 0x1302 (AES-256-GCM-SHA384) → SHA-384. Раньше всё было жёстко на SHA-256,
        // поэтому серверы, выбирающие 0x1302, ломали handshake.

        public static int HashLenOf(bool sha384) { return sha384 ? 48 : 32; }

        public static byte[] Sha384(byte[] data)
        {
            var provider = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha384);
            IBuffer hash = provider.HashData(ToBuffer(data));
            return FromBuffer(hash);
        }

        public static byte[] HmacSha384(byte[] key, byte[] data)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha384);
            var cryptoKey = provider.CreateKey(ToBuffer(key));
            return FromBuffer(CryptographicEngine.Sign(cryptoKey, ToBuffer(data)));
        }

        public static byte[] Hash(bool sha384, byte[] data)
        {
            return sha384 ? Sha384(data) : Sha256(data);
        }

        public static byte[] Hmac(bool sha384, byte[] key, byte[] data)
        {
            return sha384 ? HmacSha384(key, data) : HmacSha256(key, data);
        }

        public static byte[] HkdfExtract(bool sha384, byte[] salt, byte[] ikm)
        {
            if (salt == null) salt = new byte[HashLenOf(sha384)];
            if (ikm == null) ikm = new byte[0];
            return Hmac(sha384, salt, ikm);
        }

        public static byte[] HkdfExpand(bool sha384, byte[] prk, byte[] info, int length)
        {
            var okm = new List<byte>();
            byte[] t = new byte[0];
            byte counter = 1;
            while (okm.Count < length)
            {
                var input = new byte[t.Length + info.Length + 1];
                Array.Copy(t, 0, input, 0, t.Length);
                Array.Copy(info, 0, input, t.Length, info.Length);
                input[input.Length - 1] = counter++;
                t = Hmac(sha384, prk, input);
                okm.AddRange(t);
            }
            var result = new byte[length];
            okm.CopyTo(0, result, 0, length);
            return result;
        }

        public static byte[] HkdfExpandLabel(bool sha384, byte[] secret, string label, byte[] context, int length)
        {
            if (context == null) context = new byte[0];
            string fullLabel = "tls13 " + label;
            var labelBytes = System.Text.Encoding.ASCII.GetBytes(fullLabel);
            var info = new List<byte>();
            info.Add((byte)(length >> 8));
            info.Add((byte)length);
            info.Add((byte)labelBytes.Length);
            info.AddRange(labelBytes);
            info.Add((byte)context.Length);
            info.AddRange(context);
            return HkdfExpand(sha384, secret, info.ToArray(), length);
        }

        public static byte[] DeriveSecret(bool sha384, byte[] secret, string label, byte[] transcript)
        {
            return HkdfExpandLabel(sha384, secret, label,
                Hash(sha384, transcript ?? new byte[0]), HashLenOf(sha384));
        }

        // ===== совместимость: старые вызовы (SHA-256) =====
        public static byte[] HkdfExtract(byte[] salt, byte[] ikm) { return HkdfExtract(false, salt, ikm); }
        public static byte[] HkdfExpand(byte[] prk, byte[] info, int length) { return HkdfExpand(false, prk, info, length); }
        public static byte[] HkdfExpandLabel(byte[] secret, string label, byte[] context, int length)
        { return HkdfExpandLabel(false, secret, label, context, length); }
        public static byte[] DeriveSecret(byte[] secret, string label, byte[] transcript)
        { return DeriveSecret(false, secret, label, transcript); }

        public static IBuffer ToBuffer(byte[] data)
        {
            if (data == null) data = new byte[0];
            return data.AsBuffer();
        }

        public static byte[] FromBuffer(IBuffer buffer)
        {
            return buffer.ToArray();
        }

        public static bool ConstantEquals(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }
    }
}
