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
    // Одно направление AEAD-потока: подключ + 12-байтовый little-endian счётчик nonce,
    // который увеличивается после КАЖДОЙ операции (отдельно для блока длины и для данных).
    internal sealed class SsAeadBox
    {
        private readonly SsCipherSpec _spec;
        private readonly byte[] _key;
        private readonly byte[] _nonce = new byte[12];
        private readonly CryptographicKey _aesKey;

        public SsAeadBox(SsCipherSpec spec, byte[] subkey)
        {
            _spec = spec;
            _key = subkey;
            if (!spec.IsChaCha)
            {
                var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesGcm);
                _aesKey = provider.CreateSymmetricKey(CryptographicBuffer.CreateFromByteArray(subkey));
            }
        }

        private void IncrementNonce()
        {
            for (int i = 0; i < _nonce.Length; i++)
            {
                if (++_nonce[i] != 0) break;
            }
        }

        public byte[] Seal(byte[] plain, int offset, int length)
        {
            byte[] slice = new byte[length];
            System.Buffer.BlockCopy(plain, offset, slice, 0, length);

            byte[] result;
            if (_spec.IsChaCha)
            {
                result = AwgCrypto.Seal(_key, _nonce, null, slice);
            }
            else
            {
                var enc = CryptographicEngine.EncryptAndAuthenticate(
                    _aesKey,
                    CryptographicBuffer.CreateFromByteArray(slice),
                    CryptographicBuffer.CreateFromByteArray(_nonce),
                    null);
                byte[] c = enc.EncryptedData.ToArray();
                byte[] tag = enc.AuthenticationTag.ToArray();
                result = new byte[c.Length + tag.Length];
                System.Buffer.BlockCopy(c, 0, result, 0, c.Length);
                System.Buffer.BlockCopy(tag, 0, result, c.Length, tag.Length);
            }
            IncrementNonce();
            return result;
        }

        // Возвращает null, если тег не сошёлся (порванная сессия / неверный пароль).
        public byte[] Open(byte[] cipherAndTag)
        {
            if (cipherAndTag == null || cipherAndTag.Length < 16) return null;

            byte[] plain;
            if (_spec.IsChaCha)
            {
                plain = AwgCrypto.Open(_key, _nonce, null, cipherAndTag);
            }
            else
            {
                int ctLen = cipherAndTag.Length - 16;
                byte[] c = new byte[ctLen];
                byte[] tag = new byte[16];
                System.Buffer.BlockCopy(cipherAndTag, 0, c, 0, ctLen);
                System.Buffer.BlockCopy(cipherAndTag, ctLen, tag, 0, 16);
                try
                {
                    plain = CryptographicEngine.DecryptAndAuthenticate(
                        _aesKey,
                        CryptographicBuffer.CreateFromByteArray(c),
                        CryptographicBuffer.CreateFromByteArray(_nonce),
                        CryptographicBuffer.CreateFromByteArray(tag),
                        null).ToArray();
                }
                catch { plain = null; }
            }

            if (plain == null) return null;
            IncrementNonce();
            return plain;
        }
    }

}
