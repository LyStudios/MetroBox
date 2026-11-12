using System;
using System.Collections.Generic;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    // Уже поднятое VLESS-соединение, поданное наружу как обычный поток.
    internal sealed class ChainOutputStream : IOutputStream
    {
        private readonly IDirectConn _inner;

        public ChainOutputStream(IDirectConn inner) { _inner = inner; }

        public IAsyncOperationWithProgress<uint, uint> WriteAsync(IBuffer buffer)
        {
            return AsyncInfo.Run<uint, uint>(async (token, progress) =>
            {
                byte[] data;
                Windows.Security.Cryptography.CryptographicBuffer.CopyToByteArray(buffer, out data);
                if (data != null && data.Length > 0)
                    await _inner.WriteUnderlyingAsync(data);
                return (uint)(data == null ? 0 : data.Length);
            });
        }

        public IAsyncOperation<bool> FlushAsync()
        {
            // Первое звено пишет в сокет само, отдельного сброса ему не нужно.
            return AsyncInfo.Run(token => Task.FromResult(true));
        }

        public void Dispose() { }
    }
}
