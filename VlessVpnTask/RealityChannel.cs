using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace VlessVpnTask
{


    // Reality-обёрнутый H1-сокет для xhttp split-режимов. Отдельный от VlessConnection,
    // чтобы не задевать рабочие mux/tcp/stream-one пути. Пишет/читает прикладные (расшифрованные)
    // байты. Конкурентного read+write на одном канале НЕТ (сериализуем на уровне выше).
    internal sealed class RealityChannel
    {
        private readonly VlessConfig _cfg;
        private StreamSocket _socket;
        private DataWriter _writer;
        private DataReader _reader;
        private RealityTls13Stream _reality;
        private Stream _outStream;

        public string NegotiatedAlpn => _reality != null ? _reality.NegotiatedAlpn : "";

        public RealityChannel(VlessConfig cfg) { _cfg = cfg; }

        public async Task<bool> ConnectAsync(int timeoutMs = 8000)
        {
            try
            {
                string targetHost = string.IsNullOrEmpty(VlessVpnPlugin.ServerIp)
                    ? _cfg.Address : VlessVpnPlugin.ServerIp;

                _socket = new StreamSocket();
                _socket.Control.NoDelay = true;
                _socket.Control.KeepAlive = true;

                Windows.Foundation.IAsyncAction connectOp;
                if (VlessVpnPlugin.PhysicalIp != null)
                {
                    var epp = new EndpointPair(VlessVpnPlugin.PhysicalIp, "",
                        new HostName(targetHost), _cfg.Port.ToString());
                    connectOp = _socket.ConnectAsync(epp, SocketProtectionLevel.PlainSocket);
                }
                else
                {
                    connectOp = _socket.ConnectAsync(new HostName(targetHost),
                        _cfg.Port.ToString(), SocketProtectionLevel.PlainSocket);
                }

                var ct = connectOp.AsTask();
                if (await Task.WhenAny(ct, Task.Delay(timeoutMs)) != ct)
                { try { connectOp.Cancel(); } catch { } Close(); return false; }
                await ct;

                _writer = new DataWriter(_socket.OutputStream);
                _reader = new DataReader(_socket.InputStream);
                _reader.InputStreamOptions = InputStreamOptions.Partial;

                // split всегда H1 -> просим ALPN только http/1.1.
                // security=tls — тот же наш TLS 1.3, только ClientHello без аутентификации
                // REALITY и без ожидания подменного сертификата.
                bool plainTls = string.Equals((_cfg.Security ?? "").Trim(), "tls", StringComparison.OrdinalIgnoreCase);
                _reality = new RealityTls13Stream(_cfg) { OfferH1Only = true, PlainTls = plainTls };
                var hs = _reality.EstablishHandshakeAsync(_writer, _reader);
                if (await Task.WhenAny(hs, Task.Delay(timeoutMs)) != hs || !await hs)
                { Close(); return false; }
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[XHTTP SPLIT] RealityChannel connect fail: {ex.Message}");
                Close();
                return false;
            }
        }

        public async Task WriteAppAsync(byte[] data)
        {
            byte[] enc = _reality.EncryptRecord(data);
            if (_outStream == null) _outStream = _socket.OutputStream.AsStreamForWrite(81920);
            _outStream.Write(enc, 0, enc.Length);
            await _outStream.FlushAsync();
        }

        // Возвращает очередной расшифрованный plaintext (тип 23), пропуская CCS и тикеты.
        public async Task<byte[]> ReadPlaintextAsync()
        {
            while (true)
            {
                if (!await ReadExactAsync(5)) return null;
                byte[] header = new byte[5];
                _reader.ReadBytes(header);
                int len = (header[3] << 8) | header[4];
                if (len <= 0) continue;
                if (!await ReadExactAsync((uint)len)) return null;
                byte[] payload = new byte[len];
                _reader.ReadBytes(payload);

                if (header[0] == 20) continue; // ChangeCipherSpec
                byte innerType;
                byte[] plain = _reality.DecryptRecordExplicit(header, payload, out innerType);
                if (plain == null) return null;
                if (innerType == 23) return plain; // application data
                // иначе служебное (NewSessionTicket и т.п.) — пропускаем
            }
        }

        private async Task<bool> ReadExactAsync(uint count)
        {
            try
            {
                uint loaded = _reader.UnconsumedBufferLength;
                while (loaded < count)
                {
                    uint r = await _reader.LoadAsync(count - loaded);
                    if (r == 0) return false;
                    loaded += r;
                }
                return true;
            }
            catch { return false; }
        }

        public void Close()
        {
            try { _writer?.Dispose(); } catch { }
            try { _reader?.Dispose(); } catch { }
            try { _outStream?.Dispose(); } catch { }
            try { _socket?.Dispose(); } catch { }
        }
    }
}
