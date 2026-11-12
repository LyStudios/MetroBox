using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    // ================= ВАРИАНТ B: мультиплексирование xhttp stream-one =================
    internal sealed class H2Stream
    {
        public readonly int Id;
        private readonly H2MuxTransport _t;
        private readonly object _lock = new object();
        private readonly Queue<byte[]> _down = new Queue<byte[]>();
        private TaskCompletionSource<bool> _sig;
        private bool _closed;

        public int Status = -1;
        public bool HeadersDone;

        // окно ОТПРАВКИ этого стрима (сколько МЫ можем послать серверу); server
        // INITIAL_WINDOW_SIZE по умолчанию 65535. Меняется под H2MuxTransport._winLock.
        internal int SendWindow;
        internal readonly string SessionId;
        internal readonly XhttpTransportMode Mode;
        internal H2Stream UploadStream;
        private readonly SemaphoreSlim _upLock = new SemaphoreSlim(1, 1);
        private long _upSeq;
        private readonly GrpcFramer _grpcFramer;
        private int _uncreditedBytes;

        internal H2Stream(H2MuxTransport t, int id, int initSendWindow, string sessionId = null, XhttpTransportMode mode = XhttpTransportMode.StreamOne)
        {
            _t = t; Id = id; SendWindow = initSendWindow; SessionId = sessionId; Mode = mode;
            if (_t.Config != null && _t.Config.IsGrpc) _grpcFramer = new GrpcFramer();
        }

        internal void EnqueueDown(byte[] d)
        {
            lock (_lock)
            {
                if (_grpcFramer != null)
                {
                    _grpcFramer.PushData(d);
                    while (true)
                    {
                        byte[] p = _grpcFramer.TryExtractPayload();
                        if (p == null) break;
                        if (p.Length > 0) _down.Enqueue(p);
                    }
                }
                else
                {
                    _down.Enqueue(d);
                }
                SignalLocked();
            }
        }
        internal void MarkClosed() { lock (_lock) { _closed = true; SignalLocked(); } }
        internal void SignalHeaders() { lock (_lock) { SignalLocked(); } }
        private void SignalLocked() { if (_sig != null && !_sig.Task.IsCompleted) _sig.TrySetResult(true); }

        public bool Closed { get { lock (_lock) { return _closed && _down.Count == 0; } } }

        // Читает следующий блок downstream. null = стрим завершён/сброшен/не-200.
        public async Task<byte[]> ReadDownAsync()
        {
            while (true)
            {
                byte[] chunk = null;
                Task wait = null;
                lock (_lock)
                {
                    if (_down.Count > 0) chunk = _down.Dequeue();
                    else if (_closed) return null;
                    else if (HeadersDone && Status > 0 && Status != 200) return null;
                    else
                    {
                        if (_sig == null || _sig.Task.IsCompleted)
                            _sig = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
                        wait = _sig.Task;
                    }
                }
                if (chunk != null)
                {
                    // Окно СТРИМА кредитуем батчами по 512 КБ (половина StreamRecvWindow = 1 МБ),
                    // чтобы не блокировать чтение синхронной шифрацией и отправкой 13-байтного TLS-кадра
                    // на каждый чанк.
                    int toCredit = 0;
                    lock (_lock)
                    {
                        _uncreditedBytes += chunk.Length;
                        if (_uncreditedBytes >= 512 * 1024)
                        {
                            toCredit = _uncreditedBytes;
                            _uncreditedBytes = 0;
                        }
                    }
                    if (toCredit > 0)
                    {
                        var _ignore = _t.CreditStreamAsync(Id, toCredit);
                    }
                    return chunk;
                }
                await wait;
            }
        }

        public async Task WriteAsync(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            if (_t.Config != null && _t.Config.IsGrpc)
            {
                byte[] framed = GrpcFramer.WrapHunk(data, 0, data.Length);
                await _t.WriteStreamDataAsync(this, framed);
                return;
            }
            if (Mode == XhttpTransportMode.PacketUp)
            {
                await _upLock.WaitAsync();
                try
                {
                    int maxPost = _t.Config.ScMaxEachPostBytes > 0 ? _t.Config.ScMaxEachPostBytes : 1000000;
                    int off = 0;
                    while (off < data.Length)
                    {
                        if (Closed) return;
                        int chunkLen = Math.Min(data.Length - off, maxPost);
                        long seq = _upSeq++;
                        await _t.SendPacketUpAsync(SessionId, seq, data, off, chunkLen);
                        off += chunkLen;
                    }
                }
                finally { _upLock.Release(); }
                return;
            }
            if (Mode == XhttpTransportMode.StreamUp && UploadStream != null)
            {
                await _t.WriteStreamDataAsync(UploadStream, data);
                return;
            }
            await _t.WriteStreamDataAsync(this, data);
        }
        public void Close()
        {
            if (UploadStream != null) { try { _t.CloseStream(UploadStream); } catch { } }
            _t.CloseStream(this);
        }
    }
}
