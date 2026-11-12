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
    // Дечанкер HTTP/1.1 (вынесен, чтобы не связываться с XhttpStreamOne).
    internal sealed class ChunkedDecoder
    {
        public bool Chunked = true;
        private ChunkedDecodeState _s = ChunkedDecodeState.Size;
        private int _need;
        private readonly StringBuilder _sizeAcc = new StringBuilder();
        private byte[] _buf = new byte[65536];
        private int _len;

        public bool Done => _s == ChunkedDecodeState.Done;

        public void Feed(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            if (_len + data.Length > _buf.Length)
            {
                int cap = _buf.Length * 2;
                while (cap < _len + data.Length) cap *= 2;
                Array.Resize(ref _buf, cap);
            }
            System.Buffer.BlockCopy(data, 0, _buf, _len, data.Length);
            _len += data.Length;
        }

        public byte[] Pull()
        {
            if (!Chunked)
            {
                if (_len == 0) return new byte[0];
                byte[] all = new byte[_len];
                System.Buffer.BlockCopy(_buf, 0, all, 0, _len);
                _len = 0;
                return all;
            }

            var outp = new List<byte>();
            int i = 0;
            while (i < _len && _s != ChunkedDecodeState.Done)
            {
                if (_s == ChunkedDecodeState.Size)
                {
                    byte b = _buf[i++];
                    if (b == (byte)'\n')
                    {
                        string line = _sizeAcc.ToString().Trim();
                        _sizeAcc.Clear();
                        int semi = line.IndexOf(';');
                        if (semi >= 0) line = line.Substring(0, semi);
                        int sz;
                        try { sz = Convert.ToInt32(line, 16); }
                        catch { _s = ChunkedDecodeState.Done; break; }
                        if (sz == 0) { _s = ChunkedDecodeState.Done; break; }
                        _need = sz; _s = ChunkedDecodeState.Data;
                    }
                    else if (b != (byte)'\r')
                    {
                        _sizeAcc.Append((char)b);
                        if (_sizeAcc.Length > 16) { _s = ChunkedDecodeState.Done; break; }
                    }
                }
                else if (_s == ChunkedDecodeState.Data)
                {
                    int take = Math.Min(_len - i, _need);
                    for (int k = 0; k < take; k++) outp.Add(_buf[i + k]);
                    i += take; _need -= take;
                    if (_need == 0) _s = ChunkedDecodeState.AfterCR;
                }
                else if (_s == ChunkedDecodeState.AfterCR)
                {
                    byte b = _buf[i++];
                    if (b == (byte)'\n') _s = ChunkedDecodeState.Size; else _s = ChunkedDecodeState.AfterLF;
                }
                else if (_s == ChunkedDecodeState.AfterLF) { i++; _s = ChunkedDecodeState.Size; }
            }
            if (i > 0)
            {
                _len -= i;
                if (_len > 0) System.Buffer.BlockCopy(_buf, i, _buf, 0, _len);
            }
            return outp.Count == 0 ? new byte[0] : outp.ToArray();
        }
    }
}
