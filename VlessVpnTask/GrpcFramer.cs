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
    internal sealed class GrpcFramer
    {
        private readonly List<byte> _buf = new List<byte>();

        public void PushData(byte[] chunk)
        {
            if (chunk != null && chunk.Length > 0)
            {
                _buf.AddRange(chunk);
            }
        }

        public byte[] TryExtractPayload()
        {
            if (_buf.Count < 5) return null;
            int msgLen = (_buf[1] << 24) | (_buf[2] << 16) | (_buf[3] << 8) | _buf[4];
            if (msgLen < 0 || msgLen > 10 * 1024 * 1024)
            {
                _buf.Clear();
                return null;
            }
            if (_buf.Count < 5 + msgLen) return null;

            int offset = 5;
            int end = 5 + msgLen;
            byte[] payload = null;

            while (offset < end)
            {
                int tagBytes;
                int tag = ReadVarint(out tagBytes, offset, end);
                if (tagBytes <= 0) break;
                offset += tagBytes;

                int fieldNum = tag >> 3;
                int wireType = tag & 0x07;

                if (wireType == 2)
                {
                    int lenBytes;
                    int len = ReadVarint(out lenBytes, offset, end);
                    if (lenBytes <= 0) break;
                    offset += lenBytes;

                    if (fieldNum == 1 && len >= 0 && offset + len <= end)
                    {
                        payload = new byte[len];
                        _buf.CopyTo(offset, payload, 0, len);
                    }
                    offset += len;
                }
                else if (wireType == 0)
                {
                    int skipBytes;
                    ReadVarint(out skipBytes, offset, end);
                    offset += skipBytes;
                }
                else break;
            }

            _buf.RemoveRange(0, 5 + msgLen);
            return payload ?? new byte[0];
        }

        private int ReadVarint(out int bytesRead, int start, int limit)
        {
            int res = 0;
            int shift = 0;
            bytesRead = 0;
            for (int i = start; i < limit && bytesRead < 5; i++)
            {
                byte b = _buf[i];
                bytesRead++;
                res |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0) return res;
                shift += 7;
            }
            return res;
        }

        public static byte[] WrapHunk(byte[] payload, int offset, int length)
        {
            if (payload == null || length <= 0) return new byte[0];
            int varintLen = 1;
            if (length >= 128)
            {
                if (length < 16384) varintLen = 2;
                else if (length < 2097152) varintLen = 3;
                else varintLen = 4;
            }

            int hunkLen = 1 + varintLen + length;
            byte[] res = new byte[5 + hunkLen];
            res[0] = 0x00;
            res[1] = (byte)(hunkLen >> 24);
            res[2] = (byte)(hunkLen >> 16);
            res[3] = (byte)(hunkLen >> 8);
            res[4] = (byte)hunkLen;

            res[5] = 0x0A;
            int pos = 6;
            int temp = length;
            while (temp >= 0x80)
            {
                res[pos++] = (byte)((temp & 0x7F) | 0x80);
                temp >>= 7;
            }
            res[pos++] = (byte)temp;

            global::System.Buffer.BlockCopy(payload, offset, res, pos, length);
            return res;
        }
    }
}
