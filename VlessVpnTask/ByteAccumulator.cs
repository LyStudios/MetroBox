using System;

namespace VlessVpnTask
{
        // Растущий байтовый буфер со скользящим окном [_start, _start+_count).
        // Заменяет List<byte> + Skip/Take/RemoveRange (которые были O(n) на каждый MUX-фрейм).
        internal sealed class ByteAccumulator
        {
            private byte[] _buf = new byte[16384];
            private int _start;
            private int _count;

            public int Count => _count;

            // Индекс относительно логического начала окна.
            public byte this[int i] => _buf[_start + i];

            public void Append(byte[] data, int len)
            {
                EnsureSpace(len);
                System.Buffer.BlockCopy(data, 0, _buf, _start + _count, len);
                _count += len;
            }

            public byte[] Slice(int off, int n)
            {
                var r = new byte[n];
                System.Buffer.BlockCopy(_buf, _start + off, r, 0, n);
                return r;
            }

            public void Consume(int n)
            {
                _start += n;
                _count -= n;
                if (_count == 0) _start = 0;
                else if (_start > _buf.Length / 2) Compact();
            }

            private void EnsureSpace(int extra)
            {
                if (_start + _count + extra <= _buf.Length) return;
                if (_count + extra <= _buf.Length) { Compact(); return; }
                int newCap = _buf.Length;
                while (newCap < _count + extra) newCap *= 2;
                var nb = new byte[newCap];
                System.Buffer.BlockCopy(_buf, _start, nb, 0, _count);
                _buf = nb;
                _start = 0;
            }

            private void Compact()
            {
                if (_start == 0) return;
                System.Buffer.BlockCopy(_buf, _start, _buf, 0, _count);
                _start = 0;
            }
        }

}
