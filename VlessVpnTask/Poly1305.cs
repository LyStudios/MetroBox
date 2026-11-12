using System;

namespace VlessVpnTask
{
        internal sealed class Poly1305
        {
            private readonly uint[] _r = new uint[5];
            private readonly uint[] _s = new uint[4];
            private readonly uint[] _h = new uint[5];
            private readonly byte[] _buf = new byte[16];
            private int _bufLen;

            public Poly1305(byte[] key)
            {
                uint t0 = AwgCrypto.Le32(key, 0), t1 = AwgCrypto.Le32(key, 4), t2 = AwgCrypto.Le32(key, 8), t3 = AwgCrypto.Le32(key, 12);
                // clamp
                _r[0] = t0 & 0x3ffffff;
                _r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
                _r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
                _r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
                _r[4] = (t3 >> 8) & 0x00fffff;
                _s[0] = AwgCrypto.Le32(key, 16); _s[1] = AwgCrypto.Le32(key, 20);
                _s[2] = AwgCrypto.Le32(key, 24); _s[3] = AwgCrypto.Le32(key, 28);
            }

            private void Block(byte[] m, int off, bool final)
            {
                uint hibit = final ? 0u : (1u << 24);
                uint t0 = AwgCrypto.Le32(m, off), t1 = AwgCrypto.Le32(m, off + 4), t2 = AwgCrypto.Le32(m, off + 8), t3 = AwgCrypto.Le32(m, off + 12);

                _h[0] += t0 & 0x3ffffff;
                _h[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
                _h[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
                _h[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
                _h[4] += (t3 >> 8) | hibit;

                ulong d0 = (ulong)_h[0] * _r[0] + (ulong)_h[1] * (5 * _r[4]) + (ulong)_h[2] * (5 * _r[3]) + (ulong)_h[3] * (5 * _r[2]) + (ulong)_h[4] * (5 * _r[1]);
                ulong d1 = (ulong)_h[0] * _r[1] + (ulong)_h[1] * _r[0] + (ulong)_h[2] * (5 * _r[4]) + (ulong)_h[3] * (5 * _r[3]) + (ulong)_h[4] * (5 * _r[2]);
                ulong d2 = (ulong)_h[0] * _r[2] + (ulong)_h[1] * _r[1] + (ulong)_h[2] * _r[0] + (ulong)_h[3] * (5 * _r[4]) + (ulong)_h[4] * (5 * _r[3]);
                ulong d3 = (ulong)_h[0] * _r[3] + (ulong)_h[1] * _r[2] + (ulong)_h[2] * _r[1] + (ulong)_h[3] * _r[0] + (ulong)_h[4] * (5 * _r[4]);
                ulong d4 = (ulong)_h[0] * _r[4] + (ulong)_h[1] * _r[3] + (ulong)_h[2] * _r[2] + (ulong)_h[3] * _r[1] + (ulong)_h[4] * _r[0];

                ulong c = d0 >> 26; _h[0] = (uint)d0 & 0x3ffffff;
                d1 += c; c = d1 >> 26; _h[1] = (uint)d1 & 0x3ffffff;
                d2 += c; c = d2 >> 26; _h[2] = (uint)d2 & 0x3ffffff;
                d3 += c; c = d3 >> 26; _h[3] = (uint)d3 & 0x3ffffff;
                d4 += c; c = d4 >> 26; _h[4] = (uint)d4 & 0x3ffffff;
                _h[0] += (uint)c * 5; c = _h[0] >> 26; _h[0] &= 0x3ffffff;
                _h[1] += (uint)c;
            }

            public void Update(byte[] data, int off, int len)
            {
                if (data == null || len <= 0) return;
                int i = 0;
                if (_bufLen > 0)
                {
                    int need = Math.Min(16 - _bufLen, len);
                    Array.Copy(data, off, _buf, _bufLen, need);
                    _bufLen += need; i += need;
                    if (_bufLen == 16) { Block(_buf, 0, false); _bufLen = 0; }
                }
                while (len - i >= 16) { Block(data, off + i, false); i += 16; }
                if (len - i > 0)
                {
                    Array.Copy(data, off + i, _buf, 0, len - i);
                    _bufLen = len - i;
                }
            }

            public byte[] Finish()
            {
                if (_bufLen > 0)
                {
                    _buf[_bufLen] = 1;
                    for (int i = _bufLen + 1; i < 16; i++) _buf[i] = 0;
                    Block(_buf, 0, true);
                }

                uint c = _h[1] >> 26; _h[1] &= 0x3ffffff;
                _h[2] += c; c = _h[2] >> 26; _h[2] &= 0x3ffffff;
                _h[3] += c; c = _h[3] >> 26; _h[3] &= 0x3ffffff;
                _h[4] += c; c = _h[4] >> 26; _h[4] &= 0x3ffffff;
                _h[0] += c * 5; c = _h[0] >> 26; _h[0] &= 0x3ffffff;
                _h[1] += c;

                uint[] g = new uint[5];
                g[0] = _h[0] + 5; c = g[0] >> 26; g[0] &= 0x3ffffff;
                g[1] = _h[1] + c; c = g[1] >> 26; g[1] &= 0x3ffffff;
                g[2] = _h[2] + c; c = g[2] >> 26; g[2] &= 0x3ffffff;
                g[3] = _h[3] + c; c = g[3] >> 26; g[3] &= 0x3ffffff;
                g[4] = _h[4] + c - (1u << 26);

                uint mask = (g[4] >> 31) - 1;   // 0xffffffff если g >= 2^130-5
                for (int i = 0; i < 5; i++) g[i] &= mask;
                mask = ~mask;
                for (int i = 0; i < 5; i++) _h[i] = (_h[i] & mask) | g[i];

                uint f0 = (_h[0] | (_h[1] << 26)) & 0xffffffff;
                uint f1 = ((_h[1] >> 6) | (_h[2] << 20)) & 0xffffffff;
                uint f2 = ((_h[2] >> 12) | (_h[3] << 14)) & 0xffffffff;
                uint f3 = ((_h[3] >> 18) | (_h[4] << 8)) & 0xffffffff;

                ulong t = (ulong)f0 + _s[0]; f0 = (uint)t;
                t = (ulong)f1 + _s[1] + (t >> 32); f1 = (uint)t;
                t = (ulong)f2 + _s[2] + (t >> 32); f2 = (uint)t;
                t = (ulong)f3 + _s[3] + (t >> 32); f3 = (uint)t;

                byte[] tag = new byte[16];
                AwgCrypto.WriteLe32(tag, 0, f0); AwgCrypto.WriteLe32(tag, 4, f1);
                AwgCrypto.WriteLe32(tag, 8, f2); AwgCrypto.WriteLe32(tag, 12, f3);
                return tag;
            }
        }
}
