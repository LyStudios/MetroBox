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
    // Быстрый X25519 (radix 2^25.5, 10 знаковых 64-битных лимбов — представление
    // curve25519-donna). В горячем пути только long-арифметика без BigInteger и
    // без деления, поэтому на ARM это на порядок быстрее прежней BigInteger-версии.
    // Реализация проверена против тест-векторов RFC 7748 и перекрёстно на тысячах
    // случайных входов против прежней BigInteger-реализации.
    internal static class Curve25519
    {
        private static readonly int[] SZ = { 26, 25, 26, 25, 26, 25, 26, 25, 26, 25 };
        [ThreadStatic] private static long[] _scratch19;

        public static byte[] CreateRandomPrivateKey()
        {
            byte[] k = Tls13Crypto.RandomBytes(32);
            k[0] &= 248; k[31] &= 127; k[31] |= 64;
            return k;
        }

        public static byte[] GetPublicKey(byte[] privateKey)
        {
            var bp = new byte[32]; bp[0] = 9;
            return ScalarMult(privateKey, bp);
        }

        public static byte[] GetSharedSecret(byte[] privateKey, byte[] peerPublicKey)
        {
            return ScalarMult(privateKey, peerPublicKey);
        }

        private static long[] Expand(byte[] input)
        {
            var t = new byte[33];
            Array.Copy(input, t, 32);
            t[31] &= 0x7f; // RFC 7748: обнуляем старший бит u
            System.Numerics.BigInteger x = new System.Numerics.BigInteger(t);
            var o = new long[10];
            for (int i = 0; i < 10; i++)
            {
                o[i] = (long)(x & ((System.Numerics.BigInteger.One << SZ[i]) - 1));
                x >>= SZ[i];
            }
            return o;
        }

        private static byte[] Contract(long[] input)
        {
            FreduceCoefficients(input);
            System.Numerics.BigInteger x = 0; int off = 0;
            for (int i = 0; i < 10; i++) { x += (System.Numerics.BigInteger)input[i] << off; off += SZ[i]; }
            System.Numerics.BigInteger P = (System.Numerics.BigInteger.One << 255) - 19;
            x %= P; if (x.Sign < 0) x += P;
            var raw = x.ToByteArray();
            var b = new byte[32];
            Array.Copy(raw, b, Math.Min(32, raw.Length));
            return b;
        }

        private static void Fsum(long[] o, long[] a) { for (int i = 0; i < 10; i++) o[i] += a[i]; }
        private static void Fdiff(long[] o, long[] a, long[] b) { for (int i = 0; i < 10; i++) o[i] = a[i] - b[i]; }
        private static void Fscalar(long[] o, long[] a, long s) { for (int i = 0; i < 10; i++) o[i] = a[i] * s; }

        private static void Fproduct(long[] o, long[] a, long[] b)
        {
            for (int i = 0; i < 19; i++) o[i] = 0;
            for (int i = 0; i < 10; i++)
                for (int j = 0; j < 10; j++)
                {
                    long f = ((i & 1) == 1 && (j & 1) == 1) ? 2 : 1;
                    o[i + j] += f * a[i] * b[j];
                }
        }

        private static void FreduceDegree(long[] o)
        {
            o[8] += o[18] * 19; o[7] += o[17] * 19; o[6] += o[16] * 19; o[5] += o[15] * 19;
            o[4] += o[14] * 19; o[3] += o[13] * 19; o[2] += o[12] * 19; o[1] += o[11] * 19; o[0] += o[10] * 19;
        }

        private static long DivBy2_26(long v) { long sign = v >> 63; long roundoff = (long)((ulong)sign >> 38); return (v + roundoff) >> 26; }
        private static long DivBy2_25(long v) { long sign = v >> 63; long roundoff = (long)((ulong)sign >> 39); return (v + roundoff) >> 25; }

        private static void FreduceCoefficients(long[] o)
        {
            long o10 = 0, over;
            for (int i = 0; i < 10; i += 2)
            {
                over = DivBy2_26(o[i]); o[i] -= over << 26; o[i + 1] += over;
                over = DivBy2_25(o[i + 1]); o[i + 1] -= over << 25;
                if (i + 2 < 10) o[i + 2] += over; else o10 += over;
            }
            o[0] += o10 * 19;
            over = DivBy2_26(o[0]); o[0] -= over << 26; o[1] += over;
        }

        private static void Fmul(long[] o, long[] a, long[] b)
        {
            long[] t = _scratch19; if (t == null) { t = new long[19]; _scratch19 = t; }
            Fproduct(t, a, b);
            FreduceDegree(t);
            FreduceCoefficients(t);
            for (int i = 0; i < 10; i++) o[i] = t[i];
        }

        private static void Fsquare(long[] o, long[] a) { Fmul(o, a, a); }
        private static void SqN(long[] dst, long[] src, int n) { Fsquare(dst, src); for (int i = 1; i < n; i++) Fsquare(dst, dst); }

        private static long[] Recip(long[] z)
        {
            long[] z2 = new long[10], z9 = new long[10], z11 = new long[10], z2_5_0 = new long[10],
                   z2_10_0 = new long[10], z2_20_0 = new long[10], z2_50_0 = new long[10],
                   z2_100_0 = new long[10], t = new long[10];
            Fsquare(z2, z);
            SqN(t, z2, 2); Fmul(z9, t, z);
            Fmul(z11, z9, z2);
            SqN(t, z11, 1); Fmul(z2_5_0, t, z9);
            SqN(t, z2_5_0, 5); Fmul(z2_10_0, t, z2_5_0);
            SqN(t, z2_10_0, 10); Fmul(z2_20_0, t, z2_10_0);
            SqN(t, z2_20_0, 20); Fmul(t, t, z2_20_0);
            SqN(t, t, 10); Fmul(z2_50_0, t, z2_10_0);
            SqN(t, z2_50_0, 50); Fmul(z2_100_0, t, z2_50_0);
            SqN(t, z2_100_0, 100); Fmul(t, t, z2_100_0);
            SqN(t, t, 50); Fmul(t, t, z2_50_0);
            SqN(t, t, 5);
            long[] outp = new long[10]; Fmul(outp, t, z11);
            return outp;
        }

        private static void CSwap(int swap, long[] a, long[] b)
        {
            if (swap == 0) return;
            for (int i = 0; i < 10; i++) { long t = a[i]; a[i] = b[i]; b[i] = t; }
        }

        private static byte[] ScalarMult(byte[] scalar, byte[] uBytes)
        {
            if (scalar == null || scalar.Length != 32) throw new ArgumentException("X25519 key must be 32 bytes.");
            if (uBytes == null || uBytes.Length != 32) throw new ArgumentException("X25519 input must be 32 bytes.");

            var k = new byte[32]; Array.Copy(scalar, k, 32);
            k[0] &= 248; k[31] &= 127; k[31] |= 64;

            long[] x1 = Expand(uBytes);
            long[] x2 = new long[10]; x2[0] = 1;
            long[] z2 = new long[10];
            long[] x3 = (long[])x1.Clone();
            long[] z3 = new long[10]; z3[0] = 1;
            int swap = 0;

            long[] A = new long[10], AA = new long[10], B = new long[10], BB = new long[10],
                   E = new long[10], C = new long[10], D = new long[10], DA = new long[10],
                   CB = new long[10], t0 = new long[10], t1 = new long[10];

            for (int t = 254; t >= 0; t--)
            {
                int kt = (k[t >> 3] >> (t & 7)) & 1;
                swap ^= kt;
                CSwap(swap, x2, x3);
                CSwap(swap, z2, z3);
                swap = kt;

                Array.Copy(x2, A, 10); Fsum(A, z2);      // A = x2+z2
                Fsquare(AA, A);
                Fdiff(B, x2, z2);                         // B = x2-z2
                Fsquare(BB, B);
                Fdiff(E, AA, BB);                         // E = AA-BB
                Array.Copy(x3, C, 10); Fsum(C, z3);      // C = x3+z3
                Fdiff(D, x3, z3);                         // D = x3-z3
                Fmul(DA, D, A);
                Fmul(CB, C, B);
                Array.Copy(DA, t0, 10); Fsum(t0, CB);    // t0 = DA+CB
                Fsquare(x3, t0);                          // x3 = (DA+CB)^2
                Fdiff(t1, DA, CB);                        // t1 = DA-CB
                Fsquare(t0, t1);                          // t0 = (DA-CB)^2
                Fmul(z3, x1, t0);                         // z3 = x1*(DA-CB)^2
                Fmul(x2, AA, BB);                         // x2 = AA*BB
                Fscalar(t0, E, 121665);                   // t0 = a24*E
                FreduceCoefficients(t0);
                Fsum(t0, AA);                             // t0 = AA + a24*E
                Fmul(z2, E, t0);                          // z2 = E*(AA+a24*E)
            }
            CSwap(swap, x2, x3);
            CSwap(swap, z2, z3);

            long[] zinv = Recip(z2);
            long[] res = new long[10];
            Fmul(res, x2, zinv);
            return Contract(res);
        }
    }
}
