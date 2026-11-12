using System;
using System.Numerics;

namespace VlessApp
{
        internal static class AmneziaX25519
        {
            private static readonly BigInteger P =
                (BigInteger.One << 255) - 19;
            private const int A24 = 121665;

            public static byte[] CreateRandomPrivateKey()
            {
                byte[] k = AmneziaApi.CryptoBytes(32);
                k[0] &= 248; k[31] &= 127; k[31] |= 64;
                return k;
            }

            public static byte[] GetPublicKey(byte[] privateKey)
            {
                byte[] basePoint = new byte[32];
                basePoint[0] = 9;
                return ScalarMult(privateKey, basePoint);
            }

            public static byte[] ScalarMult(byte[] scalar, byte[] uCoord)
            {
                byte[] k = (byte[])scalar.Clone();
                k[0] &= 248; k[31] &= 127; k[31] |= 64;

                byte[] u = (byte[])uCoord.Clone();
                u[31] &= 0x7F;                       // RFC 7748: старший бит u игнорируется
                BigInteger x1 = FromLe(u);

                BigInteger x2 = BigInteger.One, z2 = BigInteger.Zero;
                BigInteger x3 = x1, z3 = BigInteger.One;
                int swap = 0;

                for (int t = 254; t >= 0; t--)
                {
                    int kt = (k[t >> 3] >> (t & 7)) & 1;
                    swap ^= kt;
                    CSwap(swap, ref x2, ref x3);
                    CSwap(swap, ref z2, ref z3);
                    swap = kt;

                    BigInteger a = Mod(x2 + z2);
                    BigInteger aa = Mod(a * a);
                    BigInteger b = Mod(x2 - z2);
                    BigInteger bb = Mod(b * b);
                    BigInteger e = Mod(aa - bb);
                    BigInteger c = Mod(x3 + z3);
                    BigInteger d = Mod(x3 - z3);
                    BigInteger da = Mod(d * a);
                    BigInteger cb = Mod(c * b);

                    x3 = Mod((da + cb) * (da + cb));
                    z3 = Mod(x1 * Mod((da - cb) * (da - cb)));
                    x2 = Mod(aa * bb);
                    z2 = Mod(e * (aa + A24 * e));
                }

                CSwap(swap, ref x2, ref x3);
                CSwap(swap, ref z2, ref z3);

                BigInteger res = Mod(x2 * BigInteger.ModPow(z2, P - 2, P));
                return ToLe(res);
            }

            private static void CSwap(int swap, ref BigInteger a, ref BigInteger b)
            {
                if (swap == 0) return;
                BigInteger t = a; a = b; b = t;
            }

            private static BigInteger Mod(BigInteger v)
            {
                BigInteger r = v % P;
                if (r.Sign < 0) r += P;
                return r;
            }

            private static BigInteger FromLe(byte[] le)
            {
                byte[] t = new byte[le.Length + 1];   // хвостовой ноль — число без знака
                System.Buffer.BlockCopy(le, 0, t, 0, le.Length);
                return new BigInteger(t);
            }

            private static byte[] ToLe(BigInteger v)
            {
                byte[] raw = v.ToByteArray();
                byte[] o = new byte[32];
                System.Buffer.BlockCopy(raw, 0, o, 0, Math.Min(32, raw.Length));
                return o;
            }
        }
}
