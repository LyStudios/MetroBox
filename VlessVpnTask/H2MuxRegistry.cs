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
    // Пул общих туннелей. Сейчас в конфиге один сервер, поэтому пул глобальный.
    internal static class H2MuxRegistry
    {
        private const int MaxConnsPerServer = 4;
        private const int SoftStreamCap = 60;

        private static readonly object _lock = new object();
        private static readonly List<H2MuxTransport> _pool = new List<H2MuxTransport>();
        public static volatile bool ServerRejectedH2;

        public static async Task<H2Stream> AcquireStreamAsync(VlessConfig cfg)
        {
            if (ServerRejectedH2) return null;
            for (int attempt = 0; attempt <= MaxConnsPerServer; attempt++)
            {
                if (ServerRejectedH2) return null;
                H2MuxTransport t = PickOrCreate(cfg);
                if (t == null) return null;
                if (!await t.EnsureStartedAsync()) { Remove(t); continue; }
                H2Stream st = await t.OpenStreamAsync();
                if (st != null) return st;
                Remove(t);
            }
            return null;
        }

        private static H2MuxTransport PickOrCreate(VlessConfig cfg)
        {
            lock (_lock)
            {
                _pool.RemoveAll(x => x.Dead);

                H2MuxTransport best = null; int bestLoad = int.MaxValue;
                foreach (var t in _pool) { int l = t.Load; if (l < bestLoad) { bestLoad = l; best = t; } }

                int softCap = (cfg != null && cfg.XmuxMaxConcurrency > 0) ? cfg.XmuxMaxConcurrency : SoftStreamCap;
                if (best != null && best.TryReserve(softCap)) return best;

                if (_pool.Count < MaxConnsPerServer)
                {
                    var nt = new H2MuxTransport(cfg);
                    _pool.Add(nt);
                    nt.TryReserve(softCap);
                    return nt;
                }

                if (_pool.Count < MaxConnsPerServer)
                {
                    var nt = new H2MuxTransport(cfg);
                    _pool.Add(nt);
                    nt.TryReserve(SoftStreamCap);
                    return nt;
                }

                if (best != null) { best.ForceReserve(); return best; } // оверсабскрайб
                return null;
            }
        }

        public static void Remove(H2MuxTransport t) { lock (_lock) { _pool.Remove(t); } }

        public static void Reset()
        {
            ServerRejectedH2 = false;
            List<H2MuxTransport> all;
            lock (_lock) { all = new List<H2MuxTransport>(_pool); _pool.Clear(); }
            foreach (var t in all) t.KillAll();
        }
    }
}
