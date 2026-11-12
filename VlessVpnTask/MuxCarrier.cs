using System.Threading;

namespace VlessVpnTask
{
    internal sealed class MuxCarrier
    {
        public VlessConnection Conn;
        public volatile bool Running;
        public int Substreams;                 // через Interlocked
        public readonly SemaphoreSlim WriteLock = new SemaphoreSlim(1, 1);
    }
}
