using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;
using System.Runtime.InteropServices.WindowsRuntime;

namespace VlessVpnTask
{
    // Общий контракт персонального (per-flow) соединения в DIRECT-режиме NatEngine.
    // Его реализуют VlessConnection и SsConnection, поэтому движок одинаково работает
    // и с VLESS, и с Shadowsocks/Outline.
    internal interface IDirectConn
    {
        void ConfigureDirectIp(byte[] ip, bool isIpv6, ushort port);
        void ConfigureDirectDomain(string domain, ushort port);
        Task<bool> StartAsync();
        Task WriteUnderlyingAsync(byte[] data);
        Task<byte[]> ReadPayloadAsync();
        void Close();
    }

}
