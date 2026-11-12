using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Networking.Vpn;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    internal class TcpConn
    {
        public string Key;
        public ushort Sid; // MUX Stream ID
        public bool MuxNewSent = false;

        public bool IsIpv6 = false; // Флаг IPv6 соединения
        public byte[] SrcIp;
        public byte[] DstIp;
        public ushort SrcPort;
        public ushort DstPort;

        public uint IsnBase;
        public uint MySeq;
        public uint PeerSeq;

        public volatile TcpState State;
        public readonly object Lock = new object();
        public int Closing;
        public int MuxSlotState; // 0 = слот MUX не занят, 1 = занят (см. _tcpSlots)
        public MuxCarrier Carrier;

        public readonly ConcurrentQueue<byte[]> SendQueue = new ConcurrentQueue<byte[]>();
        public int Sending = 0;
        public readonly ConcurrentQueue<byte[]> RecvQueue = new ConcurrentQueue<byte[]>();
        public int Receiving = 0;
        public int RecvQueuedBytes = 0; // через Interlocked — для backpressure к несущему каналу


        public bool SendFinPending = false;

        // Сколько ждём downstream после локального FIN, прежде чем гасить туннельный
        // сокет. Ответ сервера почти всегда приходит за доли секунды; запас нужен
        // только чтобы полузакрытые соединения не копились и не съедали слоты.
        public const int HalfCloseGraceMs = 10000;

        public byte[] DnsServerIp = new byte[4];
        public readonly List<byte> DnsBuffer = new List<byte>();
        public DateTime DnsStartTime;
        public string DnsQueryDomain;

        // HTTP(S)-прокси режим (для AppContainer-приложений в обход WFP-изоляции TUN).
        public bool IsProxy = false;           // соединение пришло на адрес прокси
        public bool ProxyEstablished = false;  // заголовок CONNECT/GET уже разобран
        public ushort ProxyTargetPort;         // реальный порт назначения (для MUX New-кадра)
        public readonly List<byte> ProxyHead = new List<byte>();

        public DateTime LastActivityUtc = DateTime.UtcNow;

        public uint OsAckedSeq;          // наибольший ACK от ОС (сколько она подтвердила)
        public int OsWindow = 262144;    // последнее окно приёма, объявленное ОС
        public int OsWinShift = 0;       // сдвиг окна приёма ОС из TCP Window Scale (RFC 7323)

        public IDirectConn DirectConn;       // персональное соединение VLESS/Shadowsocks (direct-режим)
        public int DirectSlotState;          // 0/1 — занят ли слот _directSlots

    }
}
