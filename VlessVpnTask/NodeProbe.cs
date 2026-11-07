using System;
using System.Diagnostics;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Threading;
using System.Threading.Tasks;
using Windows.Foundation;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Storage.Streams;

namespace VlessVpnTask
{
    /// <summary>
    /// Предоставляет методы для реальной проверки доступности узлов (REALITY/TLS хендшейк, AmneziaWG/WireGuard Noise-проба, TCP-пинг).
    /// </summary>
    public sealed class NodeProbe
    {
        public static IAsyncOperation<int> ProbeVlessAsync(
            string address, int port, string transport, string security,
            string sni, string publicKey, string shortId, string path, string host, int timeoutMs)
        {
            return AsyncInfo.Run(async ct =>
            {
                if (string.IsNullOrEmpty(address) || port <= 0) return -1;
                if (timeoutMs <= 0) timeoutMs = 3000;

                var sw = Stopwatch.StartNew();
                StreamSocket socket = null;
                try
                {
                    socket = new StreamSocket();
                    using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                    {
                        cts.CancelAfter(timeoutMs);

                        // 1. Установка TCP-соединения
                        var hostName = new HostName(address);
                        var connectTask = socket.ConnectAsync(hostName, port.ToString(), SocketProtectionLevel.PlainSocket).AsTask(cts.Token);
                        await connectTask;

                        string sec = (security ?? "").Trim().ToLowerInvariant();
                        bool isReality = sec == "reality";
                        bool isTls = sec == "tls";
                        string tr = (transport ?? "tcp").Trim().ToLowerInvariant();

                        // 2. Реальная проверка TLS / REALITY через нативный хендшейк
                        if (isReality || isTls)
                        {
                            var cfg = new VlessConfig
                            {
                                Address = address,
                                Port = port,
                                Security = isReality ? "reality" : "tls",
                                Sni = !string.IsNullOrEmpty(sni) ? sni : address,
                                PublicKey = publicKey ?? "",
                                ShortId = shortId ?? "",
                                Type = tr
                            };

                            var writer = new DataWriter(socket.OutputStream);
                            var reader = new DataReader(socket.InputStream) { InputStreamOptions = InputStreamOptions.Partial };

                            var realityStream = new RealityTls13Stream(cfg)
                            {
                                PlainTls = isTls,
                                OfferH1Only = (tr == "ws")
                            };

                            int remainMs = Math.Max(1000, timeoutMs - (int)sw.ElapsedMilliseconds);
                            var hsTask = realityStream.EstablishHandshakeAsync(writer, reader);
                            var done = await Task.WhenAny(hsTask, Task.Delay(remainMs, cts.Token));

                            if (done != hsTask || !await hsTask)
                            {
                                return -1;
                            }
                        }
                        else if (tr == "ws")
                        {
                            // 3. Проверка WebSocket-эндпоинта без шифрования
                            var writer = new DataWriter(socket.OutputStream);
                            var reader = new DataReader(socket.InputStream) { InputStreamOptions = InputStreamOptions.Partial };

                            string wsPath = !string.IsNullOrEmpty(path) ? (path.StartsWith("/") ? path : "/" + path) : "/";
                            string wsHost = !string.IsNullOrEmpty(host) ? host : (!string.IsNullOrEmpty(sni) ? sni : address);
                            string req = $"GET {wsPath} HTTP/1.1\r\nHost: {wsHost}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n";
                            writer.WriteString(req);
                            await writer.StoreAsync();

                            int remainMs = Math.Max(800, timeoutMs - (int)sw.ElapsedMilliseconds);
                            var loadTask = reader.LoadAsync(12).AsTask(cts.Token);
                            var loadDone = await Task.WhenAny(loadTask, Task.Delay(remainMs, cts.Token));
                            if (loadDone != loadTask || await loadTask == 0) return -1;

                            string statusLine = reader.ReadString(Math.Min(reader.UnconsumedBufferLength, 12));
                            if (!statusLine.StartsWith("HTTP/")) return -1;
                        }

                        sw.Stop();
                        return (int)sw.ElapsedMilliseconds;
                    }
                }
                catch
                {
                    return -1;
                }
                finally
                {
                    try { socket?.Dispose(); } catch { }
                }
            });
        }

        public static IAsyncOperation<int> ProbeAwgAsync(string configText, int timeoutMs)
        {
            return AsyncInfo.Run(async ct =>
            {
                if (string.IsNullOrEmpty(configText)) return -1;
                if (timeoutMs <= 0) timeoutMs = 3000;

                string reason;
                AwgConfig cfg = AwgConfig.Parse(configText, out reason);
                if (cfg == null || string.IsNullOrEmpty(cfg.EndpointHost) || cfg.EndpointPort == 0)
                    return -1;

                var sw = Stopwatch.StartNew();
                DatagramSocket socket = null;
                try
                {
                    socket = new DatagramSocket();
                    var remote = new HostName(cfg.EndpointHost);
                    string port = cfg.EndpointPort.ToString();

                    await socket.ConnectAsync(remote, port);

                    var tunnel = new AwgTunnel(cfg);
                    var waiter = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);

                    socket.MessageReceived += (sender, args) =>
                    {
                        try
                        {
                            var dr = args.GetDataReader();
                            uint len = dr.UnconsumedBufferLength;
                            byte[] data = new byte[len];
                            dr.ReadBytes(data);

                            if (AwgTunnel.IsHandshakeResponse(cfg, data, (int)len))
                            {
                                if (tunnel.ConsumeResponse(data, (int)len))
                                {
                                    waiter.TrySetResult(true);
                                }
                            }
                        }
                        catch { }
                    };

                    using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                    {
                        cts.CancelAfter(timeoutMs);

                        // 1. Отправка подписных пакетов (если заданы в конфиге Amnezia)
                        byte[][] sigs = tunnel.BuildSignaturePackets();
                        if (sigs != null && sigs.Length > 0)
                        {
                            foreach (var s in sigs)
                            {
                                await socket.OutputStream.WriteAsync(s.AsBuffer());
                            }
                        }

                        // 2. Отправка мусорных пакетов обфускации
                        byte[][] junk = tunnel.BuildJunkPackets();
                        if (junk != null && junk.Length > 0)
                        {
                            foreach (var j in junk)
                            {
                                await socket.OutputStream.WriteAsync(j.AsBuffer());
                            }
                        }

                        // 3. Отправка пакета инициации хендшейка
                        byte[] init = tunnel.BuildInitiation();
                        await socket.OutputStream.WriteAsync(init.AsBuffer());

                        // 4. Ожидание валидного ответа Noise IKpsk2
                        var done = await Task.WhenAny(waiter.Task, Task.Delay(timeoutMs, cts.Token));
                        if (done == waiter.Task && await waiter.Task)
                        {
                            sw.Stop();
                            return (int)sw.ElapsedMilliseconds;
                        }
                    }

                    return -1;
                }
                catch
                {
                    return -1;
                }
                finally
                {
                    try { socket?.Dispose(); } catch { }
                }
            });
        }

        public static IAsyncOperation<int> ProbeTcpAsync(string address, int port, int timeoutMs)
        {
            return AsyncInfo.Run(async ct =>
            {
                if (string.IsNullOrEmpty(address) || port <= 0) return -1;
                if (timeoutMs <= 0) timeoutMs = 3000;

                var sw = Stopwatch.StartNew();
                StreamSocket socket = null;
                try
                {
                    socket = new StreamSocket();
                    using (var cts = CancellationTokenSource.CreateLinkedTokenSource(ct))
                    {
                        cts.CancelAfter(timeoutMs);
                        await socket.ConnectAsync(new HostName(address), port.ToString(), SocketProtectionLevel.PlainSocket).AsTask(cts.Token);
                        sw.Stop();
                        return (int)sw.ElapsedMilliseconds;
                    }
                }
                catch
                {
                    return -1;
                }
                finally
                {
                    try { socket?.Dispose(); } catch { }
                }
            });
        }
    }
}

