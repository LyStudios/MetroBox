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
    internal class VlessConnection : IDirectConn
    {
        public StreamSocket Socket { get; private set; }
        private DataWriter _writer;
        private DataReader _reader;
        private VlessConfig _cfg;
        private VpnChannel _channel;
        private RealityTls13Stream _realityStream;

        private List<byte> _receiveBuffer = new List<byte>();
        private bool _headerStripped = false;
        private byte[] _vlessHeaderBuffer = null;

        private System.IO.Stream _outStream;
        private volatile bool _closed;

        // Тайминги для разбора обрыва: сервер закрывает поток в ответ на наш запрос
        // или ещё раньше, на Client Finished? Отличить можно только по времени
        // относительно RTT, поэтому все три величины держим рядом.
        private long _tcpRttMs;
        private DateTime _handshakeDoneUtc = DateTime.MinValue;
        private DateTime _requestSentUtc = DateTime.MinValue;
        private bool _downClosedLogged;
        private string _closeReason = "неизвестно";

        private bool _xhttpEnabled;
        private XhttpSplitClient _split;
        private bool _splitEnabled;
        private WsTransport _ws;
        private bool _wsEnabled;
        private XhttpStreamOne _xhttp;
        private bool _xhttpHeadParsed;

        private bool _directMode;
        private byte _directAddrType;
        private byte[] _directAddr;
        private string _directDomain;
        private ushort _directPort;

        private bool _h2Enabled;
        private Http2Conn _h2;
        private bool _h2HeadStatusLogged;
        private bool _vlessHeaderSent;
        private readonly System.Threading.SemaphoreSlim _rawWriteLock = new System.Threading.SemaphoreSlim(1, 1);
        private int _h2PendingCredit;

        // Вариант B: xhttp stream-one через ОБЩИЙ мультиплексированный Reality+H2 туннель
        // (много flow'ов = много H2-стримов на один хендшейк). Kill-switch ниже — при
        // false возвращаемся к старому пути «один Reality+H2 на flow».
        public static bool UseH2Mux = true;
        private bool _muxEnabled;
        private H2Stream _muxStream;

        // xtls-rprx-vision
        private bool _visionEnabled;
        private VisionWrap _visionWrap;
        private VisionUnpad _visionUnpad;
        private bool _visionFirstSent;
        private byte[] _uuidBytes;

        // Имя из IDirectConn: движок одинаково тянет payload и из VLESS, и из Shadowsocks.
        public Task<byte[]> ReadPayloadAsync() { return ReadVlessPayloadAsync(); }

        // Первое звено цепочки. Если задано, соединение поднимается не по TCP,
        // а поверх этого туннеля. Ставится только для профилей Amnezia с двумя
        // outbound'ами; у остальных остаётся null и весь прежний путь не меняется.
        private IDirectConn _chainOuter;

        public void UseChainTransport(IDirectConn outer) { _chainOuter = outer; }

        // Поток отправки. У второго звена цепочки сокета нет вовсе — писать
        // нужно в первое звено. Без этой развилки запись падала с
        // NullReferenceException на Socket.OutputStream уже после того,
        // как оба рукопожатия успешно прошли.
        private void EnsureOutStream()
        {
            if (_outStream != null) return;
            _outStream = _chainOuter != null
                ? new ChainOutputStream(_chainOuter).AsStreamForWrite(81920)
                : Socket.OutputStream.AsStreamForWrite(81920);
        }

        // Разовая проверка цепочки Amnezia. Реле закрывает поток, приняв ноль
        // байт, и по close_notify нельзя отличить «запрещён маршрут» от «нет
        // резолвера»: мы шлём доменное имя из-за fake-DNS. Обе версии
        // предсказывают, что IP-назначение пройдёт, — направляем ПЕРВОЕ
        // соединение на выходной узел и смотрим, что придёт в ответ.
        private bool _isChainProbe;

        // Диагностическая подмена назначения своё отработала: она доказала, что
        // реле пропускает трафик до выходного узла. Теперь этим занимается
        // настоящая цепочка в NatEngine, а подмена только мешала бы.
        private bool TryRedirectToChainExit() { return false; }

        public static bool TryParseIpv4Public(string s, out byte[] ip) { return TryParseIpv4(s, out ip); }

        private static bool TryParseIpv4(string s, out byte[] ip)
        {
            ip = null;
            var parts = (s ?? "").Split('.');
            if (parts.Length != 4) return false;
            var b = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                int v;
                if (!int.TryParse(parts[i], out v) || v < 0 || v > 255) return false;
                b[i] = (byte)v;
            }
            ip = b;
            return true;
        }

        public void ConfigureDirectIp(byte[] ip, bool isIpv6, ushort port)
        {
            if (TryRedirectToChainExit()) return;
            _directMode = true;
            _directAddrType = isIpv6 ? (byte)0x03 : (byte)0x01;
            _directAddr = ip;
            _directPort = port;
        }

        public void ConfigureDirectDomain(string domain, ushort port)
        {
            if (TryRedirectToChainExit()) return;
            _directMode = true;
            _directAddrType = 0x02;
            _directDomain = domain;
            _directPort = port;
        }

        public static byte[] GuidToNetworkBytes(Guid id)
        {
            string hex = id.ToString("N");
            var b = new byte[16];
            for (int i = 0; i < 16; i++) b[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            return b;
        }

        private string DumpPayload(byte[] data, int maxLen = 512)
        {
            if (data == null || data.Length == 0) return "[EMPTY]";
            int len = Math.Min(data.Length, maxLen);
            var sb = new StringBuilder();
            sb.AppendLine($"--- Дамп ({data.Length} байт) ---");
            for (int i = 0; i < len; i += 16)
            {
                sb.Append($"{i:X4} | ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < len) sb.Append($"{data[i + j]:X2} ");
                    else sb.Append("   ");
                }
                sb.Append("| ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < len)
                    {
                        char c = (char)data[i + j];
                        sb.Append((c >= 32 && c <= 126) ? c : '.');
                    }
                }
                sb.AppendLine();
            }
            if (data.Length > maxLen) sb.AppendLine("... (остаток скрыт)");
            return sb.ToString();
        }

        public VlessConnection(VlessConfig config, VpnChannel channel)
        {
            _cfg = config;
            _channel = channel;
        }

        private byte[] BuildDirectVlessHeader()
        {
            using (var ms = new MemoryStream())
            {
                ms.WriteByte(0x00);
                Guid guid = Guid.Empty; Guid.TryParse(_cfg.Uuid, out guid);
                ms.Write(GuidToNetworkBytes(guid), 0, 16);
                ms.WriteByte(0x00); // addon len
                ms.WriteByte(0x01); // cmd = TCP
                ms.WriteByte((byte)(_directPort >> 8));
                ms.WriteByte((byte)(_directPort & 0xFF));
                ms.WriteByte(_directAddrType);
                if (_directAddrType == 0x02)
                {
                    byte[] d = Encoding.UTF8.GetBytes(_directDomain);
                    ms.WriteByte((byte)d.Length);
                    ms.Write(d, 0, d.Length);
                }
                else
                {
                    ms.Write(_directAddr, 0, _directAddr.Length);
                }
                return ms.ToArray();
            }
        }

        private async Task<bool> StartSplitAsync(bool packetUp)
        {
            _split = new XhttpSplitClient(_cfg, packetUp, BuildDirectVlessHeader());
            _splitEnabled = true;
            if (!await _split.StartAsync()) { Close(); return false; }
            return true;
        }

        private async Task<bool> StartWsAsync()
        {
            // ВАЖНО: StartAsync уходит в эту ветку ДО общего блока, где строится
            // _vlessHeaderBuffer, поэтому заголовок надо собрать здесь. Без него
            // WriteUnderlyingAsync отправлял в WS голую полезную нагрузку без VLESS-заголовка
            // (UUID/команда/адрес), сервер не мог опознать сессию и молчал: WS вставал,
            // «101 Switching Protocols» приходил, а данных не было вообще (ни одной
            // строки [VLESS RESP]). split-режим передаёт заголовок явно, mux — тоже;
            // ws был единственным, где его забыли.
            _vlessHeaderBuffer = BuildDirectVlessHeader();
            _ws = new WsTransport(_cfg);
            _wsEnabled = true;
            if (!await _ws.ConnectAsync()) { Close(); return false; }
            return true;
        }

        public async Task<bool> StartAsync()
        {
            try
            {
                if (_cfg.IsWs && _directMode)
                    return await StartWsAsync();
                // xhttp split-режимы (stream-up / packet-up) держат собственные
                // download/upload-соединения и НЕ трогают this.Socket. Диспатчим до открытия сокета.
                if (_cfg.IsXhttp && _directMode)
                {
                    var xmode = _cfg.ResolveXhttpMode();
                    bool configForbidsH2 = !string.IsNullOrEmpty(_cfg.Alpn) &&
                                           _cfg.Alpn.IndexOf("h2", StringComparison.OrdinalIgnoreCase) < 0;
                    if (UseH2Mux && !configForbidsH2 && !H2MuxRegistry.ServerRejectedH2)
                    {
                        if (await StartH2MuxAsync()) return true;
                        if (!H2MuxRegistry.ServerRejectedH2) return false;
                    }
                    if (xmode == XhttpTransportMode.PacketUp) return await StartSplitAsync(true);
                    if (xmode == XhttpTransportMode.StreamUp) return await StartSplitAsync(false);
                    // stream-one — проваливаемся в обычный путь ниже
                }

                if (_cfg.IsGrpc && _directMode)
                    return await StartH2MuxAsync();

                // Вариант B: xhttp stream-one direct → мультиплексируем через общий
                // Reality+H2 туннель вместо собственного сокета/хендшейка на этот flow.
                // (packet-up/stream-up уже отдиспатчены выше, значит здесь только stream-one.)
                if (UseH2Mux && _cfg.IsXhttp && _directMode)
                    return await StartH2MuxAsync();

                string targetHost = string.IsNullOrEmpty(VlessVpnPlugin.ServerIp)
                    ? _cfg.Address : VlessVpnPlugin.ServerIp;

                bool isReality = _cfg.Security.ToLower() == "reality";

                // security=tls поднимается тем же нашим стеком TLS 1.3: от REALITY он
                // отличается только ClientHello — без аутентификации в session_id и без
                // ожидания подменного сертификата. Системный TLS тут не годится: schannel
                // на телефоне идёт в сеть за проверкой цепочки, а сеть в этот момент уже
                // заведена в туннель, которого ещё нет.
                bool isPlainTls = _cfg.Security.ToLower() == "tls";

                // Reality-сервер под нагрузкой изредка «роняет» нас на прикрытие (amd.com)
                // вместо аутентификации. Раньше это обнаруживалось поздно (на статусе H2),
                // и всё соединение пересоздавалось приложением заново (новый SYN + новый
                // хендшейк) — видимый стопор. Теперь fallback детектируется рано (по реальному
                // CA-сертификату, см. RealityTls13Stream.ServerFellBack) и мы делаем быстрый
                // in-place повтор тем же путём. Ретраим ТОЛЬКО fallback (он быстрый — хендшейк
                // обрывается сразу по сертификату); реальный таймаут не ретраим, чтобы не
                // копить 3×8с. Никаких общих семафоров — только per-connection, поэтому той
                // HOL-регрессии с throttle тут быть не может.
                const int maxRealityAttempts = 3;
                for (int attempt = 1; ; attempt++)
                {
                    // Второе звено цепочки Amnezia работает не поверх TCP, а поверх
                    // уже поднятого туннеля до реле. Сокет тогда не нужен: writer и
                    // reader строятся над первым звеном. Ветка включается только при
                    // заданном ChainOuter, поэтому обычные профили её не проходят.
                    if (_chainOuter != null)
                    {
                        // Адрес берём из _cfg, а не из targetHost: тот подменяется
                        // глобальным ServerIp, который указывает на реле.
                        FileLog.Important($"[CHAIN] Второе звено: рукопожатие с {_cfg.Address}:{_cfg.Port} " +
                                          "поверх туннеля до реле.");
                        _writer = new DataWriter(new ChainOutputStream(_chainOuter));
                        _reader = new DataReader(new ChainInputStream(_chainOuter));
                        _reader.InputStreamOptions = InputStreamOptions.Partial;
                        _tcpRttMs = 0;

                        if (!isReality) break;

                        _realityStream = new RealityTls13Stream(_cfg);
                        var chainTask = _realityStream.EstablishHandshakeAsync(_writer, _reader);
                        bool chainTimedOut = await Task.WhenAny(chainTask, Task.Delay(12000)) != chainTask;
                        if (chainTimedOut || !await chainTask)
                        {
                            FileLog.Important(chainTimedOut
                                ? "[CHAIN ERROR] Второе рукопожатие REALITY не уложилось в 12с."
                                : "[CHAIN ERROR] Второе рукопожатие REALITY не удалось.");
                            Close();
                            return false;
                        }
                        FileLog.Important("[CHAIN] Второе рукопожатие REALITY прошло — цепочка поднята.");
                        break;
                    }

                    Socket = new StreamSocket();
                    Socket.Control.NoDelay = true;
                    Socket.Control.KeepAlive = true;

                    FileLog.W($"[VLESS CONN] Подключение к VLESS-серверу: {targetHost}:{_cfg.Port}"
                        + (attempt > 1 ? $" (повтор {attempt}/{maxRealityAttempts} после fallback)" : ""));

                    // Секундомер обязан стартовать ДО ConnectAsync: операция начинается
                    // в момент вызова, и запуск после него давал заниженное время
                    // вплоть до «0 мс» на соединениях, которые шли по 150 мс.
                    var swConnect = Stopwatch.StartNew();

                    Windows.Foundation.IAsyncAction connectOp;
                    if (VlessVpnPlugin.PhysicalIp != null)
                    {
                        var epp = new Windows.Networking.EndpointPair(
                            VlessVpnPlugin.PhysicalIp, "",
                            new HostName(targetHost), _cfg.Port.ToString());
                        connectOp = Socket.ConnectAsync(epp, SocketProtectionLevel.PlainSocket);
                    }
                    else
                    {
                        connectOp = Socket.ConnectAsync(new HostName(targetHost), _cfg.Port.ToString(),
                                                        SocketProtectionLevel.PlainSocket);
                    }

                    var connectTask = connectOp.AsTask();
                    if (await Task.WhenAny(connectTask, Task.Delay(8000)) != connectTask)
                    {
                        try { connectOp.Cancel(); } catch { }
                        FileLog.W("[VLESS CONN ERROR] Таймаут TCP-подключения (8с).");
                        Close();
                        return false;
                    }
                    await connectTask;
                    swConnect.Stop();
                    // Время до TCP пригождается при разборе логов: оно отделяет «сервер
                    // недоступен» от «TCP прошёл, но дальше по TLS тишина». Плюс это
                    // единственная доступная нам оценка RTT до сервера.
                    _tcpRttMs = swConnect.ElapsedMilliseconds;
                    FileLog.W($"[VLESS CONN] TCP установлен за {_tcpRttMs} мс.");

                    _writer = new DataWriter(Socket.OutputStream);
                    _reader = new DataReader(Socket.InputStream);
                    _reader.InputStreamOptions = InputStreamOptions.Partial;

                    if (!isReality && !isPlainTls)
                        break; // без шифрующего слоя ретраить нечего

                    _realityStream = new RealityTls13Stream(_cfg) { PlainTls = isPlainTls };

                    // Ждём очередь ДО запуска таймера: иначе соединение, простоявшее
                    // в очереди, отвалилось бы по таймауту, ни разу не выйдя в сеть.
                    await RealityTls13Stream.EnterHandshakeGateAsync();
                    bool timedOut, ok;
                    try
                    {
                        var handshakeTask = _realityStream.EstablishHandshakeAsync(_writer, _reader);
                        timedOut = await Task.WhenAny(handshakeTask, Task.Delay(8000)) != handshakeTask;
                        ok = !timedOut && await handshakeTask;
                    }
                    finally
                    {
                        RealityTls13Stream.LeaveHandshakeGate();
                    }
                    if (ok)
                        break; // хендшейк удался — выходим из цикла

                    if (timedOut)
                    {
                        // Молчание — это НЕ фолбэк: при фолбэке сервер прозрачно проксирует
                        // нас на сайт прикрытия и тот отвечает настоящим ServerHello. Полная
                        // тишина при поднятом TCP означает, что ClientHello до сервера не
                        // дошёл или ответ не вернулся (фильтрация по пути), либо сервер лёг.
                        _realityStream.AbortedByTimeout = true;
                        FileLog.W(_realityStream.ServerBytes == 0
                            ? "[REALITY TLS 1.3 ERROR] За 8с от сервера не пришло ни байта — ClientHello без ответа."
                            : $"[REALITY TLS 1.3 ERROR] Хендшейк не уложился в 8с, получено {_realityStream.ServerBytes} б.");
                    }

                    bool quickRetryable = _realityStream.ServerFellBack || _realityStream.AlertBeforeServerHello;
                    if (quickRetryable && attempt < maxRealityAttempts)
                    {
                        FileLog.W(_realityStream.AlertBeforeServerHello
                            ? $"[VLESS CONN] Alert вместо ServerHello на попытке {attempt} — быстрый повтор."
                            : $"[VLESS CONN] Reality fallback на попытке {attempt} — быстрый повтор.");
                        try { _writer?.Dispose(); } catch { }
                        try { _reader?.Dispose(); } catch { }
                        try { Socket?.Dispose(); } catch { }
                        _writer = null; _reader = null; Socket = null; _realityStream = null;
                        continue;
                    }

                    FileLog.W(_realityStream.AlertBeforeServerHello
                        ? $"[VLESS CONN ERROR] Alert вместо ServerHello — исчерпаны попытки ({maxRealityAttempts})."
                        : _realityStream.ServerFellBack
                        ? $"[VLESS CONN ERROR] Reality fallback — исчерпаны попытки ({maxRealityAttempts})."
                        : timedOut
                            ? "[VLESS CONN ERROR] Таймаут Reality handshake (8с) — сервер не ответил."
                            : "[VLESS CONN ERROR] Сбой Reality handshake.");
                    Close();
                    return false;
                }

                _handshakeDoneUtc = DateTime.UtcNow;

                // vision работает только на raw TCP в direct-режиме (не ws/xhttp)
                _visionEnabled = _cfg.IsVision && _directMode;
                if (_visionEnabled)
                    FileLog.Important("[VISION] xtls-rprx-vision активирован (flow в заголовке + padding-обёртка).");

                using (var ms = new MemoryStream())
                {
                    ms.WriteByte(0x00);
                    Guid guid = Guid.Empty;
                    Guid.TryParse(_cfg.Uuid, out guid);
                    _uuidBytes = GuidToNetworkBytes(guid);
                    ms.Write(_uuidBytes, 0, 16);

                    if (_visionEnabled)
                    {
                        // addon: тип 0x0a (flow как строковое поле) + длина + значение
                        byte[] flowBytes = Encoding.ASCII.GetBytes(_cfg.Flow);
                        ms.WriteByte((byte)(2 + flowBytes.Length)); // длина блока addon
                        ms.WriteByte(0x0a);
                        ms.WriteByte((byte)flowBytes.Length);
                        ms.Write(flowBytes, 0, flowBytes.Length);
                        // Состояние TLS-фильтра общее на соединение: версию сайта
                        // видит нисходящий поток, а решает по ней восходящий.
                        var visionState = new VisionTrafficState();
                        _visionWrap = new VisionWrap(_uuidBytes, visionState);
                        _visionUnpad = new VisionUnpad(_uuidBytes, visionState);
                    }
                    else
                    {
                        ms.WriteByte(0x00); // addon len = 0
                    }
                    ms.WriteByte(0x01); // cmd = TCP

                    if (_directMode)
                    {
                        ms.WriteByte((byte)(_directPort >> 8));
                        ms.WriteByte((byte)(_directPort & 0xFF));
                        ms.WriteByte(_directAddrType);
                        if (_directAddrType == 0x02)
                        {
                            byte[] d = Encoding.UTF8.GetBytes(_directDomain);
                            ms.WriteByte((byte)d.Length);
                            ms.Write(d, 0, d.Length);
                        }
                        else
                        {
                            ms.Write(_directAddr, 0, _directAddr.Length);
                        }
                    }
                    else
                    {
                        // MUX: порт 9527, домен v1.mux.cool 
                        ms.WriteByte((byte)(9527 >> 8));
                        ms.WriteByte((byte)(9527 & 0xFF));
                        ms.WriteByte(0x02);
                        byte[] hostBytes = Encoding.UTF8.GetBytes("v1.mux.cool");
                        ms.WriteByte((byte)hostBytes.Length);
                        ms.Write(hostBytes, 0, hostBytes.Length);
                    }

                    _vlessHeaderBuffer = ms.ToArray();
                }

                if (_cfg.IsXhttp)
                {
                    string alpn = _realityStream != null ? _realityStream.NegotiatedAlpn : "";
                    bool forceH1 = string.Equals(alpn, "http/1.1", StringComparison.OrdinalIgnoreCase);

                    if (!forceH1)
                    {
                        FileLog.Important($"[XHTTP] Транспорт: HTTP/2 (stream-one). ALPN='{(string.IsNullOrEmpty(alpn) ? "<нет>" : alpn)}'.");
                        if (!await StartH2Async()) { Close(); return false; }
                    }
                    else
                    {
                        FileLog.Important("[XHTTP] Транспорт: HTTP/1.1 (stream-one) — сервер явно выбрал http/1.1.");
                        _xhttp = new XhttpStreamOne(_cfg);
                        _xhttpEnabled = true;
                        if (!await StartXhttpStreamOneAsync()) { Close(); return false; }
                    }
                }
                else
                {
                    FileLog.Important($"[VLESS CONN] Транспорт: стандартный {_cfg.Type} (без xhttp-обертки).");
                }

                return true;
            }
            catch (Exception ex)
            {
                FileLog.W($"[VLESS MUX CONN ERROR] {ex.Message}");
                Close();
                return false;
            }
        }

        private async System.Threading.Tasks.Task WriteRawAsync(byte[] data)
        {
            byte[] toSend = _realityStream != null ? _realityStream.EncryptRecord(data) : data;
            EnsureOutStream();
            _outStream.Write(toSend, 0, toSend.Length);
            await _outStream.FlushAsync();
        }

        private async System.Threading.Tasks.Task WriteRawSerializedAsync(byte[] data)
        {
            if (data == null || data.Length == 0) return;
            await _rawWriteLock.WaitAsync();
            try { await WriteRawAsync(data); }
            finally { _rawWriteLock.Release(); }
        }

        // Вариант B: получаем H2-стрим из общего мультиплексированного туннеля.
        // Собственный сокет/reality/H2 для этого flow НЕ открываем.
        private async System.Threading.Tasks.Task<bool> StartH2MuxAsync()
        {
            try
            {
                _vlessHeaderBuffer = BuildDirectVlessHeader();
                _muxStream = await H2MuxRegistry.AcquireStreamAsync(_cfg);
                if (_muxStream == null)
                {
                    FileLog.Important("[H2MUX] Не удалось получить стрим (туннель не поднялся).");
                    return false;
                }
                _muxEnabled = true;
                FileLog.Important($"[H2MUX] {(_cfg.IsGrpc ? "grpc" : "xhttp " + _cfg.EffectiveXhttpMode)} через общий туннель, H2 sid={_muxStream.Id}" +
                                  (string.IsNullOrEmpty(_muxStream.SessionId) ? "." : $", session={_muxStream.SessionId}."));
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[H2MUX ERROR] StartH2Mux: {ex.Message}");
                return false;
            }
        }

        private async System.Threading.Tasks.Task<bool> StartH2Async()
        {
            try
            {
                _h2 = new Http2Conn(_cfg);
                _h2Enabled = true;

                await WriteRawSerializedAsync(_h2.BuildClientHandshake());
                await WriteRawSerializedAsync(_h2.BuildHeaders());

                FileLog.Important("[H2] preface+SETTINGS+HEADERS отправлены (stream 1). Ответ читаем лениво.");
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[H2 ERROR] StartH2: {ex.Message}");
                return false;
            }
        }

        private async System.Threading.Tasks.Task<bool> StartXhttpStreamOneAsync()
        {
            try
            {
                byte[] head = _xhttp.BuildRequestHead();
                FileLog.Important("[XHTTP] >>> Отправка POST stream-one:\r\n" + Encoding.ASCII.GetString(head));
                await WriteRawAsync(head);
                FileLog.Important("[XHTTP] POST-заголовок отправлен.");

                if (!_directMode)
                {
                    byte[] ka = new byte[6];
                    ka[1] = 4;
                    ka[4] = 0x04;
                    await WriteUnderlyingAsync(ka);
                }
                return true;
            }
            catch (Exception ex)
            {
                FileLog.Important($"[XHTTP ERROR] StartXhttpStreamOne: {ex.Message}");
                return false;
            }
        }

        public async System.Threading.Tasks.Task WriteUnderlyingAsync(byte[] data)
        {
            // Гонка: ОС может закрыть локальный сокет, пока идёт StartAsync, и очередь
            // отправки дописывает данные уже в освобождённые объекты. Раньше это вылезало
            // как Arg_NullReferenceException / ObjectDisposed_Generic в логе и выглядело
            // ошибкой протокола, хотя соединения просто уже не было.
            if (_closed) return;

            if (_muxEnabled)
            {
                byte[] payload;
                if (!_vlessHeaderSent)
                {
                    _vlessHeaderSent = true;
                    int hl = _vlessHeaderBuffer.Length;
                    payload = new byte[hl + (data?.Length ?? 0)];
                    System.Buffer.BlockCopy(_vlessHeaderBuffer, 0, payload, 0, hl);
                    if (data != null && data.Length > 0)
                        System.Buffer.BlockCopy(data, 0, payload, hl, data.Length);
                }
                else
                {
                    payload = data ?? new byte[0];
                }
                await _muxStream.WriteAsync(payload);
                return;
            }
            if (_wsEnabled)
            {
                byte[] payload = data ?? new byte[0];
                if (_vlessHeaderBuffer != null)
                {
                    byte[] c = new byte[_vlessHeaderBuffer.Length + payload.Length];
                    System.Buffer.BlockCopy(_vlessHeaderBuffer, 0, c, 0, _vlessHeaderBuffer.Length);
                    if (payload.Length > 0)
                        System.Buffer.BlockCopy(payload, 0, c, _vlessHeaderBuffer.Length, payload.Length);
                    payload = c;
                    _vlessHeaderBuffer = null;
                }
                await _ws.SendAsync(payload);
                return;
            }
            if (_splitEnabled) { await _split.WriteUpAsync(data); return; }
            if (_h2Enabled)
            {
                byte[] payload;
                if (!_vlessHeaderSent)
                {
                    _vlessHeaderSent = true;
                    int hl = _vlessHeaderBuffer.Length;
                    payload = new byte[hl + (data?.Length ?? 0)];
                    System.Buffer.BlockCopy(_vlessHeaderBuffer, 0, payload, 0, hl);
                    if (data != null && data.Length > 0)
                        System.Buffer.BlockCopy(data, 0, payload, hl, data.Length);
                }
                else
                {
                    payload = data ?? new byte[0];
                }

                int off = 0;
                int maxFrame = Math.Min(_h2.PeerMaxFrame, 16384);
                if (maxFrame <= 0) maxFrame = 16384;

                while (off < payload.Length)
                {
                    if (_h2.StreamClosed) return;
                    int piece = Math.Min(payload.Length - off, maxFrame);

                    bool stalledLogged = false;
                    while (!_h2.TryReserveSend(piece))
                    {
                        if (_h2.StreamClosed) return;
                        if (!stalledLogged)
                        {
                            stalledLogged = true;
                            FileLog.Important($"[H2 TX] upload ждёт окна отправки (нужно {piece}b) — backpressure сервера");
                        }
                        await _h2.WaitWindowAsync();
                    }

                    byte[] frame = _h2.FrameData(payload, off, piece, false);
                    await WriteRawSerializedAsync(frame);
                    off += piece;
                }

                if (FileLog.Verbose) FileLog.W($"[H2 TX] {payload.Length}b (stream 1)");
                return;
            }

            // xtls-rprx-vision: заголовок (один раз) + vision-обёрнутая полезная
            // нагрузка. Полезная нагрузка режется на блоки ≤8192 (как в senko),
            // чтобы каждый vision-блок с учётом паддинга помещался в одну TLS-запись.
            // После выхода из padding-режима Wrap отдаёт данные «сырыми».
            if (_visionEnabled)
            {
                byte[] payload = data ?? new byte[0];
                var outMs = new MemoryStream();
                bool first = !_visionFirstSent;
                byte[] hdr = null;
                if (first)
                {
                    _visionFirstSent = true;
                    hdr = _vlessHeaderBuffer ?? new byte[0];
                    _vlessHeaderBuffer = null;
                }

                if (payload.Length == 0)
                {
                    // только на первом вызове без данных отправляем header + bootstrap
                    if (first)
                    {
                        byte[] boot = _visionWrap.Bootstrap();
                        AppendVisionEncrypted(outMs, hdr, boot);
                    }
                }
                else
                {
                    // Симметрично приёму: после того как мы отправили DIRECT, узел
                    // ждёт сырой поток и больше не расшифровывает уплинк своим
                    // REALITY. Продолжая шифровать, мы отдавали ему криптограмму
                    // вместо TLS сайта — выходной узел отвечал alert 20
                    // (bad_record_mac). На END это не распространяется: там внешний
                    // TLS остаётся, поэтому проверяем именно DirectSent.
                    if (_visionWrap.DirectSent)
                    {
                        outMs.Write(payload, 0, payload.Length);
                    }
                    else
                    {
                        const int VisionChunk = 8192;
                        for (int off = 0; off < payload.Length; off += VisionChunk)
                        {
                            int n = Math.Min(VisionChunk, payload.Length - off);
                            byte[] chunk = new byte[n];
                            System.Buffer.BlockCopy(payload, off, chunk, 0, n);
                            byte[] blk = _visionWrap.Wrap(chunk, n);
                            // header приклеиваем к самому первому исходящему блоку
                            byte[] pre = (first && off == 0) ? hdr : null;
                            AppendVisionEncrypted(outMs, pre, blk);
                        }
                    }
                }

                byte[] outAll = outMs.ToArray();
                if (outAll.Length == 0) return;
                EnsureOutStream();
                _outStream.Write(outAll, 0, outAll.Length);
                await _outStream.FlushAsync();
                // Первый запрос — единственное, что мы отправляем до ответа сервера.
                // Без этой строки в vision-режиме исходящий поток не логировался вовсе,
                // и «сервер молчит» было неотличимо от «мы ничего не отправили».
                if (first)
                {
                    _requestSentUtc = DateTime.UtcNow;
                    // Начало полезной нагрузки — это ClientHello браузера к самому сайту.
                    // Часть соединений сайт обрывает сразу после ServerHello, будто получил
                    // мусор; без дампа отличить «мы испортили» от «сайт сам так решил» нельзя.
                    int peek = Math.Min(48, payload.Length);
                    byte[] head = new byte[peek];
                    System.Buffer.BlockCopy(payload, 0, head, 0, peek);
                    FileLog.Important($"[VISION TX] Запрос отправлен: заголовок {hdr?.Length ?? 0}б + " +
                                      $"данные {payload.Length}б, cmd={_visionWrap.LastCommand}, " +
                                      $"итого {outAll.Length}б в TLS. Начало данных: " +
                                      CryptoSelfTest.BytesToHex(head));
                }
                return;
            }

            byte[] toSend = data ?? new byte[0];
            if (_vlessHeaderBuffer != null)
            {
                byte[] combined = new byte[_vlessHeaderBuffer.Length + toSend.Length];
                System.Buffer.BlockCopy(_vlessHeaderBuffer, 0, combined, 0, _vlessHeaderBuffer.Length);
                if (toSend.Length > 0)
                    System.Buffer.BlockCopy(toSend, 0, combined, _vlessHeaderBuffer.Length, toSend.Length);
                toSend = combined;
                _vlessHeaderBuffer = null;
            }

            if (FileLog.Verbose)
            {
                if (_directMode) FileLog.W($"[DIRECT TX] payload {toSend.Length}b");
                else FileLog.W($"[NAT->VLESS] {SummarizeMux(toSend)}");
            }

            if (_xhttpEnabled)
            {
                toSend = _xhttp.WrapChunk(toSend);
            }

            if (_realityStream != null) toSend = _realityStream.EncryptRecord(toSend);

            EnsureOutStream();
            _outStream.Write(toSend, 0, toSend.Length);
            await _outStream.FlushAsync();
        }

        // Склеивает необязательный префикс (VLESS-заголовок) с vision-блоком,
        // шифрует под reality (одна TLS-запись) и дописывает в буфер отправки.
        private void AppendVisionEncrypted(MemoryStream dst, byte[] prefix, byte[] block)
        {
            int pl = prefix?.Length ?? 0;
            int bl = block?.Length ?? 0;
            if (pl == 0 && bl == 0) return;
            byte[] plain = new byte[pl + bl];
            if (pl > 0) System.Buffer.BlockCopy(prefix, 0, plain, 0, pl);
            if (bl > 0) System.Buffer.BlockCopy(block, 0, plain, pl, bl);
            byte[] enc = _realityStream != null ? _realityStream.EncryptRecord(plain) : plain;
            dst.Write(enc, 0, enc.Length);
        }

        private async Task<bool> ReadExactAsync(uint count)
        {
            try
            {
                uint loaded = _reader.UnconsumedBufferLength;
                while (loaded < count)
                {
                    uint bytesRead = await _reader.LoadAsync(count - loaded);
                    // Ноль байт — это корректный FIN: соединение закрыла программа на той
                    // стороне. Исключение — это RST или обрыв: так выглядит вмешательство
                    // по пути. Раньше оба случая сводились к одному «false».
                    if (bytesRead == 0) { _closeReason = "штатный FIN от узла"; return false; }
                    loaded += bytesRead;
                }
                return true;
            }
            catch (Exception ex)
            {
                // 0x800703E3 = ERROR_OPERATION_ABORTED: незавершённое чтение отменено
                // тем, что сокет закрыли С НАШЕЙ стороны. Это не сетевой обрыв, и
                // называть его «RST» значило врать в логе о причине.
                _closeReason = (uint)ex.HResult == 0x800703E3
                    ? "чтение отменено закрытием сокета с нашей стороны"
                    : "обрыв: " + ex.Message;
                return false;
            }
        }

        private async Task<byte[]> ReadTlsPlaintextAsync()
        {
            try
            {
                // После команды DIRECT узел перестаёт заворачивать нисходящий поток
                // в свой REALITY: в этом и смысл «X» в XTLS — дальше идёт сплайс, а
                // шифрование обеспечивает внутренний TLS. Продолжать расшифровку
                // нельзя, но и заметить это по заголовку невозможно: внутренние
                // записи выглядят точно так же — 17 03 03 <len>. Симптомом было
                // «Запись не расшифровалась» ровно после [VISION SW RX] DIRECT.
                if (_realityStream != null && _visionEnabled && _visionUnpad != null && _visionUnpad.RawSplice)
                {
                    uint got = await _reader.LoadAsync(16384);
                    if (got == 0) return null;
                    byte[] rawDirect = new byte[got];
                    _reader.ReadBytes(rawDirect);
                    return rawDirect;
                }

                if (_realityStream != null)
                {
                    while (true)
                    {
                        if (!await ReadExactAsync(5)) return null;
                        byte[] header = new byte[5];
                        _reader.ReadBytes(header);

                        byte recordType = header[0];
                        int len = (header[3] << 8) | header[4];
                        if (len <= 0) continue;

                        if (!await ReadExactAsync((uint)len)) return null;
                        byte[] payload = new byte[len];
                        _reader.ReadBytes(payload);

                        if (recordType == 20)
                        {
                            continue;
                        }

                        byte innerType;
                        byte[] plain = _realityStream.DecryptRecordExplicit(header, payload, out innerType);
                        if (plain == null)
                        {
                            // Две несовместимые причины отказа, и различить их можно
                            // только по байтам. Либо узел после vision-DIRECT перестал
                            // заворачивать поток в REALITY (тогда мы читаем как заголовок
                            // TLS то, что им не является, и заголовок будет мусорным),
                            // либо разошёлся счётчик AEAD (тогда заголовок правильный,
                            // а расшифровка всё равно не проходит).
                            int hn = Math.Min(16, payload.Length);
                            var ph = new byte[hn];
                            System.Buffer.BlockCopy(payload, 0, ph, 0, hn);
                            bool headerSane = (recordType == 0x17 || recordType == 0x16 ||
                                               recordType == 0x15 || recordType == 0x14)
                                              && header[1] == 0x03 && header[2] == 0x03;
                            FileLog.Important(
                                $"[TLS ERR] Запись не расшифровалась. Заголовок: {CryptoSelfTest.BytesToHex(header)}, " +
                                $"len={len}, начало тела: {CryptoSelfTest.BytesToHex(ph)}. " +
                                $"Цепочка={( _chainOuter != null ? "второе звено" : "обычное")}.");
                            // По заголовку различить «сырой поток после DIRECT» и
                            // рассинхрон счётчика нельзя: внутренние записи имеют
                            // такой же вид 17 03 03 <len>. Решает только состояние
                            // vision на момент отказа.
                            FileLog.Important(
                                $"[TLS ERR] vision: включён={_visionEnabled}, " +
                                $"downstream direct={(_visionUnpad != null && _visionUnpad.IsDirect)}. " +
                                (headerSane ? "Заголовок правдоподобный." : "Заголовок не похож на TLS."));
                            return null;
                        }

                        if (innerType == 23)
                        {
                            // Пустая application-запись — легальный TLS, её шлют как
                            // keep-alive/паддинг. Наверх её отдавать нельзя: вызывающий
                            // принимал пустой буфер за конец потока и рвал соединение,
                            // хотя сервер ничего не закрывал.
                            if (plain.Length == 0)
                            {
                                FileLog.W("[TLS] Пустая application-запись — пропускаю.");
                                continue;
                            }
                            return plain;
                        }
                        else
                        {
                            // Alert (21) — единственная причина, по которой сервер
                            // молча закрывает уже поднятый туннель. Его код и
                            // уровень надо видеть: без них «поток закрыт» и
                            // «нас выгнали» выглядят в логе одинаково.
                            if (innerType == 21 && plain.Length >= 2)
                            {
                                string level = plain[0] == 1 ? "warning" : plain[0] == 2 ? "fatal" : plain[0].ToString();
                                string desc = plain[1] == 0 ? "close_notify"
                                            : plain[1] == 49 ? "access_denied"
                                            : plain[1] == 80 ? "internal_error"
                                            : plain[1] == 40 ? "handshake_failure"
                                            : plain[1] == 90 ? "user_canceled"
                                            : "код " + plain[1];
                                FileLog.Important($"[TLS ALERT] Сервер прислал alert: {level} / {desc}.");
                            }
                            else
                            {
                                FileLog.W($"[TLS] Отсеяно служебное шифрованное TLS-сообщение (тип: {innerType})");
                            }
                        }
                    }
                }
                else
                {
                    uint bytesAvailable = await _reader.LoadAsync(16384);
                    if (bytesAvailable == 0) return null;
                    byte[] data = new byte[bytesAvailable];
                    _reader.ReadBytes(data);
                    return data;
                }
            }
            catch (Exception ex)
            {
                FileLog.W($"[TLS READ ERROR] {ex.Message}");
                return null;
            }
        }

        private async Task<byte[]> ReadUnderlyingRecordAsync()
        {
            if (_muxEnabled) return await _muxStream.ReadDownAsync();
            if (_wsEnabled) return await _ws.ReceiveAsync();
            if (_splitEnabled) return await _split.ReadDownAsync();
            if (_h2Enabled)
            {
                while (true)
                {
                    if (_h2PendingCredit > 0) { _h2.CreditConsumed(_h2PendingCredit); _h2PendingCredit = 0; }

                    byte[] pend = _h2.TakePending();
                    if (pend != null) await WriteRawSerializedAsync(pend);

                    if (_h2.HeadersDone && !_h2HeadStatusLogged)
                    {
                        _h2HeadStatusLogged = true;
                        FileLog.Important($"[H2] <<< :status {_h2.Status}");
                        if (_h2.Status != 200)
                        {
                            NetDiag.ReportHttp("H2", _h2.Status, "200 OK");
                            return null;
                        }
                        NetDiag.ClearError();
                        FileLog.Important("[H2] поток принят, читаю downstream DATA.");
                    }

                    byte[] d = _h2.Pull();
                    if (d != null && d.Length > 0) { _h2PendingCredit = d.Length; return d; }
                    if (_h2.StreamClosed) return null;

                    byte[] plain = await ReadTlsPlaintextAsync();
                    if (plain == null) return null;
                    _h2.Feed(plain);

                    byte[] p2 = _h2.TakePending();
                    if (p2 != null) await WriteRawSerializedAsync(p2);
                }
            }

            if (!_xhttpEnabled)
                return await ReadTlsPlaintextAsync();

            if (!_xhttpHeadParsed)
            {
                var deadline = DateTime.UtcNow.AddSeconds(15);
                while (true)
                {
                    byte[] plain = await ReadTlsPlaintextAsync();
                    if (plain == null)
                    {
                        NetDiag.Report("XHTTP", "сервер разорвал TLS до того, как прислал заголовки ответа");
                        return null;
                    }

                    if (_xhttp.TryConsumeResponseHead(plain, out string status, out var headers))
                    {
                        FileLog.Important($"[XHTTP] <<< {status}");
                        int xCode = NetDiag.ParseStatus(status);
                        if (xCode != 200)
                        {
                            NetDiag.ReportHttp("XHTTP", xCode, "200 OK");
                            return null;
                        }
                        NetDiag.ClearError();

                        _xhttp.ConfigureFromResponse(headers);
                        _xhttpHeadParsed = true;
                        FileLog.Important("[XHTTP] Заголовки приняты, читаю chunked downstream.");
                        break;
                    }

                    if (DateTime.UtcNow > deadline)
                    {
                        NetDiag.Report("XHTTP", "сервер не прислал заголовки ответа за 15 секунд");
                        return null;
                    }
                }
            }

            while (true)
            {
                byte[] outp = _xhttp.Pull();
                if (outp != null && outp.Length > 0) return outp;
                if (_xhttp.StreamClosed) return null;

                byte[] plain = await ReadTlsPlaintextAsync();
                if (plain == null) return null;
                _xhttp.Feed(plain);
            }
        }

        // Кадр HTTP/2 SETTINGS на нулевом стриме: длина(3) тип=0x04 флаги=0x00 stream=0.
        // Первым кадром его шлёт любой h2-сервер, в том числе сайт-прикрытия reality.
        private static bool LooksLikeHttp2Settings(List<byte> buf)
        {
            if (buf == null || buf.Count < 9) return false;
            if (buf[0] != 0x00 || buf[1] != 0x00) return false;   // кадр короче 64 КБ
            if (buf[3] != 0x04 || buf[4] != 0x00) return false;   // SETTINGS без флагов
            for (int i = 5; i < 9; i++) if (buf[i] != 0x00) return false;   // stream id = 0
            int len = buf[2];
            return len % 6 == 0;                                  // записи SETTINGS по 6 байт
        }

        public async Task<byte[]> ReadVlessPayloadAsync()
        {
            byte[] raw = await ReadUnderlyingRecordAsync();
            // Пустой буфер — это НЕ конец потока: транспорты возвращают его, когда данных
            // ещё нет (неполный заголовок, пустая TLS-запись). Концом потока считается
            // только null. Раньше пустой буфер убивал живое соединение.
            if (raw != null && raw.Length == 0) return new byte[0];

            if (raw == null)
            {
                // Ключевой замер: закрытие через ~один RTT ПОСЛЕ рукопожатия означает,
                // что сервер отверг нас ещё на Client Finished и наш запрос до него даже
                // не доехал. Закрытие через ~RTT после запроса — что дело в самом запросе.
                // По одному лишь факту обрыва эти два случая неразличимы.
                if (!_downClosedLogged && _handshakeDoneUtc != DateTime.MinValue)
                {
                    _downClosedLogged = true;
                    var now = DateTime.UtcNow;
                    string sinceReq = _requestSentUtc == DateTime.MinValue
                        ? "запрос ещё не отправляли"
                        : $"{(int)(now - _requestSentUtc).TotalMilliseconds} мс после запроса";
                    FileLog.Important($"[VLESS RX] Поток закрыт ({_closeReason}): " +
                        $"{(int)(now - _handshakeDoneUtc).TotalMilliseconds} мс после рукопожатия, " +
                        $"{sinceReq}, RTT TCP ~{_tcpRttMs} мс.");
                }
                return null;
            }

            byte[] output;

            if (!_headerStripped)
            {
                _receiveBuffer.AddRange(raw);
                if (_receiveBuffer.Count >= 2)
                {
                    int totalHeader = 2 + _receiveBuffer[1];
                    if (_receiveBuffer.Count >= totalHeader)
                    {
                        // Диагностика: первые байты нисходящего потока (VLESS-ответ-заголовок
                        // ver+addonlen, затем данные). Показывает, что реально пришло от сервера.
                        int dn = Math.Min(_receiveBuffer.Count, 16);
                        var hx = new StringBuilder();
                        for (int i = 0; i < dn; i++) hx.Append(_receiveBuffer[i].ToString("X2")).Append(' ');
                        FileLog.Important($"[VLESS RESP] ver={_receiveBuffer[0]} addonlen={_receiveBuffer[1]} hdr={totalHeader}b всего={_receiveBuffer.Count}b hex: {hx}");

                        // Последний рубеж: сайт-прикрытие отвечает по HTTP/2, и его SETTINGS-кадр
                        // начинается с 00 00 — ровно как валидный VLESS-заголовок (ver=0, addonlen=0).
                        // Без этой проверки два байта кадра съедались как заголовок, а сдвинутый
                        // мусор уходил в браузер (в адресной строке — «dяяяя» вместо страницы).
                        if (LooksLikeHttp2Settings(_receiveBuffer))
                        {
                            FileLog.Important("[VLESS RESP] Это HTTP/2-кадр SETTINGS, а не ответ VLESS: " +
                                              "мы разговариваем с сайтом-прикрытием, туннеля нет. " +
                                              "Проверьте pbk/sid в ссылке и часы устройства.");
                            return null;
                        }

                        byte[] leftover = _receiveBuffer.Skip(totalHeader).ToArray();
                        _receiveBuffer.Clear();
                        _headerStripped = true;
                        output = leftover;
                    }
                    else return new byte[0];
                }
                else return new byte[0];
            }
            else
            {
                output = raw;
            }

            // Снятие vision-обёртки с нисходящего потока (устойчиво к серверам,
            // которые downstream не паддят — тогда сразу direct passthrough).
            if (_visionEnabled && _visionUnpad.NeedsProcessing && output.Length > 0)
            {
                bool switchedDirect;
                output = _visionUnpad.Unpad(output, output.Length, out switchedDirect);
                if (switchedDirect)
                    FileLog.Important("[VISION] downstream → direct passthrough.");

                // Ответ на проверку цепочки: если реле пропустило IP-назначение,
                // здесь придёт ServerHello выходного узла (16 03 03 ...).
                if (_isChainProbe && output.Length > 0)
                {
                    int n = Math.Min(32, output.Length);
                    var head = new byte[n];
                    System.Buffer.BlockCopy(output, 0, head, 0, n);
                    bool looksTls = output.Length >= 3 && output[0] == 0x16 && output[1] == 0x03;
                    FileLog.Important($"[CHAIN PROBE] От выходного узла пришло {output.Length}б. " +
                                      $"Начало: {CryptoSelfTest.BytesToHex(head)}");
                    FileLog.Important(looksTls
                        ? "[CHAIN PROBE] Это TLS-рукопожатие — реле ПРОПУСКАЕТ трафик до выходного узла, цепочка реализуема."
                        : "[CHAIN PROBE] На TLS не похоже — разбирать нужно по этим байтам.");
                    _isChainProbe = false;
                }
                // Связывать направления, как делает senko (request_upstream_direct
                // на downstream DIRECT), оказалось нельзя: в xray они независимы.
                // На TLS 1.2 сервер закрывает нисходящую обёртку командой END рано,
                // и по этому сигналу мы снимали паддинг с восходящего потока, так и
                // не отправив завершающий блок — сервер продолжал ждать заголовок
                // vision и разбирал сырые TLS-записи как команду с длинами.
            }

            if (output.Length > 0 && FileLog.Verbose)
            {
                if (_directMode)
                {
                    int n = Math.Min(output.Length, 32);
                    var sb = new StringBuilder();
                    for (int i = 0; i < n; i++) sb.Append(output[i].ToString("X2")).Append(' ');
                    FileLog.W($"[VLESS->NAT DIRECT] {output.Length}b: {sb}");
                }
                else
                {
                    FileLog.W($"[VLESS->NAT] {SummarizeMux(output)}");
                }
            }
            return output;
        }

        private static string SummarizeMux(byte[] d)
        {
            if (d == null || d.Length < 6) return $"[{d?.Length ?? 0}b]";
            int metaLen = (d[0] << 8) | d[1];
            if (metaLen < 4 || d.Length < 2 + metaLen) return $"[{d.Length}b неполн]";
            ushort sid = (ushort)((d[2] << 8) | d[3]);
            byte status = d[4], opt = d[5];
            string st = status == 1 ? "New" : status == 2 ? "Keep" : status == 3 ? "End" : status == 4 ? "KeepAlive" : $"?{status}";
            int pay = ((opt & 1) != 0 && d.Length >= 4 + metaLen) ? (d[2 + metaLen] << 8) | d[2 + metaLen + 1] : 0;
            return $"sid={sid} {st} data={pay}b ({d.Length}b всего)";
        }

        public void Close() { _closed = true; try { _muxStream?.Close(); } catch { }; try { _writer?.Dispose(); _reader?.Dispose(); Socket?.Dispose(); } catch { }; try { _outStream?.Dispose(); } catch { }; try { _split?.Close(); } catch { }; try { _ws?.Close(); } catch { } }
    }
}
