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
    internal class RealityTls13Stream
    {
        private VlessConfig _cfg;
        private DataWriter _writer;
        private DataReader _reader;

        // Параметры выбранного сервером шифра (заполняются в ParseServerHello).
        private bool _sha384;      // 0x1302 → SHA-384 в KDF/транскрипте
        private int _aesKeyLen = 16; // 16 для AES-128-GCM, 32 для AES-256-GCM и ChaCha20
        private bool _chacha;      // 0x1303 → ChaCha20-Poly1305 вместо AES-GCM

        private byte[] _clientPrivate, _clientPublic, _clientRandom, _realityAuthKey;
        private List<byte> _transcript = new List<byte>();
        private byte[] _handshakeSecret, _clientHandshakeTrafficSecret, _serverHandshakeTrafficSecret;
        private byte[] _clientHandshakeKey, _clientHandshakeIv, _serverHandshakeKey, _serverAppIv;
        private byte[] _clientAppKey, _clientAppIv, _serverAppKey, _serverHandshakeIv;
        private ulong _writeSeq = 0, _readSeq = 0;

        private CryptographicKey _clientAppCryptoKey;
        private CryptographicKey _serverAppCryptoKey;
        public bool OfferH1Only = false;

        // Обычный TLS 1.3 без reality-аутентификации: в legacy_session_id пишем случайные
        // байты вместо зашифрованного auth-блока. Нужен для ws+tls: системный
        // UpgradeToSslAsync на W10M виснет намертво (проверка цепочки лезет за OCSP/CRL в сеть,
        // а та идёт в ещё не поднятый туннель — взаимная блокировка; плюс schannel умеет
        // максимум TLS 1.2, а сервер может быть TLS 1.3-only). Свой стек от ОС не зависит.
        public bool PlainTls = false;

        public string NegotiatedAlpn { get; private set; } = "";

        public RealityTls13Stream(VlessConfig config) { _cfg = config; }

        // Сколько байт всего пришло от сервера за хендшейк. Ноль при обрыве означает, что
        // ClientHello остался без ответа — сервер молчит. Это принципиально иная картина,
        // чем reality-фолбэк: тот отвечает настоящим ServerHello с сайта прикрытия.
        public int ServerBytes { get; private set; }

        // Ставится вызывающим перед Close() по своему таймауту: без этого наш же обрыв
        // сокета выглядел в логе как разрыв со стороны сервера.
        public bool AbortedByTimeout;

        // Сервер ответил на ClientHello фатальным alert'ом вместо ServerHello.
        // Ошибка ранняя и дешёвая (один RTT), поэтому её, как и fallback, имеет
        // смысл переигрывать новым соединением, а не ронять запрос целиком.
        public bool AlertBeforeServerHello;
        private byte[] _lastClientHello;

        // Общий на процесс: эталонный ClientHello пишем ровно один раз, иначе он
        // засорит лог на каждом соединении.
        private static int _goodChLogged;

        private async Task<bool> ReadExactAsync(uint count)
        {
            try
            {
                uint loaded = _reader.UnconsumedBufferLength;
                while (loaded < count)
                {
                    uint bytesRead = await _reader.LoadAsync(count - loaded);
                    if (bytesRead == 0) return false;
                    loaded += bytesRead;
                    ServerBytes += (int)bytesRead;
                }
                return true;
            }
            catch { return false; }
        }

        private ushort NextGrease()
        {
            byte[] r = Tls13Crypto.RandomBytes(1);
            byte b = (byte)((r[0] & 0xF0) | 0x0A); // валидный GREASE-паттерн 0x?a?a
            return (ushort)((b << 8) | b);
        }

        private byte[] BuildAlpnList()
        {
            byte[] protos = (_cfg != null && _cfg.IsGrpc)
                ? new byte[] { 2, (byte)'h', (byte)'2' }
                : (OfferH1Only
                    ? new byte[] { 8, (byte)'h', (byte)'t', (byte)'t', (byte)'p', (byte)'/', (byte)'1', (byte)'.', (byte)'1' }
                    : new byte[] { 2, (byte)'h',(byte)'2',
                                   8, (byte)'h',(byte)'t',(byte)'t',(byte)'p',(byte)'/',(byte)'1',(byte)'.',(byte)'1' });
            byte[] list = new byte[protos.Length + 2];
            list[0] = (byte)(protos.Length >> 8);
            list[1] = (byte)(protos.Length & 0xFF);
            System.Buffer.BlockCopy(protos, 0, list, 2, protos.Length);
            return list;
        }

        // Рукопожатие REALITY почти целиком упирается в счёт: X25519, HKDF, AES-GCM,
        // проверка подписи. На телефоне это сотни миллисекунд, и когда страница разом
        // открывает десяток соединений (speedtest опрашивает дюжину серверов Ookla),
        // они начинают толкаться: в логе одно рукопожатие растягивалось до 8.4 с, из
        // них 2.3 с — до отправки ClientHello, то есть чистый локальный счёт.
        // Суммарной работы очередь не убавляет, но первые соединения получаются
        // готовыми за свои честные полсекунды вместо того, чтобы все ползли разом.
        private static readonly System.Threading.SemaphoreSlim HandshakeGate =
            new System.Threading.SemaphoreSlim(2, 2);

        public static async Task EnterHandshakeGateAsync()
        {
            if (HandshakeGate.Wait(0)) return;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            await HandshakeGate.WaitAsync();
            FileLog.W($"[REALITY GATE] Ожидание очереди рукопожатий: {sw.ElapsedMilliseconds} мс.");
        }

        public static void LeaveHandshakeGate()
        {
            try { HandshakeGate.Release(); } catch { }
        }

        public async Task<bool> EstablishHandshakeAsync(DataWriter writer, DataReader reader)
        {
            _writer = writer;
            _reader = reader;

            FileLog.W("[REALITY TLS 1.3] === Старт Reality рукопожатия ===");

            _clientPrivate = Curve25519.CreateRandomPrivateKey();
            _clientPublic = Curve25519.GetPublicKey(_clientPrivate);
            _clientRandom = Tls13Crypto.RandomBytes(32);

            FileLog.W($"[REALITY TLS 1.3] Ключ X25519 клиента: {CryptoSelfTest.BytesToHex(_clientPublic)}");

            byte[] clientHello = BuildRealityClientHello();
            _transcript.AddRange(clientHello);

            byte[] record = new byte[clientHello.Length + 5];
            record[0] = 22; // Handshake
            record[1] = 3; record[2] = 1; // TLS 1.0 (совместимость)
            record[3] = (byte)(clientHello.Length >> 8);
            record[4] = (byte)(clientHello.Length & 0xFF);
            System.Buffer.BlockCopy(clientHello, 0, record, 5, clientHello.Length);

            FileLog.W($"[REALITY TLS 1.3] Отправка ClientHello ({record.Length} байт) с SNI: {_cfg.Sni}...");
            try
            {
                _lastClientHello = record;
                _writer.WriteBytes(record);
                uint stored = await _writer.StoreAsync();
                // Сервер изредка отвечает на ClientHello фатальным decode_error, хотя
                // сама запись собирается одинаково и всегда одной длины. Первое, что
                // стоит исключить, — неполная запись в сокет: её результат мы до сих
                // пор не проверяли вовсе.
                if (stored != (uint)record.Length)
                    FileLog.Important($"[REALITY TLS 1.3] ВНИМАНИЕ: ClientHello записан не полностью — " +
                                      $"{stored} из {record.Length} б.");
                FileLog.W("[REALITY TLS 1.3] ClientHello отправлен.");
            }
            catch (Exception ex)
            {
                FileLog.W($"[REALITY TLS 1.3 ERROR] Сбой отправки ClientHello: {ex.Message}");
                return false;
            }

            FileLog.W("[REALITY TLS 1.3] Ожидание ServerHello...");
            byte[] serverHelloPayload = null;
            while (true)
            {
                var rec = await ReadNextRecordAsync();
                if (rec == null)
                {
                    FileLog.W(AbortedByTimeout
                        ? $"[REALITY TLS 1.3 ERROR] Чтение прервано нашим таймаутом. От сервера получено {ServerBytes} б."
                        : $"[REALITY TLS 1.3 ERROR] Соединение разорвано во время ожидания ServerHello (получено {ServerBytes} б).");
                    return false;
                }

                if (rec.Item1 == 20)
                {
                    FileLog.W("[REALITY TLS 1.3] Пропущен нешифрованный ChangeCipherSpec (тип 20)");
                    continue;
                }
                if (rec.Item1 == 21)
                {
                    // Alert вместо ServerHello — сервер не смог разобрать наш ClientHello
                    // (0232 = fatal/decode_error). Запись собирается одинаково и всегда
                    // ровно 521 б, а падает лишь часть попыток, поэтому дампим именно
                    // отвергнутый экземпляр: сравнение с удачным покажет, что плавает.
                    AlertBeforeServerHello = true;
                    FileLog.W($"[REALITY TLS 1.3 ERROR] Получен Alert-код ошибки: {CryptoSelfTest.BytesToHex(rec.Item3)}");
                    if (_lastClientHello != null)
                        FileLog.Important("[REALITY CH] Отвергнутый ClientHello: " +
                                          CryptoSelfTest.BytesToHex(_lastClientHello));
                    return false;
                }
                if (rec.Item1 == 22)
                {
                    serverHelloPayload = rec.Item3;
                    FileLog.W("[REALITY TLS 1.3] Получен ServerHello!");
                    // Эталон для сравнения с отвергнутыми: запись собирается одинаково
                    // и всегда 521 б, поэтому побайтовый diff удачной с неудачной сразу
                    // покажет, какое из случайных полей сервер не переваривает.
                    if (_lastClientHello != null &&
                        System.Threading.Interlocked.Exchange(ref _goodChLogged, 1) == 0)
                        FileLog.Important("[REALITY CH] Принятый ClientHello: " +
                                          CryptoSelfTest.BytesToHex(_lastClientHello));
                    break;
                }
            }

            FileLog.W("[REALITY TLS 1.3] Парсинг ServerHello и извлечение Server Share...");
            byte[] serverShare = ParseServerHello(serverHelloPayload);
            if (serverShare == null)
            {
                FileLog.W("[REALITY TLS 1.3 ERROR] Не найден Server Share (публичный ключ X25519 сервера)!");
                return false;
            }
            FileLog.W($"[REALITY TLS 1.3] Публичный ключ сервера (Server Share): {CryptoSelfTest.BytesToHex(serverShare)}");
            _transcript.AddRange(serverHelloPayload);

            FileLog.W("[REALITY TLS 1.3] Вычисление общего секрета X25519 и генерация Handshake-ключей...");
            DeriveHandshakeKeys(serverShare);

            bool gotServerFinished = false;
            List<byte> hsBuf = new List<byte>();

            FileLog.W("[REALITY TLS 1.3] Чтение зашифрованных сообщений сервера...");
            while (!gotServerFinished)
            {
                var plain = await ReadEncryptedRecordAsync(false);
                if (plain == null)
                {
                    FileLog.W("[REALITY TLS 1.3 ERROR] Сбой чтения или расшифровки записи сервера.");
                    return false;
                }
                if (plain.Item1 == 21)
                {
                    FileLog.W("[REALITY TLS 1.3 ERROR] Получена зашифрованная Alert-ошибка от сервера.");
                    return false;
                }
                if (plain.Item1 != 22)
                {
                    FileLog.W($"[REALITY TLS 1.3] Пропущена TLS-запись типа {plain.Item1}");
                    continue;
                }

                hsBuf.AddRange(plain.Item2);
                while (hsBuf.Count >= 4)
                {
                    byte hsType = hsBuf[0];
                    int hsLen = (hsBuf[1] << 16) | (hsBuf[2] << 8) | hsBuf[3];
                    int total = 4 + hsLen;
                    if (hsBuf.Count < total) break;

                    byte[] hsMsg = hsBuf.Take(total).ToArray();
                    hsBuf.RemoveRange(0, total);

                    FileLog.W($"[REALITY TLS 1.3] Расшифровано Handshake-сообщение. Тип: {hsType}, Длина: {hsLen} байт");

                    if (hsType == 8) // EncryptedExtensions (RFC 8446: ALPN в TLS 1.3 передаётся здесь, а не в ServerHello)
                        ParseEncryptedExtensions(hsMsg);
                    if (hsType == 11) // Certificate
                    {
                        InspectServerCertificate(hsMsg);
                        if (ServerFellBack)
                        {
                            FileLog.W("[REALITY TLS 1.3] Fallback (реальный сертификат) — обрываю хендшейк для быстрого повтора.");
                            return false;
                        }
                    }
                    else if (hsType == 25 && !PlainTls) // compressed_certificate (RFC 8879)
                    {
                        // Мы не объявляем compress_certificate, значит сжать сертификат мог
                        // только тот, кто нас не аутентифицировал: reality-сервер отдаёт
                        // обычный тип 11. Разобрать такой сертификат нечем, поэтому считаем
                        // это фолбэком — иначе туннеля нет, а клиент этого не замечает.
                        FileLog.Important("[REALITY TLS 1.3] Сервер прислал СЖАТЫЙ сертификат (тип 25) — " +
                                          "это не reality-сервер, а сайт-прикрытие. Считаю фолбэком.");
                        ServerFellBack = true;
                        return false;
                    }

                    if (hsType == 20) // Finished
                    {
                        FileLog.W("[REALITY TLS 1.3] Проверка подписи Server Finished...");
                        if (!VerifyServerFinished(hsMsg))
                        {
                            FileLog.W("[REALITY TLS 1.3 ERROR] КРИТИЧЕСКАЯ ОШИБКА: Верификация Server Finished ПРОВАЛЕНА!");
                            return false;
                        }
                        FileLog.W("[REALITY TLS 1.3] Подпись Server Finished верна!");
                        _transcript.AddRange(hsMsg);
                        gotServerFinished = true;
                        break;
                    }
                    _transcript.AddRange(hsMsg);
                }
            }

            FileLog.W("[REALITY TLS 1.3] Генерация Application-ключей для основного трафика...");
            DeriveApplicationKeys();

            FileLog.W("[REALITY TLS 1.3] Отправка Client Finished...");
            await SendClientFinishedAsync();

            _writeSeq = 0;
            _readSeq = 0;
            FileLog.W("[REALITY TLS 1.3] === РУКОПОЖАТИЕ REALITY УСПЕШНО ЗАВЕРШЕНО! ===");
            return true;
        }

        // Ставится в true, если reality-сервер отдал реальную CA-цепочку вместо
        // самоподписанного «прикрытия» — значит он НЕ аутентифицировал наш ClientHello
        // (fallback). Используется для быстрого in-place повтора в StartAsync.
        public bool ServerFellBack { get; private set; }

        private void InspectServerCertificate(byte[] hsMsg)
        {
            int certLen = 0;
            try
            {
                int pos = 4;
                int ctxLen = hsMsg[pos]; pos += 1 + ctxLen;
                pos += 3;
                certLen = (hsMsg[pos] << 16) | (hsMsg[pos + 1] << 8) | hsMsg[pos + 2];
                pos += 3;

                if (certLen <= 0 || pos + certLen > hsMsg.Length) return;

                byte[] der = new byte[certLen];
                System.Buffer.BlockCopy(hsMsg, pos, der, 0, certLen);

                var cert = new Windows.Security.Cryptography.Certificates.Certificate(der.AsBuffer());
                bool selfSigned = string.Equals(cert.Subject, cert.Issuer, StringComparison.OrdinalIgnoreCase);
                // В обычном TLS сертификат от настоящего CA — это НОРМА, а не признак
                // reality-фолбэка. Флаг ставим только в reality-режиме.
                if (!selfSigned && !PlainTls) ServerFellBack = true;

                FileLog.W("========== СЕРТИФИКАТ СЕРВЕРА ==========");
                FileLog.W($"[CERT] Subject:   {cert.Subject}");
                FileLog.W($"[CERT] Issuer:    {cert.Issuer}");
                FileLog.W(PlainTls
                    ? "[CERT] => Обычный TLS 1.3 (цепочку не проверяем — туннель и так шифрован VLESS)."
                    : selfSigned
                        ? "[CERT] => Самоподписанный/временный сертификат: REALITY НАС ПРИНЯЛ."
                        : "[CERT] => Реальная цепочка CA: МЫ В FALLBACK, REALITY нас отбросил на прикрытие.");
                FileLog.W("=======================================");
            }
            catch (Exception ex)
            {
                // Windows не умеет разбирать сертификаты на Ed25519, а REALITY выдаёт
                // именно такой — крошечный и подписанный ключом, выведенным из общего
                // секрета. Раньше исключение глоталось, и в логе не было НИ ОДНОЙ строки
                // про сертификат ровно в тот момент, когда туннель наконец поднялся.
                // Размер здесь решает: настоящая CA-цепочка — это килобайты.
                FileLog.W($"[CERT] Разобрать сертификат не удалось ({certLen} б): {ex.Message}");
                FileLog.W(certLen > 0 && certLen < 512
                    ? "[CERT] => Размер как у временного сертификата REALITY — на прикрытие не похоже."
                    : "[CERT] => Размер как у настоящей цепочки CA — вероятен FALLBACK.");
            }
        }

        // Версия клиента внутри auth-payload reality (первые три байта session_id).
        // Это НЕ косметика: у сервера есть настройка minClientVer формата x.y.z, которая
        // сверяется именно с этими байтами, и клиент старее заданного уводится на
        // сайт-прикрытие — неотличимо от неверного ключа. Мы годами слали 1.8.1, поэтому
        // серверы с minClientVer нас молча отфутболивали.
        // Держим версию не ниже актуального ядра Xray. Верхнюю границу (maxClientVer)
        // операторы почти никогда не задают, так что риск завысить минимален.
        private const byte RealityVerX = 26;
        private const byte RealityVerY = 3;
        private const byte RealityVerZ = 27;

        // Соединений за сеанс десятки, поэтому параметры auth пишем один раз за процесс:
        // по ним видно, совпадают ли pbk/sid со ссылкой и не уехали ли часы устройства
        // (сервер может отбивать по maxTimeDiff).
        private static int _authParamsLogged;

        private void LogAuthParamsOnce(bool pubKeyOk)
        {
            if (System.Threading.Interlocked.Exchange(ref _authParamsLogged, 1) != 0) return;
            try
            {
                string sid = _cfg.ShortId ?? "";
                int sidBytes = -1;
                try { sidBytes = CryptoSelfTest.HexToBytes(sid).Length; } catch { }
                FileLog.Important($"[REALITY AUTH] pbk={(pubKeyOk ? "32 байта, ок" : "НЕВЕРНЫЙ")}, " +
                                  $"sid='{sid}' ({sidBytes} байт), sni='{_cfg.Sni}', " +
                                  $"версия клиента={RealityVerX}.{RealityVerY}.{RealityVerZ}, " +
                                  $"часы устройства UTC={DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
            }
            catch { }
        }

        private byte[] BuildRealityClientHello()
        {
            ushort gCipher = NextGrease();
            ushort gGroup = NextGrease();
            ushort gVer = NextGrease();
            ushort gExtA = NextGrease();
            ushort gExtB = NextGrease();
            // gExtA и gExtB идут в ClientHello как ТИПЫ двух GREASE-расширений, а RFC 8446
            // запрещает два расширения одного типа. Значения тянулись независимо из набора
            // в 16 штук, поэтому раз на шестнадцать они совпадали — и сервер отвечал на такую
            // запись fatal decode_error (alert 0232). Chrome по той же причине берёт для этих
            // двух слотов заведомо разные значения. При совпадении сдвигаем на шаг по набору
            // (0x0a0a…0xfafa, с переходом через край) — детерминированно и всегда валидно.
            if (gExtB == gExtA)
            {
                byte hi = (byte)((((gExtA >> 8) + 0x10) & 0xF0) | 0x0A);
                gExtB = (ushort)((hi << 8) | hi);
            }

            using (var ms = new MemoryStream())
            {
                ms.WriteByte(3); ms.WriteByte(3);                 // legacy_version = TLS 1.2
                ms.Write(_clientRandom, 0, 32);                   // random
                ms.WriteByte(32); ms.Write(new byte[32], 0, 32);  // legacy_session_id (auth впишется сюда позже)

                // cipher_suites.
                //
                // REALITY: GREASE + только TLS_AES_128_GCM_SHA256 (0x1301). 0x1301 обязателен
                // в любом TLS 1.3 сервере (RFC 8446 §9.1), а наш KDF умеет только SHA-256.
                // Предлагать 0x1302/0x1303 нельзя — сервер их выберет, а расшифровать мы не
                // сможем (ровно так и ломалось: сервер выбирал 0x1302).
                //
                // ОБЫЧНЫЙ TLS (PlainTls): одинокий 0x1301 — крайне нетипичный отпечаток. Happ
                // ходит на этот же сервер с uTLS-отпечатком Chrome и работает, а наш ClientHello
                // сервер/фильтр рвёт до ServerHello. Поэтому предлагаем Chrome-подобный набор.
                // Если сервер выберет шифр, который мы не реализуем, ParseServerHello скажет об
                // этом явно (и тогда будет понятно, что именно доделывать).
                byte[] cipherSuites;
                if (PlainTls)
                {
                    cipherSuites = new byte[]
                    {
                        (byte)(gCipher >> 8), (byte)gCipher,
                        0x13,0x01, 0x13,0x02, 0x13,0x03,
                        0xc0,0x2b, 0xc0,0x2f, 0xc0,0x2c, 0xc0,0x30,
                        0xcc,0xa9, 0xcc,0xa8,
                        0xc0,0x13, 0xc0,0x14,
                        0x00,0x9c, 0x00,0x9d, 0x00,0x2f, 0x00,0x35
                    };
                }
                else
                {
                    cipherSuites = new byte[]
                    {
                        (byte)(gCipher >> 8), (byte)gCipher,
                        0x13, 0x01
                    };
                }
                ms.WriteByte((byte)(cipherSuites.Length >> 8));
                ms.WriteByte((byte)(cipherSuites.Length & 0xFF));
                ms.Write(cipherSuites, 0, cipherSuites.Length);

                ms.WriteByte(0x01); ms.WriteByte(0x00);           // legacy_compression = null

                byte[] exts = BuildExtensions(gGroup, gVer, gExtA, gExtB, cipherSuites.Length);
                ms.WriteByte((byte)(exts.Length >> 8)); ms.WriteByte((byte)(exts.Length & 0xFF));
                ms.Write(exts, 0, exts.Length);

                byte[] body = ms.ToArray();
                using (var hs = new MemoryStream())
                {
                    hs.WriteByte(1);
                    hs.WriteByte((byte)(body.Length >> 16));
                    hs.WriteByte((byte)(body.Length >> 8));
                    hs.WriteByte((byte)(body.Length & 0xFF));
                    hs.Write(body, 0, body.Length);
                    byte[] hsBytes = hs.ToArray();

                    // ==== Обычный TLS 1.3: session_id = случайные байты, auth не нужен ====
                    if (PlainTls)
                    {
                        byte[] sid = Tls13Crypto.RandomBytes(32);
                        System.Buffer.BlockCopy(sid, 0, hsBytes, 39, 32);
                        return hsBytes;
                    }

                    // ==== Reality-auth ====
                    // Ключ обязан раскодироваться ровно в 32 байта. Раньше при кривом pbk
                    // сюда молча уходил массив нулей (или неверной длины), общий секрет
                    // получался мусорным, сервер отправлял нас в фолбэк — и понять причину
                    // по логу было нельзя.
                    byte[] pubKey = new byte[32];
                    bool pubKeyOk = false;
                    if (!string.IsNullOrEmpty(_cfg.PublicKey))
                    {
                        string b64 = _cfg.PublicKey.Replace("-", "+").Replace("_", "/");
                        while (b64.Length % 4 != 0) b64 += "=";
                        try
                        {
                            byte[] decoded = Convert.FromBase64String(b64);
                            if (decoded.Length == 32) { pubKey = decoded; pubKeyOk = true; }
                            else FileLog.Important($"[REALITY AUTH] pbk раскодировался в {decoded.Length} байт вместо 32 — ключ в ссылке битый.");
                        }
                        catch (Exception ex)
                        {
                            FileLog.Important($"[REALITY AUTH] pbk не разбирается как base64: {ex.Message}");
                        }
                    }
                    else FileLog.Important("[REALITY AUTH] В профиле нет pbk — аутентификация reality невозможна.");

                    LogAuthParamsOnce(pubKeyOk);

                    byte[] shared = Curve25519.GetSharedSecret(_clientPrivate, pubKey);
                    byte[] prk = Tls13Crypto.HkdfExtract(_clientRandom.Take(20).ToArray(), shared);
                    _realityAuthKey = Tls13Crypto.HkdfExpand(prk, Encoding.ASCII.GetBytes("REALITY"), 32);
                    byte[] nonce = _clientRandom.Skip(20).Take(12).ToArray();

                    byte[] p = new byte[16];
                    uint now = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                    p[0] = RealityVerX; p[1] = RealityVerY; p[2] = RealityVerZ;
                    p[4] = (byte)(now >> 24); p[5] = (byte)(now >> 16); p[6] = (byte)(now >> 8); p[7] = (byte)now;

                    if (!string.IsNullOrEmpty(_cfg.ShortId))
                    {
                        try
                        {
                            byte[] sidBytes = CryptoSelfTest.HexToBytes(_cfg.ShortId);
                            int copyLen = Math.Min(8, sidBytes.Length);
                            System.Buffer.BlockCopy(sidBytes, 0, p, 8, copyLen);
                        }
                        catch { }
                    }

                    byte[] encryptedSession = Tls13Crypto.AesGcmEncrypt(_realityAuthKey, nonce, hsBytes, p);
                    System.Buffer.BlockCopy(encryptedSession, 0, hsBytes, 39, 32);
                    return hsBytes;
                }
            }
        }

        private byte[] BuildExtensions(ushort gGroup, ushort gVer, ushort gExtA, ushort gExtB, int cipherBytes)
        {
            using (var ms = new MemoryStream())
            {
                // 1. GREASE (пустое)
                AddExt(ms, gExtA, new byte[0]);

                // 2. server_name.
                // Пустой SNI — законная конфигурация: так отдаёт конфиги Amnezia.
                // Подставлять вместо него адрес сервера нельзя по двум причинам:
                // literal-IP в SNI запрещён RFC 6066, а REALITY сверяет имя со
                // своим списком serverNames и на IP отвечает прикрытием. Раньше
                // подстановка стояла как «запасной вариант» и на таких конфигах
                // гарантированно уводила рукопожатие в fallback. Если имени нет —
                // расширение не отправляем вовсе, как это делает uTLS.
                if (!string.IsNullOrEmpty(_cfg.Sni))
                {
                    byte[] sniBytes = Encoding.ASCII.GetBytes(_cfg.Sni);
                    byte[] sniExt = new byte[5 + sniBytes.Length];
                    sniExt[0] = (byte)((sniBytes.Length + 3) >> 8); sniExt[1] = (byte)(sniBytes.Length + 3);
                    sniExt[2] = 0; sniExt[3] = (byte)(sniBytes.Length >> 8); sniExt[4] = (byte)(sniBytes.Length & 0xFF);
                    System.Buffer.BlockCopy(sniBytes, 0, sniExt, 5, sniBytes.Length);
                    AddExt(ms, 0x0000, sniExt);
                }

                // 3. extended_master_secret
                AddExt(ms, 0x0017, new byte[0]);
                // 4. renegotiation_info
                AddExt(ms, 0xff01, new byte[] { 0x00 });
                // 5. supported_groups: GREASE, x25519, secp256r1, secp384r1
                AddExt(ms, 0x000a, new byte[] {
                    0x00, 0x08,
                    (byte)(gGroup >> 8), (byte)gGroup,
                    0x00, 0x1d, 0x00, 0x17, 0x00, 0x18
                });
                // 6. ec_point_formats: uncompressed
                AddExt(ms, 0x000b, new byte[] { 0x01, 0x00 });
                // 7. session_ticket
                AddExt(ms, 0x0023, new byte[0]);
                // 8. ALPN
                AddExt(ms, 0x0010, BuildAlpnList());
                // 9. status_request (OCSP)
                AddExt(ms, 0x0005, new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00 });
                // 10. signature_algorithms (Chrome-порядок)
                AddExt(ms, 0x000d, new byte[] {
                    0x00, 0x10,
                    0x04,0x03, 0x08,0x04, 0x04,0x01, 0x05,0x03,
                    0x08,0x05, 0x05,0x01, 0x08,0x06, 0x06,0x01
                });
                // 11. signed_certificate_timestamp
                AddExt(ms, 0x0012, new byte[0]);
                // 12. key_share: GREASE(1 байт) + x25519(32 байта). GREASE-group совпадает с supported_groups.
                byte[] ks = new byte[2 + 5 + 4 + 32];
                int ksLen = 5 + 4 + 32; // длина client_shares
                ks[0] = (byte)(ksLen >> 8); ks[1] = (byte)ksLen;
                ks[2] = (byte)(gGroup >> 8); ks[3] = (byte)gGroup; ks[4] = 0x00; ks[5] = 0x01; ks[6] = 0x00;
                ks[7] = 0x00; ks[8] = 0x1d; ks[9] = 0x00; ks[10] = 0x20;
                System.Buffer.BlockCopy(_clientPublic, 0, ks, 11, 32);
                AddExt(ms, 0x0033, ks);
                // 13. psk_key_exchange_modes: psk_dhe_ke
                AddExt(ms, 0x002d, new byte[] { 0x01, 0x01 });
                // 14. supported_versions.
                // REALITY: GREASE + только TLS 1.3 (сервер обязан выбрать 1.3 — мы больше ничего
                // не умеем). PlainTls: добавляем ещё и 1.2, как это делает Chrome — так CH
                // выглядит браузерным. Любой TLS 1.3-сервер всё равно выберет 1.3 (берётся
                // максимальная общая версия), а если сервер только 1.2 — сработает запасной
                // системный путь в WsTransport.
                AddExt(ms, 0x002b, PlainTls
                    ? new byte[] { 0x06, (byte)(gVer >> 8), (byte)gVer, 0x03, 0x04, 0x03, 0x03 }
                    : new byte[] { 0x04, (byte)(gVer >> 8), (byte)gVer, 0x03, 0x04 });
                // 15. compress_certificate: brotli — ТОЛЬКО в обычном TLS.
                // В reality его просить нельзя: сервер честно отвечает сжатым сертификатом
                // (handshake-сообщение типа 25 вместо 11), распаковать brotli в UWP нечем,
                // InspectServerCertificate не вызывается — и определение фолбэка
                // (ServerFellBack) перестаёт работать. Клиент считает хендшейк успешным
                // и льёт в браузер HTTP/2-мусор с сайта-прикрытия.
                // В PlainTls сертификат мы и так не проверяем, а отпечаток тут подобран
                // под Chrome — там расширение оставляем.
                if (PlainTls)
                    AddExt(ms, 0x001b, new byte[] { 0x02, 0x00, 0x02 });
                // 16. application_settings (ALPS) — только когда предлагаем h2
                if (!OfferH1Only)
                    AddExt(ms, 0x4469, new byte[] { 0x00, 0x03, 0x02, (byte)'h', (byte)'2' });
                // 17. GREASE (1-байтовая нагрузка)
                AddExt(ms, gExtB, new byte[] { 0x00 });

                // 18. padding до 512 (правило BoringSSL: окно 256..511)
                // cipherBytes раньше был захардкожен как 8 и разошёлся с реальным списком
                // (после сокращения до 0x1301 стало 4) — из-за этого ClientHello не добивался
                // до задуманных 512 байт. Теперь считаем от фактической длины.
                byte[] soFar = ms.ToArray();
                int bodyNoPad = 2 + 32 + 1 + 32 + 2 + cipherBytes + 2 + 2 + soFar.Length;
                if (bodyNoPad >= 256 && bodyNoPad < 512)
                {
                    int padLen = 512 - bodyNoPad - 4; // 4 = заголовок padding-расширения
                    if (padLen < 0) padLen = 0;
                    AddExt(ms, 0x0015, new byte[padLen]);
                }

                return ms.ToArray();
            }
        }

        private void AddExt(MemoryStream ms, ushort type, byte[] data)
        {
            ms.WriteByte((byte)(type >> 8)); ms.WriteByte((byte)(type & 0xFF));
            ms.WriteByte((byte)(data.Length >> 8)); ms.WriteByte((byte)(data.Length & 0xFF));
            ms.Write(data, 0, data.Length);
        }

        private void DeriveHandshakeKeys(byte[] serverShare)
        {
            byte[] shared = Curve25519.GetSharedSecret(_clientPrivate, serverShare);
            byte[] zeros = new byte[Tls13Crypto.HashLenOf(_sha384)];
            byte[] earlySecret = Tls13Crypto.HkdfExtract(_sha384, zeros, zeros);
            byte[] derived = Tls13Crypto.DeriveSecret(_sha384, earlySecret, "derived", new byte[0]);
            _handshakeSecret = Tls13Crypto.HkdfExtract(_sha384, derived, shared);
            _clientHandshakeTrafficSecret = Tls13Crypto.DeriveSecret(_sha384, _handshakeSecret, "c hs traffic", _transcript.ToArray());
            _serverHandshakeTrafficSecret = Tls13Crypto.DeriveSecret(_sha384, _handshakeSecret, "s hs traffic", _transcript.ToArray());
            _clientHandshakeKey = Tls13Crypto.HkdfExpandLabel(_sha384, _clientHandshakeTrafficSecret, "key", new byte[0], _aesKeyLen);
            _clientHandshakeIv = Tls13Crypto.HkdfExpandLabel(_sha384, _clientHandshakeTrafficSecret, "iv", new byte[0], 12);
            _serverHandshakeKey = Tls13Crypto.HkdfExpandLabel(_sha384, _serverHandshakeTrafficSecret, "key", new byte[0], _aesKeyLen);
            _serverHandshakeIv = Tls13Crypto.HkdfExpandLabel(_sha384, _serverHandshakeTrafficSecret, "iv", new byte[0], 12);
        }

        private void DeriveApplicationKeys()
        {
            byte[] zeros = new byte[Tls13Crypto.HashLenOf(_sha384)];
            byte[] derived = Tls13Crypto.DeriveSecret(_sha384, _handshakeSecret, "derived", new byte[0]);
            byte[] masterSecret = Tls13Crypto.HkdfExtract(_sha384, derived, zeros);
            byte[] cAppTraffic = Tls13Crypto.DeriveSecret(_sha384, masterSecret, "c ap traffic", _transcript.ToArray());
            byte[] sAppTraffic = Tls13Crypto.DeriveSecret(_sha384, masterSecret, "s ap traffic", _transcript.ToArray());
            _clientAppKey = Tls13Crypto.HkdfExpandLabel(_sha384, cAppTraffic, "key", new byte[0], _aesKeyLen);
            _clientAppIv = Tls13Crypto.HkdfExpandLabel(_sha384, cAppTraffic, "iv", new byte[0], 12);
            _serverAppKey = Tls13Crypto.HkdfExpandLabel(_sha384, sAppTraffic, "key", new byte[0], _aesKeyLen);
            _serverAppIv = Tls13Crypto.HkdfExpandLabel(_sha384, sAppTraffic, "iv", new byte[0], 12);

            _clientAppCryptoKey = _chacha ? null : Tls13Crypto.CreateAesGcmKey(_clientAppKey);
            _serverAppCryptoKey = _chacha ? null : Tls13Crypto.CreateAesGcmKey(_serverAppKey);
        }

        public byte[] EncryptRecord(byte[] data)
        {
            if (_chacha) return EncryptRecordInternal(_clientAppKey, _clientAppIv, ref _writeSeq, 23, data);
            return EncryptRecordInternalWithKey(_clientAppCryptoKey, _clientAppIv, ref _writeSeq, 23, data);
        }

        public byte[] DecryptRecordExplicit(byte[] header, byte[] cipherAndTag, out byte innerType)
        {
            innerType = 0;
            try
            {
                byte[] nonce = BuildNonce(_serverAppIv, _readSeq++);
                byte[] plain = _chacha
                    ? AwgCrypto.Open(_serverAppKey, nonce, header, cipherAndTag)
                    : Tls13Crypto.AesGcmDecryptWithKey(_serverAppCryptoKey, nonce, header, cipherAndTag);
                if (plain != null && plain.Length > 0)
                {
                    int end = plain.Length - 1;
                    while (end >= 0 && plain[end] == 0) end--;
                    if (end >= 0)
                    {
                        innerType = plain[end];
                        return plain.Take(end).ToArray();
                    }
                }
            }
            catch { }
            return null;
        }

        private async Task<Tuple<byte, byte[], byte[]>> ReadNextRecordAsync()
        {
            if (!await ReadExactAsync(5)) return null;
            byte[] header = new byte[5]; _reader.ReadBytes(header);
            int len = (header[3] << 8) | header[4];
            if (len <= 0) return new Tuple<byte, byte[], byte[]>(header[0], header, new byte[0]);

            if (!await ReadExactAsync((uint)len)) return null;
            byte[] payload = new byte[len]; _reader.ReadBytes(payload);
            return new Tuple<byte, byte[], byte[]>(header[0], header, payload);
        }

        private async Task<Tuple<byte, byte[]>> ReadEncryptedRecordAsync(bool application)
        {
            var rec = await ReadNextRecordAsync();
            if (rec == null) return null;
            if (rec.Item1 == 20) return await ReadEncryptedRecordAsync(application);

            if (application)
            {
                byte[] nonce = BuildNonce(_serverAppIv, _readSeq++);
                byte[] plain = _chacha
                    ? AwgCrypto.Open(_serverAppKey, nonce, rec.Item2, rec.Item3)
                    : Tls13Crypto.AesGcmDecryptWithKey(_serverAppCryptoKey, nonce, rec.Item2, rec.Item3);
                if (plain == null) return null;
                int end = plain.Length - 1;
                while (end >= 0 && plain[end] == 0) end--;
                if (end < 0) return null;
                return new Tuple<byte, byte[]>(plain[end], plain.Take(end).ToArray());
            }
            else
            {
                byte[] key = _serverHandshakeKey;
                byte[] iv = _serverHandshakeIv;
                byte[] nonce = BuildNonce(iv, _readSeq++);
                byte[] plain = _chacha
                    ? AwgCrypto.Open(key, nonce, rec.Item2, rec.Item3)
                    : Tls13Crypto.AesGcmDecrypt(key, nonce, rec.Item2, rec.Item3);
                if (plain == null) return null;
                int end = plain.Length - 1;
                while (end >= 0 && plain[end] == 0) end--;
                if (end < 0) return null;
                return new Tuple<byte, byte[]>(plain[end], plain.Take(end).ToArray());
            }
        }

        private byte[] EncryptRecordInternalWithKey(CryptographicKey cryptoKey, byte[] iv, ref ulong seq, byte innerType, byte[] content)
        {
            byte[] inner = new byte[content.Length + 1];
            System.Buffer.BlockCopy(content, 0, inner, 0, content.Length);
            inner[inner.Length - 1] = innerType;
            int encLen = inner.Length + 16;
            byte[] header = new byte[] { 23, 3, 3, (byte)(encLen >> 8), (byte)(encLen & 0xFF) };
            byte[] nonce = BuildNonce(iv, seq++);

            byte[] encrypted = Tls13Crypto.AesGcmEncryptWithKey(cryptoKey, nonce, header, inner);

            byte[] result = new byte[header.Length + encrypted.Length];
            System.Buffer.BlockCopy(header, 0, result, 0, header.Length);
            System.Buffer.BlockCopy(encrypted, 0, result, header.Length, encrypted.Length);
            return result;
        }

        private byte[] EncryptRecordInternal(byte[] key, byte[] iv, ref ulong seq, byte innerType, byte[] content)
        {
            byte[] inner = new byte[content.Length + 1];
            System.Buffer.BlockCopy(content, 0, inner, 0, content.Length);
            inner[inner.Length - 1] = innerType;
            int encLen = inner.Length + 16;
            byte[] header = new byte[] { 23, 3, 3, (byte)(encLen >> 8), (byte)(encLen & 0xFF) };
            byte[] nonce = BuildNonce(iv, seq++);

            byte[] encrypted = _chacha
                ? AwgCrypto.Seal(key, nonce, header, inner)
                : Tls13Crypto.AesGcmEncrypt(key, nonce, header, inner);

            byte[] result = new byte[header.Length + encrypted.Length];
            System.Buffer.BlockCopy(header, 0, result, 0, header.Length);
            System.Buffer.BlockCopy(encrypted, 0, result, header.Length, encrypted.Length);
            return result;
        }

        private byte[] BuildNonce(byte[] iv, ulong seq)
        {
            byte[] nonce = (byte[])iv.Clone();
            for (int i = 0; i < 8; i++) nonce[nonce.Length - 1 - i] ^= (byte)(seq >> (8 * i));
            return nonce;
        }

        private byte[] ParseServerHello(byte[] hs)
        {
            if (hs.Length < 44 || hs[0] != 2) return null;
            int sidLen = hs[38];
            int cipherOff = 39 + sidLen;
            if (cipherOff + 3 > hs.Length) return null;
            int chosenCipher = (hs[cipherOff] << 8) | hs[cipherOff + 1];
            FileLog.Important($"[TLS 1.3] Сервер ответил ServerHello, выбранный шифр: 0x{chosenCipher:X4}.");
            // 0x1301 = AES-128-GCM-SHA256, 0x1302 = AES-256-GCM-SHA384,
            // 0x1303 = ChaCha20-Poly1305-SHA256. Провайдера ChaCha20 в UWP нет, поэтому
            // берётся своя реализация из AwgCrypto — та же, что шифрует AmneziaWG.
            if (chosenCipher == 0x1301) { _sha384 = false; _aesKeyLen = 16; _chacha = false; }
            else if (chosenCipher == 0x1302) { _sha384 = true; _aesKeyLen = 32; _chacha = false; }
            else if (chosenCipher == 0x1303) { _sha384 = false; _aesKeyLen = 32; _chacha = true; }
            else
            {
                FileLog.Important($"[REALITY TLS 1.3 ERROR] Сервер выбрал шифр 0x{chosenCipher:X4}; " +
                                  "клиент реализует 0x1301, 0x1302 и 0x1303. Handshake прерван.");
                return null;
            }
            int pos = 39 + sidLen + 2 + 1; // пропустили cipher(2) + compression(1)
            int extTotal = (hs[pos] << 8) | hs[pos + 1];
            pos += 2;
            int end = pos + extTotal;

            byte[] serverShare = null;

            while (pos + 4 <= end)
            {
                int type = (hs[pos] << 8) | hs[pos + 1];
                int len = (hs[pos + 2] << 8) | hs[pos + 3];
                pos += 4;

                if (type == 0x0033 && len >= 36) // key_share
                {
                    int group = (hs[pos] << 8) | hs[pos + 1];
                    if (group == 0x001d) serverShare = hs.Skip(pos + 4).Take(32).ToArray();
                }
                else if (type == 0x0010 && len >= 3) // ALPN
                {
                    int nameLen = hs[pos + 2];
                    if (nameLen > 0 && pos + 3 + nameLen <= end)
                    {
                        NegotiatedAlpn = Encoding.ASCII.GetString(hs, pos + 3, nameLen);
                        FileLog.Important($"[REALITY TLS 1.3] Сервер выбрал ALPN: '{NegotiatedAlpn}'");
                    }
                }

                pos += len;
            }

            return serverShare;
        }
        private void ParseEncryptedExtensions(byte[] hs)
        {
            if (hs == null || hs.Length < 6 || hs[0] != 8) return;
            int extTotal = (hs[4] << 8) | hs[5];
            int pos = 6;
            int end = Math.Min(hs.Length, pos + extTotal);
            while (pos + 4 <= end)
            {
                int type = (hs[pos] << 8) | hs[pos + 1];
                int len = (hs[pos + 2] << 8) | hs[pos + 3];
                pos += 4;
                if (type == 0x0010 && len >= 3 && pos + 3 <= end) // ALPN
                {
                    int nameLen = hs[pos + 2];
                    if (nameLen > 0 && pos + 3 + nameLen <= end)
                    {
                        NegotiatedAlpn = Encoding.ASCII.GetString(hs, pos + 3, nameLen);
                        FileLog.Important($"[TLS 1.3] Сервер выбрал ALPN (EncryptedExtensions): '{NegotiatedAlpn}'");
                    }
                }
                pos += len;
            }
        }
        private void UnusedBraceClose()
        {
        }

        private bool VerifyServerFinished(byte[] finishedHs)
        {
            byte[] verifyData = finishedHs.Skip(4).ToArray();
            int hl = Tls13Crypto.HashLenOf(_sha384);
            byte[] finishedKey = Tls13Crypto.HkdfExpandLabel(_sha384, _serverHandshakeTrafficSecret, "finished", new byte[0], hl);
            byte[] transcriptHash = Tls13Crypto.Hash(_sha384, _transcript.ToArray());
            byte[] expected = Tls13Crypto.Hmac(_sha384, finishedKey, transcriptHash);
            return Tls13Crypto.ConstantEquals(expected, verifyData);
        }

        private async Task SendClientFinishedAsync()
        {
            int hl = Tls13Crypto.HashLenOf(_sha384);
            byte[] transcriptHash = Tls13Crypto.Hash(_sha384, _transcript.ToArray());
            byte[] finishedKey = Tls13Crypto.HkdfExpandLabel(_sha384, _clientHandshakeTrafficSecret, "finished", new byte[0], hl);
            byte[] verify = Tls13Crypto.Hmac(_sha384, finishedKey, transcriptHash);
            byte[] hs = new byte[4 + verify.Length];
            hs[0] = 20; hs[1] = 0; hs[2] = (byte)(verify.Length >> 8); hs[3] = (byte)(verify.Length & 0xFF);
            System.Buffer.BlockCopy(verify, 0, hs, 4, verify.Length);
            byte[] record = EncryptRecordInternal(_clientHandshakeKey, _clientHandshakeIv, ref _writeSeq, 22, hs);

            try
            {
                // RFC 8446 D.4: клиент с непустым legacy_session_id обязан отправить
                // фиктивный ChangeCipherSpec непосредственно перед вторым флайтом, то
                // есть прямо перед Client Finished. У REALITY session_id непустой всегда
                // (в нём лежит auth), так что это наш случай, а мы CCS не слали вовсе —
                // отличие и от Chrome, и от Firefox, под которых подобран отпечаток.
                // В транскрипт CCS не входит: это запись уровня записей, не рукопожатия.
                _writer.WriteBytes(new byte[] { 20, 3, 3, 0, 1, 1 });
                _writer.WriteBytes(record);
                await _writer.StoreAsync();
                _transcript.AddRange(hs);
            }
            catch { }
        }
    }
}
