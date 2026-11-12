using System;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Collections.Generic;
using Windows.Networking;
using Windows.Networking.Sockets;
using Windows.Networking.Vpn;
using Windows.Storage;
using Windows.Storage.Streams;
using Windows.Networking.Connectivity;

namespace VlessVpnTask
{
    internal class VlessConfig
    {
        public string Address { get; set; }
        public int Port { get; set; } = 443;
        public string Uuid { get; set; }
        public string Type { get; set; } = "tcp";
        public string Security { get; set; } = "reality";
        public string Sni { get; set; }
        public string PublicKey { get; set; }
        public string ShortId { get; set; }
        public string Path { get; set; }
        public string Host { get; set; }
        public string Flow { get; set; }
        public string Alpn { get; set; }

        // Второе звено цепочки Amnezia. Address/Port выше — это реле, которое
        // умеет доводить только до этого узла. Пока используется для разовой
        // проверки: первое соединение направляется сюда вместо сайта, чтобы
        // выяснить, принимает ли реле IP-назначение вообще.
        public string ChainExitHost { get; set; } = "";
        public int ChainExitPort { get; set; }

        // У выходного узла свои учётные данные REALITY: ключи реле ему чужие,
        // и на них он отбрасывает на прикрытие (в логе — настоящий CA-сертификат).
        public string ChainExitUuid { get; set; } = "";
        public string ChainExitPublicKey { get; set; } = "";
        public string ChainExitSni { get; set; } = "";
        public string ChainExitShortId { get; set; } = "";
        public string ChainExitFlow { get; set; } = "";

        // Конфиг второго звена. Транспорт и режим наследуются от первого
        // (оба узла — tcp/reality), а всё, что узел проверяет у клиента,
        // подменяется на его собственное. Цепочка дальше не идёт, поэтому
        // поля ChainExit* в копии остаются пустыми — иначе получилась бы
        // бесконечная вложенность.
        public VlessConfig CloneForChainExit()
        {
            return new VlessConfig
            {
                Address = ChainExitHost,
                Port = ChainExitPort,
                Uuid = ChainExitUuid,
                PublicKey = ChainExitPublicKey,
                Sni = ChainExitSni,
                ShortId = ChainExitShortId,
                Flow = ChainExitFlow,
                Type = Type,
                Security = Security,
                Alpn = Alpn,
                Path = Path,
                Host = Host,
                XhttpMode = XhttpMode
            };
        }

        // Shadowsocks / Outline
        public string Method { get; set; } = "";     // шифр AEAD
        public string Password { get; set; } = "";
        public string SsPrefix { get; set; } = "";   // маскировка начала потока (Outline)

        public string XhttpMode { get; set; } = "auto";
        public string Extra { get; set; } = "";
        public string Fp { get; set; } = "";
        public bool NoGrpcHeader { get; set; } = true;
        public bool NoSseHeader { get; set; } = true;
        public int XPaddingMin { get; set; } = 100;
        public int XPaddingMax { get; set; } = 1000;
        public bool XPaddingObfsMode { get; set; } = false;
        public string XPaddingHeader { get; set; } = "X-Padding";
        public string XPaddingKey { get; set; } = "x_padding";
        public string XPaddingPlacement { get; set; } = "queryInHeader";
        public string XPaddingMethod { get; set; } = "repeat-x";
        public string UplinkHttpMethod { get; set; } = "POST";
        public string SessionPlacement { get; set; } = "path";
        public string SessionKey { get; set; } = "";
        public string SeqPlacement { get; set; } = "path";
        public string SeqKey { get; set; } = "";
        public int ScMaxEachPostBytes { get; set; } = 1000000;
        public int XmuxMaxConcurrency { get; set; } = 0;
        public int XmuxKeepAlivePeriod { get; set; } = 0;

        private static readonly Random _padRng = new Random();
        private const string Base62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        // Длина символов Base62 в битах по таблице Хаффмана HPACK (RFC 7541 Appendix B).
        // Нужна для метода tokenish: Xray-core проверяет, что байтовая длина строки
        // после сжатия Хаффманом попадает в диапазон [xPaddingBytes.From, xPaddingBytes.To].
        private static readonly byte[] Base62HuffmanBits = new byte[62]
        {
            5, 5, 5, 6, 6, 6, 6, 6, 6, 6,
            6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8,
            5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7
        };

        public void ParseExtra()
        {
            if (string.IsNullOrWhiteSpace(Extra)) return;
            try
            {
                Windows.Data.Json.JsonObject root;
                if (!Windows.Data.Json.JsonObject.TryParse(Extra, out root) || root == null)
                    return;

                ApplyExtraObject(root);
                if (root.ContainsKey("extra"))
                {
                    var inner = root.GetNamedValue("extra");
                    if (inner != null && inner.ValueType == Windows.Data.Json.JsonValueType.Object)
                        ApplyExtraObject(inner.GetObject());
                }

                FileLog.Important(
                    $"[XHTTP EXTRA] mode='{XhttpMode}'->{ResolveXhttpMode()}, obfs={XPaddingObfsMode}, " +
                    $"method='{XPaddingMethod}', placement='{XPaddingPlacement}', " +
                    $"hdr='{XPaddingHeader}', key='{XPaddingKey}', pad={XPaddingMin}-{XPaddingMax}, " +
                    $"xmuxConc={XmuxMaxConcurrency}, keepAlive={XmuxKeepAlivePeriod}s");
            }
            catch (Exception ex)
            {
                FileLog.W($"[XHTTP EXTRA] Не удалось разобрать extra JSON: {ex.Message}");
            }
        }

        private void ApplyExtraObject(Windows.Data.Json.JsonObject obj)
        {
            if (obj == null) return;

            int from, to;
            if (TryParseRange(obj, "xPaddingBytes", out from, out to) && to > 0)
            {
                XPaddingMin = from > 0 ? from : to;
                XPaddingMax = to >= XPaddingMin ? to : XPaddingMin;
            }

            bool b;
            if (TryGetBool(obj, "xPaddingObfsMode", out b)) XPaddingObfsMode = b;
            if (TryGetBool(obj, "noGRPCHeader", out b)) NoGrpcHeader = b;
            if (TryGetBool(obj, "noSSEHeader", out b)) NoSseHeader = b;

            string s;
            if (TryGetStr(obj, "xPaddingHeader", out s)) XPaddingHeader = s;
            if (TryGetStr(obj, "xPaddingKey", out s)) XPaddingKey = s;
            if (TryGetStr(obj, "xPaddingPlacement", out s)) XPaddingPlacement = s;
            if (TryGetStr(obj, "xPaddingMethod", out s)) XPaddingMethod = s;
            if (TryGetStr(obj, "uplinkHTTPMethod", out s)) UplinkHttpMethod = s;
            if (TryGetStr(obj, "sessionPlacement", out s)) SessionPlacement = s;
            if (TryGetStr(obj, "sessionKey", out s)) SessionKey = s;
            if (TryGetStr(obj, "seqPlacement", out s)) SeqPlacement = s;
            if (TryGetStr(obj, "seqKey", out s)) SeqKey = s;

            if (TryParseRange(obj, "scMaxEachPostBytes", out from, out to) && to > 0)
                ScMaxEachPostBytes = to;

            if (obj.ContainsKey("xmux"))
            {
                var xmuxVal = obj.GetNamedValue("xmux");
                if (xmuxVal != null && xmuxVal.ValueType == Windows.Data.Json.JsonValueType.Object)
                {
                    var xmux = xmuxVal.GetObject();
                    if (TryParseRange(xmux, "maxConcurrency", out from, out to) && to > 0)
                        XmuxMaxConcurrency = to;
                    int ka, kaTo;
                    if (TryParseRange(xmux, "hKeepAlivePeriod", out ka, out kaTo) && kaTo > 0)
                        XmuxKeepAlivePeriod = kaTo;
                }
            }
        }

        private static bool TryGetStr(Windows.Data.Json.JsonObject obj, string key, out string val)
        {
            val = null;
            if (obj == null || !obj.ContainsKey(key)) return false;
            var v = obj.GetNamedValue(key);
            if (v != null && v.ValueType == Windows.Data.Json.JsonValueType.String)
            {
                string s = v.GetString();
                if (!string.IsNullOrEmpty(s)) { val = s; return true; }
            }
            return false;
        }

        private static bool TryGetBool(Windows.Data.Json.JsonObject obj, string key, out bool val)
        {
            val = false;
            if (obj == null || !obj.ContainsKey(key)) return false;
            var v = obj.GetNamedValue(key);
            if (v != null && v.ValueType == Windows.Data.Json.JsonValueType.Boolean)
            {
                val = v.GetBoolean();
                return true;
            }
            return false;
        }

        private static bool TryParseRange(Windows.Data.Json.JsonObject obj, string key, out int from, out int to)
        {
            from = 0; to = 0;
            if (obj == null || !obj.ContainsKey(key)) return false;
            var v = obj.GetNamedValue(key);
            if (v == null) return false;
            if (v.ValueType == Windows.Data.Json.JsonValueType.Number)
            {
                int n = (int)v.GetNumber();
                from = n; to = n;
                return true;
            }
            if (v.ValueType == Windows.Data.Json.JsonValueType.String)
            {
                string s = (v.GetString() ?? "").Trim();
                int dash = s.IndexOf('-');
                if (dash > 0)
                {
                    int a, b;
                    if (int.TryParse(s.Substring(0, dash).Trim(), out a) &&
                        int.TryParse(s.Substring(dash + 1).Trim(), out b))
                    {
                        from = a; to = b;
                        return true;
                    }
                }
                int single;
                if (int.TryParse(s, out single))
                {
                    from = single; to = single;
                    return true;
                }
            }
            if (v.ValueType == Windows.Data.Json.JsonValueType.Object)
            {
                var ro = v.GetObject();
                if (ro.ContainsKey("from") && ro.GetNamedValue("from").ValueType == Windows.Data.Json.JsonValueType.Number)
                    from = (int)ro.GetNamedValue("from").GetNumber();
                if (ro.ContainsKey("to") && ro.GetNamedValue("to").ValueType == Windows.Data.Json.JsonValueType.Number)
                    to = (int)ro.GetNamedValue("to").GetNumber();
                if (to == 0 && from > 0) to = from;
                if (from == 0 && to > 0) from = to;
                return to > 0;
            }
            return false;
        }

        public string NormalizeXhttpBasePath()
        {
            string p = string.IsNullOrEmpty(Path) ? "/" : Path.Trim();
            int q = p.IndexOf('?');
            if (q >= 0) p = p.Substring(0, q);
            if (!p.StartsWith("/")) p = "/" + p;
            if (!p.EndsWith("/")) p += "/";
            return p;
        }

        public string GenerateXPadding()
        {
            int min = XPaddingMin > 0 ? XPaddingMin : 100;
            int max = XPaddingMax >= min ? XPaddingMax : Math.Max(min, 1000);
            int targetLen;
            bool tokenish = string.Equals((XPaddingMethod ?? "").Trim(), "tokenish", StringComparison.OrdinalIgnoreCase);

            lock (_padRng)
            {
                targetLen = _padRng.Next(min, max + 1);
                if (!tokenish)
                    return new string('X', targetLen);

                var sb = new System.Text.StringBuilder((int)(targetLen * 1.4) + 8);
                int totalBits = 0;
                while ((totalBits + 7) / 8 < targetLen)
                {
                    int idx = _padRng.Next(62);
                    sb.Append(Base62Chars[idx]);
                    totalBits += Base62HuffmanBits[idx];
                }
                return sb.ToString();
            }
        }

        public void BuildXhttpRequestMeta(
            string sessionId,
            long? seq,
            out string pathAndQuery,
            out List<KeyValuePair<string, string>> extraHeaders)
        {
            string basePath = NormalizeXhttpBasePath();
            string p = basePath;
            var queries = new List<string>();
            var cookies = new List<string>();
            extraHeaders = new List<KeyValuePair<string, string>>();

            bool sessionInPath = false;
            if (!string.IsNullOrEmpty(sessionId))
            {
                string sp = (SessionPlacement ?? "path").Trim().ToLowerInvariant();
                string sk = !string.IsNullOrEmpty(SessionKey)
                    ? SessionKey
                    : (!XPaddingObfsMode ? "x_session" : (!string.IsNullOrEmpty(XPaddingKey) ? XPaddingKey : "x_session"));
                if (sp == "query") queries.Add(sk + "=" + sessionId);
                else if (sp == "header") extraHeaders.Add(new KeyValuePair<string, string>(sk, sessionId));
                else if (sp == "cookie") cookies.Add(sk + "=" + sessionId);
                else
                {
                    p += sessionId;
                    sessionInPath = true;
                }
            }

            if (seq.HasValue)
            {
                string qp = (SeqPlacement ?? "path").Trim().ToLowerInvariant();
                string qk = !string.IsNullOrEmpty(SeqKey)
                    ? SeqKey
                    : (!XPaddingObfsMode ? "x_seq" : (!string.IsNullOrEmpty(XPaddingKey) ? XPaddingKey : "x_seq"));
                if (qp == "query") queries.Add(qk + "=" + seq.Value);
                else if (qp == "header") extraHeaders.Add(new KeyValuePair<string, string>(qk, seq.Value.ToString()));
                else if (qp == "cookie") cookies.Add(qk + "=" + seq.Value);
                else
                {
                    if (sessionInPath) p += "/" + seq.Value;
                    else p += seq.Value.ToString();
                }
            }

            string pad = GenerateXPadding();
            string host = !string.IsNullOrEmpty(Host) ? Host : (!string.IsNullOrEmpty(Sni) ? Sni : Address);
            if (!XPaddingObfsMode)
            {
                extraHeaders.Add(new KeyValuePair<string, string>("Referer", $"https://{host}{basePath}?x_padding={pad}"));
            }
            else
            {
                string pp = (XPaddingPlacement ?? "queryInHeader").Trim().ToLowerInvariant();
                string pk = !string.IsNullOrEmpty(XPaddingKey) ? XPaddingKey : "x_padding";
                string ph = !string.IsNullOrEmpty(XPaddingHeader) ? XPaddingHeader : "X-Padding";

                if (pp == "cookie") cookies.Add(pk + "=" + pad);
                else if (pp == "header") extraHeaders.Add(new KeyValuePair<string, string>(ph, pad));
                else if (pp == "query") queries.Add(pk + "=" + pad);
                else extraHeaders.Add(new KeyValuePair<string, string>(ph, $"https://{host}{basePath}?{pk}={pad}"));
            }

            if (cookies.Count > 0)
                extraHeaders.Add(new KeyValuePair<string, string>("Cookie", string.Join("; ", cookies)));

            pathAndQuery = queries.Count > 0
                ? (p + (p.IndexOf('?') >= 0 ? "&" : "?") + string.Join("&", queries))
                : p;
        }

        public XhttpTransportMode ResolveXhttpMode()
        {
            string m = (XhttpMode ?? "").Trim().ToLowerInvariant();
            switch (m)
            {
                case "packet-up":
                case "packetup":
                    return XhttpTransportMode.PacketUp;
                case "stream-up":
                case "streamup":
                    return XhttpTransportMode.StreamUp;
                case "stream-one":
                    // auto/пусто/stream-one -> stream-one. В отличие от senko здесь
                    // НЕ выбираем packet-up для security=none: split-транспорт
                    // (XhttpSplit) в Metrobox всегда идёт через Reality, а stream-one
                    // корректно шлёт cleartext при security=none.
                case "streamone":
                    return XhttpTransportMode.StreamOne;
                case "auto":
                case "":
                default:
                    // В Xray-core для mode=auto:
                    //   по умолчанию выбирается packet-up (совместим с CDN и reverse-proxy вроде Caddy/Nginx,
                    //   которые буферизуют тело POST до его завершения и вешают stream-one),
                    //   и только для REALITY без отдельных downloadSettings выбирается stream-one.
                    bool isReality = string.Equals((Security ?? "").Trim(), "reality", StringComparison.OrdinalIgnoreCase);
                    return isReality ? XhttpTransportMode.StreamOne : XhttpTransportMode.PacketUp;
            }
        }

        // Определяет, включен ли режим XHTTP
        public bool IsXhttp =>
            string.Equals(Type, "xhttp", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "splithttp", StringComparison.OrdinalIgnoreCase);

        public bool IsWs =>
            string.Equals(Type, "ws", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "websocket", StringComparison.OrdinalIgnoreCase);

        // Shadowsocks/Outline: собственный AEAD-транспорт, ни Reality, ни MUX не участвуют.
        public bool IsShadowsocks =>
            string.Equals(Type, "shadowsocks", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(Type, "ss", StringComparison.OrdinalIgnoreCase);

        // xtls-rprx-vision активен только для своего flow и только на raw TCP
        // (не ws/xhttp), как и в xray-core.
        public bool IsGrpc =>
            string.Equals(Type, "grpc", StringComparison.OrdinalIgnoreCase);

        public bool IsVision =>
            string.Equals((Flow ?? "").Trim(), "xtls-rprx-vision", StringComparison.OrdinalIgnoreCase)
            && !IsWs && !IsXhttp && !IsGrpc;

        public string NormalizeGrpcPath()
        {
            string p = string.IsNullOrEmpty(Path) ? "" : Path.Trim();
            if (string.IsNullOrEmpty(p)) return "/Tun";
            if (p.StartsWith("/"))
            {
                if (p.EndsWith("/Tun", StringComparison.OrdinalIgnoreCase) || p.EndsWith("/TunMulti", StringComparison.OrdinalIgnoreCase))
                    return p;
                return p.TrimEnd('/') + "/Tun";
            }
            return "/" + p + "/Tun";
        }

        public string EffectiveXhttpMode
        {
            get
            {
                string m = (XhttpMode ?? "").Trim().ToLowerInvariant();
                if (m == "" || m == "auto")
                    return ResolveXhttpMode() == XhttpTransportMode.PacketUp ? "packet-up"
                         : ResolveXhttpMode() == XhttpTransportMode.StreamUp ? "stream-up"
                         : "stream-one";
                return m;
            }
        }

        public static VlessConfig Parse(string configStr)
        {
            var cfg = new VlessConfig();
            if (string.IsNullOrEmpty(configStr)) return cfg;

            var pairs = configStr.Split(new[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var pair in pairs)
            {
                var kv = pair.Split(new[] { '=' }, 2);
                if (kv.Length == 2)
                {
                    string key = kv[0].Trim().ToLowerInvariant();
                    string val = kv[1].Trim();

                    switch (key)
                    {
                        case "type": cfg.Type = val; break;
                        case "security": cfg.Security = val; break;
                        case "sni": cfg.Sni = val; break;
                        case "sid":
                        case "shortid": cfg.ShortId = val; break;
                        case "flow": cfg.Flow = val; break;
                        case "path": cfg.Path = val; break;
                        case "host": cfg.Host = val; break;
                        case "alpn": cfg.Alpn = val; break;
                        case "pbk":
                        case "publickey":
                            val = val.Replace("-", "+").Replace("_", "/");
                            while (val.Length % 4 != 0) val += "=";
                            cfg.PublicKey = val;
                            break;
                    }
                }
            }
            return cfg;
        }
    }
}
