using System;
using System.Collections.Generic;

namespace VlessApp.Services
{
    /// <summary>Сборка ссылок/JSON профиля для «поделиться».</summary>
    public static class ShareLinkBuilder
    {
        public static string BuildUrl(VlessProfile p)
        {
            // У AmneziaWG нет ссылочного формата — делимся исходным .conf.
            if (p.IsAmneziaWg) return p.AwgConfig ?? "";
            if (p.IsShadowsocks)
            {
                // SIP002: userinfo = base64url(method:password) без паддинга.
                string userInfo = Convert.ToBase64String(
                        System.Text.Encoding.UTF8.GetBytes($"{p.Method}:{p.Password}"))
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
                // prefix хранится в hex — в ссылку он идёт как percent-encoded UTF-8,
                // ровно так же, как его пишет сам Outline.
                string rawPrefix = VlessProfile.PrefixFromHex(p.SsPrefix);
                string query = string.IsNullOrEmpty(rawPrefix)
                    ? "" : "?prefix=" + Uri.EscapeDataString(rawPrefix);
                return $"ss://{userInfo}@{p.Address}:{p.Port}/{query}#{Uri.EscapeDataString(p.Name)}";
            }
            // Ссылка обязана пережить цикл «поделиться → импортировать обратно»: любое
            // потерянное поле молча меняет профиль. Так терялся flow — профиль с
            // xtls-rprx-vision после реимпорта становился обычным и уходил в MUX-режим
            // вместо DIRECT, то есть вёл себя совсем иначе, чем исходная ссылка.
            var q = new List<string>();
            Action<string, string> add = (k, v) =>
            {
                if (!string.IsNullOrEmpty(v)) q.Add(k + "=" + Uri.EscapeDataString(v));
            };

            add("type", p.Type);
            add("security", p.Security);
            add("encryption", "none");          // в ссылках VLESS поле обязательное
            add("sni", p.Sni);
            // PublicKey хранится в обычном base64 (парсер его туда переводит), а в ссылке
            // он должен быть base64url без паддинга — иначе «+» в query другие клиенты
            // прочитают как пробел и ключ развалится.
            add("pbk", string.IsNullOrEmpty(p.PublicKey)
                ? null
                : p.PublicKey.TrimEnd('=').Replace('+', '-').Replace('/', '_'));
            add("sid", p.ShortId);
            add("flow", p.Flow);
            add("path", p.Path);
            add("host", p.Host);
            add("alpn", p.Alpn);
            add("mode", p.Mode);
            add("fp", p.Fp);
            add("extra", p.Extra);

            // UUID парсер хранит без дефисов; отдаём в каноническом виде — так его
            // примут и сторонние клиенты.
            string uuid = p.Uuid;
            Guid g;
            if (Guid.TryParseExact(uuid ?? "", "N", out g)) uuid = g.ToString("D");

            return $"vless://{uuid}@{p.Address}:{p.Port}?{string.Join("&", q)}"
                 + $"#{Uri.EscapeDataString(p.Name ?? "")}";
        }

        public static string BuildJson(VlessProfile p)
        {
            if (p.IsAmneziaWg) return p.AwgConfig ?? "";
            if (p.IsShadowsocks)
                return $"{{\n  \"server\": \"{p.Address}\",\n  \"server_port\": {p.Port},\n  \"method\": \"{p.Method}\",\n  \"password\": \"{p.Password}\"\n}}";
            return $"{{\n  \"server\": \"{p.Address}\",\n  \"port\": {p.Port},\n  \"uuid\": \"{p.Uuid}\",\n  \"type\": \"{p.Type}\",\n  \"security\": \"{p.Security}\",\n  \"sni\": \"{p.Sni}\",\n  \"public_key\": \"{p.PublicKey}\",\n  \"short_id\": \"{p.ShortId}\"\n}}";
        }
    }
}

