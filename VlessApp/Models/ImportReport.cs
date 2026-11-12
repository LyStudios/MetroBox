using System;
using System.Collections.Generic;

namespace VlessApp
{
    // Итог последнего разбора подписки — MainPage показывает его пользователю,
    // чтобы «импортировано 12» не скрывало «и ещё 7 пропущено».
    public sealed class ImportReport
    {
        public readonly List<string> Skipped = new List<string>();

        // Профили, которые импортировались, но заведомо не поднимутся:
        // незнакомый транспорт или нереализованный шифр.
        public readonly List<string> Warnings = new List<string>();

        // «vmess ×3, trojan ×1» — компактно для строки статуса.
        public string SkippedSummary()
        {
            var byKind = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var s in Skipped)
            {
                int n;
                byKind.TryGetValue(s, out n);
                byKind[s] = n + 1;
            }
            var parts = new List<string>();
            foreach (var kv in byKind)
                parts.Add(kv.Value > 1 ? kv.Key + " ×" + kv.Value : kv.Key);
            return string.Join(", ", parts);
        }
    }
}
