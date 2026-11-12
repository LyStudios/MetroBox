using System;
using System.Collections.Generic;
using System.Text;

namespace VlessApp
{
    /// <summary>
    /// Определение страны по имени профиля и преобразование ISO-кода в эмодзи-флаг
    /// для рендеринга через встроенный цветной шрифт Twemoji Mozilla (COLRv0).
    /// </summary>
    internal static class CountryFlags
    {
        public static string DetectFromName(string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return "";

            string fromEmoji = FromRegionalIndicators(name);
            if (fromEmoji != "") return fromEmoji;

            string lower = name.ToLowerInvariant();

            foreach (var kv in NamesByLength)
            {
                if (lower.IndexOf(kv.Key, StringComparison.Ordinal) >= 0)
                    return kv.Value;
            }

            string token3 = FindCodeToken(name, 3);
            if (token3 != "") return token3;

            string token2 = FindCodeToken(name, 2);
            if (token2 != "") return token2;

            return "";
        }

        /// <summary>
        /// Преобразует двухбуквенный код ISO 3166-1 alpha-2 (например, "NL")
        /// в пару символов Regional Indicator (U+1F1E6..U+1F1FF), которую
        /// шрифт Twemoji Mozilla отображает как векторный цветной флаг.
        /// </summary>
        public static string GetFlagEmoji(string iso2)
        {
            if (string.IsNullOrEmpty(iso2) || iso2.Length != 2) return "";
            char c1 = char.ToUpperInvariant(iso2[0]);
            char c2 = char.ToUpperInvariant(iso2[1]);
            if (c1 < 'A' || c1 > 'Z' || c2 < 'A' || c2 > 'Z') return "";

            char lo1 = (char)(0xDDE6 + (c1 - 'A'));
            char lo2 = (char)(0xDDE6 + (c2 - 'A'));
            return new string(new[] { '\uD83C', lo1, '\uD83C', lo2 });
        }

        // U+1F1E6..U+1F1FF, в UTF-16 это суррогатные пары D83C DDE6..DDFF.
        private static string FromRegionalIndicators(string s)
        {
            for (int i = 0; i + 3 < s.Length; i++)
            {
                if (s[i] != '\uD83C' || s[i + 2] != '\uD83C') continue;
                int a = s[i + 1], b = s[i + 3];
                if (a < 0xDDE6 || a > 0xDDFF || b < 0xDDE6 || b > 0xDDFF) continue;
                char c1 = (char)('A' + (a - 0xDDE6));
                char c2 = (char)('A' + (b - 0xDDE6));
                string code = new string(new[] { c1, c2 });
                if (Alpha2Set.Contains(code)) return code;
            }
            return "";
        }

        private static bool IsLetter(char c)
        {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        // Коды, которые в нижнем регистре неотличимы от обычных слов.
        private static readonly HashSet<string> AmbiguousLower = new HashSet<string>(StringComparer.Ordinal)
        {
            "MY","IN","IT","IS","NO","AT","BE","US","ME","BY","ID","AM","SA","LA","AS","SO","DO","OR","TO","IF","ON","WE","HE","AD","SM",
            "CAN","ARE","EST","PER","NOR","COL","MAR","AUT","IND"
        };

        private static string FindCodeToken(string src, int len)
        {
            for (int i = 0; i + len <= src.Length; i++)
            {
                if (i > 0 && IsLetter(src[i - 1])) continue;
                if (i + len < src.Length && IsLetter(src[i + len])) continue;

                bool allLetters = true;
                bool allUpper = true;
                for (int k = 0; k < len; k++)
                {
                    char c = src[i + k];
                    if (!IsLetter(c)) { allLetters = false; break; }
                    if (c < 'A' || c > 'Z') allUpper = false;
                }
                if (!allLetters) continue;

                string tok = src.Substring(i, len).ToUpperInvariant();
                if (!allUpper && AmbiguousLower.Contains(tok)) continue;

                if (len == 3)
                {
                    string mapped;
                    if (Alpha3.TryGetValue(tok, out mapped)) return mapped;
                }
                else if (Alpha2Set.Contains(tok)) return tok;
            }
            return "";
        }

        // Убирает флаг-эмодзи из названия сервера, так как в системном Segoe UI
        // без Twemoji они рисуются буквенными квадратиками («NL»), а сам флаг
        // уже выводится в отдельном бейдже слева.
        public static string StripFlagEmoji(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            var sb = new StringBuilder(name.Length);
            for (int i = 0; i < name.Length; i++)
            {
                if (i + 1 < name.Length && name[i] == '\uD83C' &&
                    name[i + 1] >= 0xDDE6 && name[i + 1] <= 0xDDFF)
                {
                    i++;
                    continue;
                }
                sb.Append(name[i]);
            }
            return sb.ToString().Trim(' ', '\t', '-', '|', '_');
        }

        private static readonly HashSet<string> Alpha2Set = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "RU","NL","DE","FR","IT","GB","US","CA","ES","PT","PL","UA","BY","MD","RO","BG","GR","TR",
            "CZ","SK","SI","HR","RS","HU","AT","CH","BE","LU","IE","DK","SE","NO","FI","IS","EE","LV",
            "LT","JP","KR","CN","HK","TW","SG","IN","ID","TH","VN","MY","PH","AE","IL","SA","QA","IR",
            "PK","BD","AU","NZ","BR","AR","CL","MX","CO","PE","VE","EC","ZA","EG","NG","KE","MA","AM",
            "GE","AZ","KZ","UZ","KG","TJ","TM","MN","MC","MT","CY","AL","MK","BA","ME","LI","AD","SM",
            "SY","YE","JO","LB","OM","KW","BH","IQ","AF","LK","NP","MM","KH","LA","BN","PA","CR","UY",
            "PY","BO","DO","CU","JM","PR","SC","MU","TN","DZ","ET","GH","TZ","UG","SN","CI","AO","MZ"
        };

        private static readonly Dictionary<string, string> Alpha3 = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            {"RUS","RU"},{"NLD","NL"},{"DEU","DE"},{"GER","DE"},{"FRA","FR"},{"ITA","IT"},{"GBR","GB"},
            {"UKR","UA"},{"USA","US"},{"CAN","CA"},{"ESP","ES"},{"PRT","PT"},{"POL","PL"},{"ROU","RO"},
            {"BGR","BG"},{"GRC","GR"},{"TUR","TR"},{"CZE","CZ"},{"SVK","SK"},{"SVN","SI"},{"HRV","HR"},
            {"SRB","RS"},{"HUN","HU"},{"AUT","AT"},{"CHE","CH"},{"BEL","BE"},{"LUX","LU"},{"IRL","IE"},
            {"DNK","DK"},{"SWE","SE"},{"NOR","NO"},{"FIN","FI"},{"ISL","IS"},{"EST","EE"},{"LVA","LV"},
            {"LTU","LT"},{"JPN","JP"},{"KOR","KR"},{"CHN","CN"},{"HKG","HK"},{"TWN","TW"},{"SGP","SG"},
            {"IND","IN"},{"IDN","ID"},{"THA","TH"},{"VNM","VN"},{"MYS","MY"},{"PHL","PH"},{"ARE","AE"},
            {"ISR","IL"},{"SAU","SA"},{"IRN","IR"},{"PAK","PK"},{"BGD","BD"},{"AUS","AU"},{"NZL","NZ"},
            {"BRA","BR"},{"ARG","AR"},{"CHL","CL"},{"MEX","MX"},{"COL","CO"},{"PER","PE"},{"ZAF","ZA"},
            {"EGY","EG"},{"NGA","NG"},{"KEN","KE"},{"MAR","MA"},{"ARM","AM"},{"GEO","GE"},{"AZE","AZ"},
            {"KAZ","KZ"},{"UZB","UZ"},{"BLR","BY"},{"MDA","MD"},{"KGZ","KG"},{"TJK","TJ"},{"TKM","TM"},
            {"MNG","MN"},{"CYP","CY"},{"MLT","MT"},{"ALB","AL"},{"MKD","MK"},{"BIH","BA"},{"MNE","ME"}
        };

        private static readonly List<KeyValuePair<string, string>> NamesByLength = BuildNames();

        private static List<KeyValuePair<string, string>> BuildNames()
        {
            var d = new Dictionary<string, string>
            {
                {"нидерланд","NL"},{"голланд","NL"},{"netherland","NL"},{"holland","NL"},{"amsterdam","NL"},
                {"герман","DE"},{"germany","DE"},{"deutschland","DE"},{"frankfurt","DE"},{"франкфурт","DE"},
                {"франц","FR"},{"france","FR"},{"paris","FR"},{"париж","FR"},
                {"росси","RU"},{"russia","RU"},{"москв","RU"},{"moscow","RU"},{"питер","RU"},{"spb","RU"},
                {"великобритан","GB"},{"британ","GB"},{"англи","GB"},{"united kingdom","GB"},{"england","GB"},{"london","GB"},{"лондон","GB"},
                {"соединённые штаты","US"},{"соединенные штаты","US"},{"united states","US"},{"америк","US"},{"america","US"},
                {"канад","CA"},{"canada","CA"},
                {"испан","ES"},{"spain","ES"},{"madrid","ES"},
                {"португал","PT"},{"portugal","PT"},{"lisbon","PT"},
                {"польш","PL"},{"poland","PL"},{"warsaw","PL"},
                {"украин","UA"},{"ukraine","UA"},{"kyiv","UA"},{"kiev","UA"},
                {"беларус","BY"},{"belarus","BY"},
                {"молдов","MD"},{"moldova","MD"},
                {"румын","RO"},{"romania","RO"},{"bucharest","RO"},
                {"болгар","BG"},{"bulgaria","BG"},{"sofia","BG"},
                {"греци","GR"},{"greece","GR"},{"athens","GR"},
                {"турци","TR"},{"turkey","TR"},{"turkiye","TR"},{"istanbul","TR"},{"стамбул","TR"},
                {"чехи","CZ"},{"czech","CZ"},{"prague","CZ"},{"прага","CZ"},
                {"словаки","SK"},{"slovakia","SK"},
                {"словени","SI"},{"slovenia","SI"},
                {"хорват","HR"},{"croatia","HR"},
                {"серби","RS"},{"serbia","RS"},
                {"венгри","HU"},{"hungary","HU"},{"budapest","HU"},
                {"австри","AT"},{"austria","AT"},{"vienna","AT"},{"вена","AT"},
                {"швейцар","CH"},{"switzerland","CH"},{"zurich","CH"},
                {"бельги","BE"},{"belgium","BE"},
                {"люксембург","LU"},{"luxembourg","LU"},
                {"ирланди","IE"},{"ireland","IE"},{"dublin","IE"},
                {"дани","DK"},{"denmark","DK"},{"copenhagen","DK"},
                {"швеци","SE"},{"sweden","SE"},{"stockholm","SE"},
                {"норвег","NO"},{"norway","NO"},{"oslo","NO"},
                {"финлянд","FI"},{"finland","FI"},{"helsinki","FI"},{"хельсинки","FI"},
                {"исланди","IS"},{"iceland","IS"},
                {"эстони","EE"},{"estonia","EE"},{"tallinn","EE"},
                {"латви","LV"},{"latvia","LV"},{"riga","LV"},
                {"литв","LT"},{"lithuania","LT"},{"vilnius","LT"},
                {"япони","JP"},{"japan","JP"},{"tokyo","JP"},{"токио","JP"},
                {"южная коре","KR"},{"south korea","KR"},{"корея","KR"},{"korea","KR"},{"seoul","KR"},
                {"китай","CN"},{"china","CN"},{"shanghai","CN"},{"beijing","CN"},
                {"гонконг","HK"},{"hong kong","HK"},{"hongkong","HK"},
                {"тайван","TW"},{"taiwan","TW"},
                {"сингапур","SG"},{"singapore","SG"},
                {"инди","IN"},{"india","IN"},{"mumbai","IN"},
                {"индонези","ID"},{"indonesia","ID"},
                {"таиланд","TH"},{"thailand","TH"},{"bangkok","TH"},
                {"вьетнам","VN"},{"vietnam","VN"},
                {"малайзи","MY"},{"malaysia","MY"},
                {"филиппин","PH"},{"philippines","PH"},
                {"эмират","AE"},{"emirates","AE"},{"dubai","AE"},{"дубай","AE"},
                {"израил","IL"},{"israel","IL"},
                {"саудов","SA"},{"saudi","SA"},
                {"катар","QA"},{"qatar","QA"},
                {"пакистан","PK"},{"pakistan","PK"},
                {"бангладеш","BD"},{"bangladesh","BD"},
                {"австрали","AU"},{"australia","AU"},{"sydney","AU"},
                {"новая зеланди","NZ"},{"new zealand","NZ"},
                {"бразили","BR"},{"brazil","BR"},{"sao paulo","BR"},
                {"аргентин","AR"},{"argentina","AR"},
                {"чили","CL"},{"chile","CL"},
                {"мексик","MX"},{"mexico","MX"},
                {"колумби","CO"},{"colombia","CO"},
                {"перу","PE"},{"peru","PE"},
                {"юар","ZA"},{"south africa","ZA"},
                {"египет","EG"},{"egypt","EG"},
                {"нигери","NG"},{"nigeria","NG"},
                {"кени","KE"},{"kenya","KE"},
                {"марокк","MA"},{"morocco","MA"},
                {"армени","AM"},{"armenia","AM"},{"yerevan","AM"},
                {"грузи","GE"},{"georgia","GE"},{"tbilisi","GE"},
                {"азербайджан","AZ"},{"azerbaijan","AZ"},{"baku","AZ"},
                {"казахстан","KZ"},{"kazakhstan","KZ"},{"almaty","KZ"},
                {"узбекистан","UZ"},{"uzbekistan","UZ"},
                {"итали","IT"},{"italy","IT"},{"milan","IT"},{"милан","IT"},{"rome","IT"},
                {"монако","MC"},{"monaco","MC"},
                {"иран","IR"},{"iran","IR"}
            };

            var list = new List<KeyValuePair<string, string>>(d);
            list.Sort((a, b) => b.Key.Length.CompareTo(a.Key.Length));
            return list;
        }
    }
}
