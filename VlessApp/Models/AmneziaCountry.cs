using System.Collections.Generic;

namespace VlessApp
{
    internal sealed class AmneziaCountry
    {
        public string Code;
        public string Name;
        public List<string> Protocols = new List<string>();

        public override string ToString()
        {
            string p = Protocols.Count > 0 ? " · " + string.Join("/", Protocols).ToUpperInvariant() : "";
            return (string.IsNullOrEmpty(Name) ? Code : Name) + p;
        }
    }
}
