using System;

namespace VlessApp
{
    // Конфиг пришёл, но разобрать его нечем. Несёт обезличенную структуру
    // ответа, чтобы её можно было показать и скопировать.
    internal sealed class AmneziaUnsupportedConfigException : Exception
    {
        public string Dump { get; private set; }
        public AmneziaUnsupportedConfigException(string message, string dump) : base(message) { Dump = dump; }
    }
}
