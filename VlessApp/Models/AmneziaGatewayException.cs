using System;

namespace VlessApp
{
    // Шлюз ответил, но не тем, что мы ждали. Несёт статус и тело как есть.
    internal sealed class AmneziaGatewayException : Exception
    {
        public int HttpStatus { get; private set; }
        public string RawBody { get; private set; }
        public AmneziaGatewayException(string message, int status, string rawBody) : base(message)
        {
            HttpStatus = status;
            RawBody = rawBody;
        }
    }
}
