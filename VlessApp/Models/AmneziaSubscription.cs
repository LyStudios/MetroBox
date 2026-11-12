namespace VlessApp
{
    internal sealed class AmneziaSubscription
    {
        public string ApiKey;
        public string ServiceType;       // "amnezia-premium"
        public string ServiceProtocol;   // "awg"
        public string UserCountryCode;   // "ru"
        public string Name;
        // Куда подключаться. Пусто — выбирает шлюз. Подписка выдаёт ОДИН
        // активный конфиг на устройство, поэтому смена страны — это новый
        // запрос, после которого прежний конфиг отзывается.
        public string ServerCountryCode;
    }
}
