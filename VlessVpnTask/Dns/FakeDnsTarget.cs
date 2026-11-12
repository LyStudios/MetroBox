namespace VlessVpnTask
{
    internal sealed class FakeDnsTarget
    {
        public byte[] RealIp;    // 4 байта, реальный A-ответ от upstream DNS
        public string Domain;    // оригинальный запрошенный домен
    }
}
