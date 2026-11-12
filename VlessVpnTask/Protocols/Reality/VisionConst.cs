using System;
using System.IO;

namespace VlessVpnTask
{
    // Порт senko/daemon/core/vision.c — xtls-rprx-vision padding-обёртка.
    // Проволочно совместим с xray-core: первый блок несёт 16-байтовый UUID,
    // далее команда(1) + content_len(2) + padding_len(2) + content + padding.
    // Команды: 0=CONTINUE, 1=END, 2=DIRECT. После END/DIRECT паддинг выключается
    // и поток идёт «сырым» passthrough.
    internal static class VisionConst
    {
        public const byte CmdContinue = 0;
        public const byte CmdEnd = 1;
        public const byte CmdDirect = 2;

        public const int DefaultPadPackets = 8;
        public const int LongPadThreshold = 900;
        public const int LongPadRandom = 500;
        public const int LongPadBase = 900;
        public const int ShortPadRandom = 256;
    }

}
