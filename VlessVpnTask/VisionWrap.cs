using System;
using System.IO;

namespace VlessVpnTask
{
    internal sealed class VisionWrap
    {
        private readonly byte[] _uuid = new byte[16];
        private readonly VisionTrafficState _state;
        private bool _uuidSent;
        private bool _paddingActive;
        private bool _bootstrapSent;
        public bool DirectSent { get; private set; }
        // Команда последнего собранного блока — нужна только логу: по ней видно,
        // в каком режиме ушёл первый запрос (0=CONTINUE, 1=END, 2=DIRECT).
        public byte LastCommand { get; private set; }
        private uint _prng;
        private int _blocksSent;
        private long _bytesSent;

        public VisionWrap(byte[] uuid16, VisionTrafficState state)
        {
            Buffer.BlockCopy(uuid16, 0, _uuid, 0, 16);
            _state = state;
            _paddingActive = true;
            uint seed = SeedNow();
            _prng = seed ^ ((uint)_uuid[0] << 24) ^ ((uint)_uuid[15] << 8);
        }

        private static uint SeedNow()
        {
            // эквивалент tv_sec ^ (tv_usec<<11) ^ 0xa5a5c3
            long ticks = DateTime.UtcNow.Ticks;
            uint sec = (uint)(ticks / TimeSpan.TicksPerSecond);
            uint usec = (uint)((ticks / 10) % 1000000);
            return sec ^ (usec << 11) ^ 0xa5a5c3u;
        }

        private ushort PrngMod(ushort mod)
        {
            if (mod == 0) return 0;
            uint x = _prng != 0 ? _prng : 0x13579bdfu;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            _prng = x;
            return (ushort)(x % mod);
        }

        private ushort PaddingLen(int contentLen, bool longPadding)
        {
            if (longPadding && contentLen < VisionConst.LongPadThreshold)
            {
                ushort extra = PrngMod((ushort)VisionConst.LongPadRandom);
                int want = VisionConst.LongPadBase + extra;
                if (want > contentLen) want -= contentLen;
                else want = 0;
                if (want > 0xffff) want = 0xffff;
                return (ushort)want;
            }
            return PrngMod((ushort)VisionConst.ShortPadRandom);
        }

        private void FillPadding(byte[] outBuf, int offset, int n)
        {
            for (int i = 0; i < n; i++)
                outBuf[offset + i] = (byte)PrngMod(256);
        }

        // Порт IsCompleteRecord из xray-core: буфер целиком состоит из полных
        // application-data записей (0x17 0x03 0x03 + длина). Именно это, а не
        // подсчёт записей, служит эталону признаком «хендшейк к сайту закончился».
        private static bool IsCompleteRecord(byte[] b, int totalLen)
        {
            int headerLen = 5;
            int recordLen = 0;
            int i = 0;
            while (i < totalLen)
            {
                if (headerLen > 0)
                {
                    byte data = b[i];
                    i++;
                    switch (headerLen)
                    {
                        case 5: if (data != 0x17) return false; break;
                        case 4: if (data != 0x03) return false; break;
                        case 3: if (data != 0x03) return false; break;
                        case 2: recordLen = data << 8; break;
                        case 1: recordLen |= data; break;
                    }
                    headerLen--;
                }
                else if (recordLen > 0)
                {
                    int remaining = totalLen - i;
                    if (remaining < recordLen) return false;
                    i += recordLen;
                    recordLen = 0;
                    headerLen = 5;
                }
                else return false;
            }
            return headerLen == 5 && recordLen == 0;
        }

        private byte[] BuildBlock(byte cmd, byte[] input, int inLen, bool longPadding)
        {
            if (inLen > 0xffff) inLen = 0xffff;
            ushort pad = PaddingLen(inLen, longPadding);
            int prefix = _uuidSent ? 0 : 16;
            int total = prefix + 5 + inLen + pad;

            byte[] outBuf = new byte[total];
            LastCommand = cmd;
            int o = 0;
            if (!_uuidSent)
            {
                Buffer.BlockCopy(_uuid, 0, outBuf, 0, 16);
                o = 16;
                _uuidSent = true;
            }
            outBuf[o++] = cmd;
            outBuf[o++] = (byte)(inLen >> 8);
            outBuf[o++] = (byte)(inLen & 0xff);
            outBuf[o++] = (byte)(pad >> 8);
            outBuf[o++] = (byte)(pad & 0xff);
            if (inLen > 0) { Buffer.BlockCopy(input, 0, outBuf, o, inLen); o += inLen; }
            if (pad > 0) { FillPadding(outBuf, o, pad); o += pad; }
            return outBuf;
        }

        // Пустой bootstrap-блок (CONTINUE + длинный паддинг) — отправляется,
        // когда клиентских данных ещё нет, чтобы vision-сервер не сбросил соединение.
        public byte[] Bootstrap()
        {
            if (!_paddingActive || _bootstrapSent) return null;
            _bootstrapSent = true;
            return BuildBlock(VisionConst.CmdContinue, null, 0, true);
        }

        // Обернуть исходящий блок клиентских данных. После выключения паддинга
        // возвращает данные без изменений (raw passthrough).
        public byte[] Wrap(byte[] input, int inLen)
        {
            if (inLen == 0) return null;

            // В xray фильтр висит на writer'е и срабатывает до решения о паддинге,
            // поэтому ClientHello к сайту успевает выставить IsTLS на своём же буфере.
            if (_state.NumberOfPacketToFilter > 0) _state.FilterTls(input, inLen);

            if (!_paddingActive)
            {
                if (inLen == input.Length) return input;
                byte[] raw = new byte[inLen];
                Buffer.BlockCopy(input, 0, raw, 0, inLen);
                return raw;
            }

            if (inLen > 0xffff) inLen = 0xffff;

            // Правило xray (VisionWriter.WriteMultiBuffer): обёртка закрывается на
            // первом буфере, который целиком состоит из application-data записей.
            // Команда при этом зависит от версии TLS у САЙТА: DIRECT только когда
            // включён xtls (TLS 1.3), иначе END. Мы раньше считали app-записи и
            // всегда слали DIRECT — на TLS 1.2 это расходилось с сервером и по
            // моменту (мы переключались буфером позже), и по команде.
            byte cmd;
            bool longPadding = _state.IsTLS;
            bool switchRecord = _state.IsTLS && inLen >= 6 &&
                                input[0] == 0x17 && input[1] == 0x03 && input[2] == 0x03 &&
                                IsCompleteRecord(input, inLen);
            if (switchRecord)
            {
                cmd = _state.EnableXtls ? VisionConst.CmdDirect : VisionConst.CmdEnd;
                longPadding = true;
            }
            else if (!_state.IsTLS12orAbove && _state.NumberOfPacketToFilter <= 1)
            {
                // Не-TLS поток: эталон добивает паддинг за пакет до конца окна фильтра.
                cmd = VisionConst.CmdEnd;
            }
            else
            {
                cmd = VisionConst.CmdContinue;
            }

            byte[] block = BuildBlock(cmd, input, inLen, longPadding);
            _blocksSent++;
            _bytesSent += inLen;
            if (cmd != VisionConst.CmdContinue)
            {
                _paddingActive = false;
                // Переключение в raw на исходящем потоке. Обёртка и распаковка решают
                // это независимо, и если границы разъедутся, наружу уйдёт мусор — сайт
                // ответит alert'ом. Пишем, на каком блоке и после скольких байт это
                // случилось, чтобы сверить с моментом переключения downstream.
                FileLog.Important($"[VISION SW TX] Уход в raw: cmd={cmd} " +
                                  $"({(cmd == VisionConst.CmdDirect ? "DIRECT" : "END")}), " +
                                  $"блок #{_blocksSent}, в нём {inLen}б, всего отправлено {_bytesSent}б, " +
                                  $"по записи={(switchRecord ? "да" : "нет")}, " +
                                  $"IsTLS={_state.IsTLS}, xtls={_state.EnableXtls}.");
            }
            if (cmd == VisionConst.CmdDirect) DirectSent = true;
            return block;
        }
    }

}
