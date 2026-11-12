using System;
using System.IO;

namespace VlessVpnTask
{
    internal sealed class VisionUnpad
    {
        private readonly byte[] _uuid = new byte[16];
        private int _remainingCommand = -1;
        private int _remainingContent = -1;
        private int _remainingPadding = -1;
        private int _currentCommand;
        private bool _direct;
        private readonly byte[] _stash = new byte[24];
        private int _stashLen;
        private long _bytesOut;
        private int _blocksSeen;
        private int _lastCmdSeen = -1;

        private readonly VisionTrafficState _state;

        public bool IsDirect => _direct;

        // Узел перестал заворачивать поток во внешний REALITY. Поднимается только
        // командой DIRECT; при уходе в raw «по кадру без UUID» остаётся false —
        // там причина неизвестна, и снимать TLS вслепую опаснее, чем оставить.
        public bool RawSplice { get; private set; }

        // После END поток идёт сырым, но версия сайта могла ещё не определиться:
        // в xray reader продолжает фильтровать, пока NumberOfPacketToFilter > 0.
        public bool NeedsProcessing => !_direct || _state.NumberOfPacketToFilter > 0;

        public VisionUnpad(byte[] uuid16, VisionTrafficState state)
        {
            Buffer.BlockCopy(uuid16, 0, _uuid, 0, 16);
            _state = state;
        }

        // Снять vision-обёртку и скормить результат фильтру TLS. Порядок как в
        // xray (VisionReader.ReadMultiBuffer): сначала XtlsUnpadding, потом
        // XtlsFilterTls по УЖЕ распакованным байтам — иначе на нулевом смещении
        // окажется vision-заголовок, а не запись ServerHello, и версия сайта
        // никогда не определится.
        public byte[] Unpad(byte[] input, int inLen, out bool switchedDirect)
        {
            byte[] outBuf = UnpadCore(input, inLen, out switchedDirect);
            if (_state.NumberOfPacketToFilter > 0 && outBuf.Length > 0)
                _state.FilterTls(outBuf, outBuf.Length);
            return outBuf;
        }

        // Возвращает распакованные application-данные. switchedDirect=true в момент
        // перехода в passthrough. Устойчиво к серверам, которые downstream не паддят:
        // первые 16 байт не совпадут с UUID и поток сразу пойдёт как direct.
        private byte[] UnpadCore(byte[] input, int inLen, out bool switchedDirect)
        {
            switchedDirect = false;
            var outMs = new MemoryStream();

            if (_direct)
            {
                if (inLen > 0) outMs.Write(input, 0, inLen);
                return outMs.ToArray();
            }

            int i = 0;
            while (i < inLen || _stashLen > 0)
            {
                if (_remainingCommand == -1)
                {
                    while (_stashLen < 16 && i < inLen) _stash[_stashLen++] = input[i++];
                    if (_stashLen < 16) break; // нужно больше данных

                    if (!Equals16(_stash, _uuid))
                    {
                        // Не vision-фрейм → direct passthrough: отдаём stash + остаток.
                        // Сюда попадаем и штатно (сервер не паддит downstream), и после END,
                        // когда мы зря ждём UUID. Отличать важно: во втором случае решение
                        // принимается по 16 байтам сырых данных сайта, и если их в этом
                        // чтении меньше, кусок задержится в stash.
                        FileLog.Important($"[VISION SW RX] Кадр без UUID на {_bytesOut}-м байте " +
                                          $"(до этого блоков {_blocksSeen}, последняя команда " +
                                          $"{_lastCmdSeen}) — ухожу в raw, отдаю {_stashLen}б из stash " +
                                          $"+ {inLen - i}б остатка.");
                        outMs.Write(_stash, 0, _stashLen);
                        if (inLen - i > 0) outMs.Write(input, i, inLen - i);
                        _bytesOut += _stashLen + (inLen - i);
                        _stashLen = 0;
                        _direct = true;
                        switchedDirect = true;
                        return outMs.ToArray();
                    }
                    _stashLen = 0;
                    _remainingCommand = 5;
                    _remainingContent = 0;
                    _remainingPadding = 0;
                }

                while (_remainingCommand > 0)
                {
                    if (i >= inLen) return outMs.ToArray(); // заголовок разорван между чтениями
                    byte b = input[i++];
                    switch (_remainingCommand)
                    {
                        case 5: _currentCommand = b; break;
                        case 4: _remainingContent = ((int)b) << 8; break;
                        case 3: _remainingContent |= b; break;
                        case 2: _remainingPadding = ((int)b) << 8; break;
                        case 1: _remainingPadding |= b; break;
                    }
                    _remainingCommand--;
                }

                if (_remainingContent > 0)
                {
                    int take = inLen - i;
                    if (take > _remainingContent) take = _remainingContent;
                    if (take > 0) { outMs.Write(input, i, take); i += take; _bytesOut += take; }
                    _remainingContent -= take;
                    if (_remainingContent > 0) return outMs.ToArray();
                }

                if (_remainingContent == 0 && _remainingPadding > 0)
                {
                    int skip = inLen - i;
                    if (skip > _remainingPadding) skip = _remainingPadding;
                    i += skip;
                    _remainingPadding -= skip;
                    if (_remainingPadding > 0) return outMs.ToArray();
                }

                if (_remainingCommand <= 0 && _remainingContent <= 0 && _remainingPadding <= 0)
                {
                    if (_currentCommand == VisionConst.CmdContinue)
                    {
                        _blocksSeen++;
                        _lastCmdSeen = _currentCommand;
                        _remainingCommand = 5; // следующий блок без uuid
                        _remainingContent = 0;
                        _remainingPadding = 0;
                    }
                    else
                    {
                        _blocksSeen++;
                        _lastCmdSeen = _currentCommand;
                        FileLog.Important($"[VISION SW RX] Команда {_currentCommand} " +
                                          $"({(_currentCommand == VisionConst.CmdDirect ? "DIRECT" : "END")}) " +
                                          $"в блоке #{_blocksSeen}, всего распаковано {_bytesOut}б, " +
                                          $"хвостом отдаю {inLen - i}б.");
                        // И DIRECT, и END означают одно: обёртка кончилась, дальше сырой поток.
                        // Раньше на END мы возвращались к ожиданию uuid, и решение «это уже не
                        // vision-кадр» принималось только по 16 накопленным байтам данных сайта.
                        // Пока их не набиралось, начало ответа лежало в stash — в логе такие
                        // задержки доходили до 734 мс, а если соединение закрывалось раньше,
                        // хвост терялся совсем.
                        _direct = true;
                        // Обёртка кончается на обеих командах, но внешний TLS —
                        // только на DIRECT: это и есть сплайс XTLS, дальше узел
                        // перестаёт шифровать, потому что данные уже защищены
                        // внутренним TLS сайта. END означает лишь конец паддинга
                        // (xtls выключен, сайт на TLS 1.2), и REALITY продолжается.
                        // Смешивать их нельзя: на END сырое чтение отдавало наружу
                        // шифротекст, браузер получал мусор и рвал соединение.
                        if (_currentCommand == VisionConst.CmdDirect) RawSplice = true;
                        switchedDirect = true;
                        int rest = inLen - i;
                        if (rest > 0) { outMs.Write(input, i, rest); i = inLen; _bytesOut += rest; }
                        _remainingCommand = -1;
                        _remainingContent = -1;
                        _remainingPadding = -1;
                    }
                }
            }

            return outMs.ToArray();
        }

        private static bool Equals16(byte[] a, byte[] b)
        {
            for (int i = 0; i < 16; i++) if (a[i] != b[i]) return false;
            return true;
        }
    }
}
