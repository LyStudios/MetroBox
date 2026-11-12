namespace VlessVpnTask
{
    internal enum ChunkedDecodeState
    {
        Size,
        Data,
        AfterCR,
        AfterLF,
        Done
    }
}
