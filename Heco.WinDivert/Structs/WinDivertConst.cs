namespace Heco.WinDivert.Structs;

public static class WinDivertConst
{
    public const short PriorityHighest = 30000;
    public const short PriorityLowest = -30000;
    public const int QueueLengthDefault = 4096;
    public const int QueueLengthMin = 32;
    public const int QueueLengthMax = 16384;
    public const int QueueTimeDefault = 2000;
    public const int QueueTimeMin = 100;
    public const int QueueTimeMax = 16000;
    public const int QueueSizeDefault = 4194304;
    public const int QueueSizeMin = 65535;
    public const int QueueSizeMax = 33554432;
    public const byte BatchMax = 0xFF;
    public const int MtuMax = 40 + 0xFFFF;
    public const int FilterMaxLen = 4096;
    public const int PriorityMin = -30000;
    public const int PriorityMax = 30000;
}