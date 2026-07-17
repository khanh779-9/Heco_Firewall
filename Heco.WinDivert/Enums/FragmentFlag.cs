using System;

namespace Heco.WinDivert.Enums;

[Flags]
public enum FragmentFlag : byte
{
    Reserved = 0, MayFragment = 0, DontFragment = 2, MoreFragments = 4,
}