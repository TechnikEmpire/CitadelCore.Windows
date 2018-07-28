using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace CitadelCore.Windows.WinAPI
{
    internal static class Iphlpapi
    {
        [DllImport("Iphlpapi.dll", EntryPoint = "GetTcp6Table2")]
        public static extern int GetTcp6Table2(IntPtr TcpTable, ref int SizePointer, [MarshalAs(UnmanagedType.Bool)] bool Order);

        [DllImport("Iphlpapi.dll", EntryPoint = "GetTcpTable2")]
        public static extern int GetTcpTable2(IntPtr TcpTable, ref int SizePointer, [MarshalAs(UnmanagedType.Bool)] bool Order);
    }
}
