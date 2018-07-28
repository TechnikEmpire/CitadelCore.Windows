/*
* Copyright © 2017-Present Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using CitadelCore.Logging;
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace CitadelCore.Windows.WinAPI
{
    internal enum TcpConnectionOffloadState : uint
    {
        TcpConnectionOffloadStateInHost = 0,
        TcpConnectionOffloadStateOffloading = 1,
        TcpConnectionOffloadStateOffloaded = 2,
        TcpConnectionOffloadStateUploading = 3,
        TcpConnectionOffloadStateMax = 4,
    }

    [StructLayout(LayoutKind.Explicit)]
    internal struct in6_addr_union
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8, ArraySubType = UnmanagedType.U2)]
        [FieldOffset(0)]
        internal ushort[] Word;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16, ArraySubType = UnmanagedType.U1)]
        [FieldOffset(0)]
        internal byte[] Byte;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct in6_addr
    {
        internal in6_addr_union u;
    }

    // Enum for different possible states of TCP connection
    internal enum MibTcpState : uint
    {
        CLOSED = 1,
        LISTENING = 2,
        SYN_SENT = 3,
        SYN_RCVD = 4,
        ESTABLISHED = 5,
        FIN_WAIT1 = 6,
        FIN_WAIT2 = 7,
        CLOSE_WAIT = 8,
        CLOSING = 9,
        LAST_ACK = 10,
        TIME_WAIT = 11,
        DELETE_TCB = 12,
        NONE = 0
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCP6ROW2
    {
        internal in6_addr LocalAddr;

        internal uint dwLocalScopeId;

        internal uint dwLocalPort;

        internal in6_addr RemoteAddr;

        internal uint dwRemoteScopeId;

        internal uint dwRemotePort;

        internal MibTcpState State;

        internal uint dwOwningPid;

        internal TcpConnectionOffloadState dwOffloadState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPROW2
    {
        internal MibTcpState dwState;

        internal uint dwLocalAddr;

        internal uint dwLocalPort;

        internal uint dwRemoteAddr;

        internal uint dwRemotePort;

        internal uint dwOwningPid;

        internal TcpConnectionOffloadState dwOffloadState;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCPTABLE2
    {
        internal uint dwNumEntries;

        internal IntPtr table;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct MIB_TCP6TABLE2
    {
        internal uint dwNumEntries;

        internal IntPtr table;
    }

    internal interface ITcpConnectionInfo
    {
        ushort LocalPort
        {
            get;
        }

        ushort RemotePort
        {
            get;
        }

        IPAddress LocalAddress
        {
            get;
        }

        IPAddress RemoteAddress
        {
            get;
        }

        ulong OwnerPid
        {
            get;
        }

        string OwnerProcessPath
        {
            get;
        }

        MibTcpState State
        {
            get;
        }

        TcpConnectionOffloadState OffloadState
        {
            get;
        }
    }

    internal class Tcp4ConnectionInfo : ITcpConnectionInfo
    {
        public ushort LocalPort
        {
            get;
            private set;
        }

        public ushort RemotePort
        {
            get;
            private set;
        }

        public IPAddress LocalAddress
        {
            get;
            private set;
        }

        public IPAddress RemoteAddress
        {
            get;
            private set;
        }

        public ulong OwnerPid
        {
            get;
            private set;
        }

        public string OwnerProcessPath
        {
            get
            {
                try
                {
                    return ProcessUtilities.GetProcessName(OwnerPid);
                }
                catch(Exception e)
                {
                    LoggerProxy.Default.Error(e);
                }

                return string.Empty;
            }
        }

        public MibTcpState State
        {
            get;
            private set;
        }

        public TcpConnectionOffloadState OffloadState
        {
            get;
            private set;
        }

        public Tcp4ConnectionInfo(MIB_TCPROW2 tcpRow)
        {
            // We mask the ports in this struct because according to the documentation, the upper
            // bits can be populated arbitrarily, aka undefined state.
            LocalPort = (ushort)(tcpRow.dwLocalPort & 0xFFFF);

            RemotePort = (ushort)(tcpRow.dwRemotePort & 0xFFFF);

            LocalAddress = new IPAddress(tcpRow.dwLocalAddr);

            RemoteAddress = new IPAddress(tcpRow.dwRemoteAddr);

            State = tcpRow.dwState;

            OffloadState = tcpRow.dwOffloadState;

            OwnerPid = tcpRow.dwOwningPid;
        }
    }

    internal class Tcp6ConnectionInfo : ITcpConnectionInfo
    {
        public ushort LocalPort
        {
            get;
            private set;
        }

        public ushort RemotePort
        {
            get;
            private set;
        }

        public IPAddress LocalAddress
        {
            get;
            private set;
        }

        public IPAddress RemoteAddress
        {
            get;
            private set;
        }

        public ulong OwnerPid
        {
            get;
            private set;
        }

        public string OwnerProcessPath
        {
            get
            {
                try
                {
                    return ProcessUtilities.GetProcessName(OwnerPid);
                }
                catch(Exception e)
                {
                    LoggerProxy.Default.Error(e);
                }

                return string.Empty;
            }
        }

        public MibTcpState State
        {
            get;
            private set;
        }

        public TcpConnectionOffloadState OffloadState
        {
            get;
            private set;
        }

        public uint LocalScopeId
        {
            get;
            private set;
        }

        public Tcp6ConnectionInfo(MIB_TCP6ROW2 tcpRow)
        {
            // We mask the ports in this struct because according to the documentation, the upper
            // bits can be populated arbitrarily, aka undefined state.
            LocalPort = (ushort)(tcpRow.dwLocalPort & 0xFFFF);

            RemotePort = (ushort)(tcpRow.dwRemotePort & 0xFFFF);

            LocalAddress = new IPAddress(tcpRow.LocalAddr.u.Byte);

            RemoteAddress = new IPAddress(tcpRow.RemoteAddr.u.Byte);

            State = tcpRow.State;

            OffloadState = tcpRow.dwOffloadState;

            LocalScopeId = tcpRow.dwLocalScopeId;

            OwnerPid = tcpRow.dwOwningPid;
        }
    }

    internal class NetworkTables
    {
        internal static List<ITcpConnectionInfo> GetTcp6Table()
        {
            int tableSize = 0;

            var result = Iphlpapi.GetTcp6Table2(IntPtr.Zero, ref tableSize, false);

            IntPtr tcpTableRecordsPtr = IntPtr.Zero;

            List<ITcpConnectionInfo> fTable = new List<ITcpConnectionInfo>();

            try
            {
                tcpTableRecordsPtr = Marshal.AllocHGlobal(tableSize);

                result = Iphlpapi.GetTcp6Table2(tcpTableRecordsPtr, ref tableSize, false);

                if(result != 0)
                {
                    return fTable;
                }

                var table = (MIB_TCP6TABLE2)Marshal.PtrToStructure(tcpTableRecordsPtr, typeof(MIB_TCP6TABLE2));

                IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr + Marshal.SizeOf(table.dwNumEntries));

                for(int i = 0; i < table.dwNumEntries; ++i)
                {
                    MIB_TCP6ROW2 tcpRow = (MIB_TCP6ROW2)Marshal.PtrToStructure(tableRowPtr, typeof(MIB_TCP6ROW2));

                    fTable.Add(new Tcp6ConnectionInfo(tcpRow));

                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                }

                return fTable;
            }
            catch(OutOfMemoryException me)
            {
                LoggerProxy.Default.Error(me);
            }
            catch(Exception e)
            {
                LoggerProxy.Default.Error(e);
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTableRecordsPtr);
            }

            return fTable;
        }

        internal static List<ITcpConnectionInfo> GetTcp4Table()
        {
            int tableSize = 0;

            var result = Iphlpapi.GetTcpTable2(IntPtr.Zero, ref tableSize, false);

            IntPtr tcpTableRecordsPtr = IntPtr.Zero;

            List<ITcpConnectionInfo> fTable = new List<ITcpConnectionInfo>();

            try
            {
                tcpTableRecordsPtr = Marshal.AllocHGlobal(tableSize);

                result = Iphlpapi.GetTcpTable2(tcpTableRecordsPtr, ref tableSize, false);

                if(result != 0)
                {
                    return fTable;
                }

                var table = Marshal.PtrToStructure<MIB_TCPTABLE2>(tcpTableRecordsPtr);

                IntPtr tableRowPtr = (IntPtr)((long)tcpTableRecordsPtr + Marshal.SizeOf(table.dwNumEntries));

                for(int i = 0; i < table.dwNumEntries; ++i)
                {
                    MIB_TCPROW2 tcpRow = (MIB_TCPROW2)Marshal.PtrToStructure(tableRowPtr, typeof(MIB_TCPROW2));

                    fTable.Add(new Tcp4ConnectionInfo(tcpRow));

                    tableRowPtr = (IntPtr)((long)tableRowPtr + Marshal.SizeOf(tcpRow));
                }

                return fTable;
            }
            catch(OutOfMemoryException me)
            {
                LoggerProxy.Default.Error(me);
            }
            catch(Exception e)
            {
                LoggerProxy.Default.Error(e);
            }
            finally
            {
                Marshal.FreeHGlobal(tcpTableRecordsPtr);
            }

            return fTable;
        }
    }
}