/*
 * Copyright © 2017-Present Jesse Nicholson
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

using CitadelCore.Diversion;
using CitadelCore.Extensions;
using CitadelCore.Logging;
using CitadelCore.Net.Proxy;
using CitadelCore.Windows.WinAPI;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using WinDivert;

namespace CitadelCore.Windows.Diversion
{
    internal unsafe class WindowsDiverter : IDiverter
    {
        /// <summary>
        /// The local IPV4 port that the filtering proxy server is listening for HTTP connections on. 
        /// </summary>
        private readonly ushort m_v4HttpProxyPort;

        /// <summary>
        /// The local IPV4 port that the filtering proxy server is listening for HTTPS connections on. 
        /// </summary>
        private readonly ushort m_v4HttpsProxyPort;

        /// <summary>
        /// The local IPV6 port that the filtering proxy server is listening for HTTP connections on. 
        /// </summary>
        private readonly ushort m_v6HttpProxyPort;

        /// <summary>
        /// The local IPV6 port that the filtering proxy server is listening for HTTPS connections on. 
        /// </summary>
        private readonly ushort m_v6HttpsProxyPort;

        /// <summary>
        /// Used for tracking which IPV4 TCP connections ought to be forced through the proxy server.
        /// We use the local port of TCP connections as the index to this array.
        /// </summary>
        private readonly int[] m_v4ShouldFilter = new int[ushort.MaxValue];

        /// <summary>
        /// Used for tracking which IPV6 TCP connections ought to be forced through the proxy server.
        /// We use the local port of TCP connections as the index to this array.
        /// </summary>
        private readonly int[] m_v6ShouldFilter = new int[ushort.MaxValue];

        /// <summary>
        /// Used for keeping track of the local port that we are to return packets to after filtering. 
        /// </summary>
        /// <remarks>
        /// In moving toward port-independent filtering, we need to be able to keep track of the
        /// original port that a connection was intercepted on. This way, we can make sure we route
        /// filtered connection data back to the right local port.
        /// </remarks>
        private readonly ushort[] m_v4ReturnPorts = new ushort[ushort.MaxValue];

        /// <summary>
        /// Used for keeping track of the local port that we are to return packets to after filtering. 
        /// </summary>
        /// <remarks>
        /// In moving toward port-independent filtering, we need to be able to keep track of the
        /// original port that a connection was intercepted on. This way, we can make sure we route
        /// filtered connection data back to the right local port.
        /// </remarks>
        private readonly ushort[] m_v6ReturnPorts = new ushort[ushort.MaxValue];

        /// <summary>
        /// Keeps track of user-supplied hints about whether or not a filtered connection is
        /// encrypted. Specific to IPv6 connections.
        /// </summary>
        private readonly bool[] m_v4EncryptionHints = new bool[ushort.MaxValue];

        /// <summary>
        /// Keeps track of user-supplied hints about whether or not a filtered connection is
        /// encrypted. Specific to IPv4 connections.
        /// </summary>
        private readonly bool[] m_v6EncryptionHints = new bool[ushort.MaxValue];

        /// <summary>
        /// Constant for port 80 TCP aka HTTP. 
        /// </summary>
        private const ushort s_httpStandardPort = 80;

        /// <summary>
        /// Constant for port 80 TCP aka HTTP alt port. 
        /// </summary>
        private const ushort s_httpAltPort = 8080;

        /// <summary>
        /// Constant for port 443 TCP aka HTTPS. 
        /// </summary>
        private const ushort s_httpsStandardPort = 443;

        /// <summary>
        /// Constant for port 443 TCP aka HTTPS alt port. 
        /// </summary>
        private const ushort s_httpsAltPort = 8443;

        /// <summary>
        /// Our process ID. We use this to ignore packets originating from within our own software. 
        /// </summary>
        private readonly ulong m_thisPid = (ulong)Process.GetCurrentProcess().Id;

        /// <summary>
        /// Flag for the main processing loop. 
        /// </summary>
        private volatile bool m_running = false;

        /// <summary>
        /// For synchronizing startup and shutdown. 
        /// </summary>
        private readonly object m_startStopLock = new object();

        /// <summary>
        /// WinDivert driver handle. 
        /// </summary>
        private IntPtr m_diversionHandle = IntPtr.Zero;

        /// <summary>
        /// WinDivert handle that simply drops all UDP packets destined for port 80 and 443 in order
        /// to render QUIC inoperable.
        /// </summary>
        private IntPtr m_QUICDropHandle = IntPtr.Zero;

        /// <summary>
        /// Collection of threads running against the WinDivert driver. 
        /// </summary>
        private List<Thread> m_diversionThreads;

        /// <summary>
        /// Gets whether or not the diverter is currently active. 
        /// </summary>
        public bool IsRunning
        {
            get
            {
                return m_running;
            }
        }

        /// <summary>
        /// Optional callback that allows the user to determine if a specific binary should have its
        /// traffic sent through the filter, which implicitly permits network access.
        /// </summary>
        public FirewallCheckCallback ConfirmDenyFirewallAccess
        {
            get;
            set;
        }

        /// <summary>
        /// Constructs a new WindowsDiverter instance. 
        /// </summary>
        /// <param name="v4httpProxyPort">
        /// The IPV4 port that the filtering proxy server is listening for HTTP connections on. 
        /// </param>
        /// <param name="v4httpsProxyPort">
        /// The IPV4 port that the filtering proxy server is listening for HTTPS connections on. 
        /// </param>
        /// <param name="v6httpProxyPort">
        /// The IPV6 port that the filtering proxy server is listening for HTTP connections on. 
        /// </param>
        /// <param name="v6httpsProxyPort">
        /// The IPV6 port that the filtering proxy server is listening for HTTPS connections on. 
        /// </param>
        public WindowsDiverter(ushort v4httpProxyPort, ushort v4httpsProxyPort, ushort v6httpProxyPort, ushort v6httpsProxyPort)
        {
            m_v4HttpProxyPort = v4httpProxyPort;
            m_v4HttpsProxyPort = v4httpsProxyPort;

            m_v6HttpProxyPort = v6httpProxyPort;
            m_v6HttpsProxyPort = v6httpsProxyPort;
        }

        /// <summary>
        /// Starts the packet diversion with the given number of threads. 
        /// </summary>
        /// <param name="numThreads">
        /// The number of threads to use for diversion. If equal to or less than zero, will default
        /// to Environment.ProcessorCount.
        /// </param>
        /// <remarks>
        /// The number of threads ought not to exceed Environment.ProcessorCount but this is not
        /// enforced with a bounds check.
        /// </remarks>
        public void Start(int numThreads)
        {
            lock (m_startStopLock)
            {
                if (m_running)
                {
                    return;
                }

                if (numThreads <= 0)
                {
                    numThreads = Environment.ProcessorCount;
                }

                m_diversionThreads = new List<Thread>();

#if ENGINE_NO_BLOCK_TOR
                string mainFilterString = "outbound and tcp and ((ip and ip.SrcAddr != 127.0.0.1) or (ipv6 and ipv6.SrcAddr != ::1))";
#else
                string mainFilterString = "outbound and tcp";
#endif
                string QUICFilterString = "udp and (udp.DstPort == 80 || udp.DstPort == 443)";

                m_diversionHandle = WinDivertMethods.WinDivertOpen(mainFilterString, WINDIVERT_LAYER.WINDIVERT_LAYER_NETWORK, -1000, 0);

                if (m_diversionHandle == new IntPtr(-1) || m_diversionHandle == IntPtr.Zero)
                {
                    // Invalid handle value.
                    throw new Exception(string.Format("Failed to open main diversion handle. Got Win32 error code {0}.", Marshal.GetLastWin32Error()));
                }

                m_QUICDropHandle = WinDivertMethods.WinDivertOpen(QUICFilterString, WINDIVERT_LAYER.WINDIVERT_LAYER_NETWORK, -999, WinDivertConstants.WINDIVERT_FLAG_DROP);

                if (m_QUICDropHandle == new IntPtr(-1) || m_QUICDropHandle == IntPtr.Zero)
                {
                    // Invalid handle value.
                    throw new Exception(string.Format("Failed to open QUIC diversion handle. Got Win32 error code {0}.", Marshal.GetLastWin32Error()));
                }

                WinDivertMethods.WinDivertSetParam(m_diversionHandle, WINDIVERT_PARAM.WINDIVERT_PARAM_QUEUE_LEN, 8192);
                WinDivertMethods.WinDivertSetParam(m_diversionHandle, WINDIVERT_PARAM.WINDIVERT_PARAM_QUEUE_TIME, 2048);

                m_running = true;

                for (int i = 0; i < numThreads; ++i)
                {
                    m_diversionThreads.Add(new Thread(() =>
                    {
                        RunDiversion();
                    }));

                    m_diversionThreads.Last().Start();
                }
            }
        }

        private void RunDiversion()
        {
            byte[] packet = new byte[65536];

            WINDIVERT_IPHDR* ipV4Header = null;
            WINDIVERT_IPV6HDR* ipV6Header = null;
            WINDIVERT_TCPHDR* tcpHeader = null;

            uint recvLength = 0;

            WINDIVERT_ADDRESS addr = new WINDIVERT_ADDRESS();

            NativeOverlapped recvOverlapped;

            IntPtr recvEvent = IntPtr.Zero;
            uint recvAsyncIoLen = 0;

            bool isLocalIpv4 = false;
            bool modifiedPacket = false;
            bool dropPacket = false;

            byte* payloadBufferPtr = null;
            uint payloadBufferLength = 0;

            while (m_running)
            {
                payloadBufferPtr = null;
                payloadBufferLength = 0;

                recvLength = 0;
                addr.Reset();
                modifiedPacket = false;
                dropPacket = false;
                isLocalIpv4 = false;
                recvAsyncIoLen = 0;

                recvOverlapped = new NativeOverlapped();

                recvEvent = WinApiHelpers.CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero);

                if (recvEvent == IntPtr.Zero)
                {
                    LoggerProxy.Default.Warn("Failed to initialize receive IO event.");
                    continue;
                }

                recvOverlapped.EventHandle = recvEvent;

                fixed (byte* inBuf = packet)
                {
                    #region Packet Reading Code

                    if (!WinDivertMethods.WinDivertRecvEx(m_diversionHandle, packet, (uint)packet.Length, 0, ref addr, ref recvLength, ref recvOverlapped))
                    {
                        var error = Marshal.GetLastWin32Error();

                        // 997 == ERROR_IO_PENDING
                        if (error != 997)
                        {
                            LoggerProxy.Default.Warn(string.Format("Unknown IO error ID {0}while awaiting overlapped result.", error));
                            WinApiHelpers.CloseHandle(recvEvent);
                            continue;
                        }

                        // 258 == WAIT_TIMEOUT
                        while (WinApiHelpers.WaitForSingleObject(recvEvent, 1000) == 258) ;

                        if (!WinApiHelpers.GetOverlappedResult(m_diversionHandle, ref recvOverlapped, ref recvAsyncIoLen, false))
                        {
                            LoggerProxy.Default.Warn("Failed to get overlapped result.");
                            WinApiHelpers.CloseHandle(recvEvent);
                            continue;
                        }

                        recvLength = recvAsyncIoLen;
                        WinApiHelpers.CloseHandle(recvEvent);
                    }

                    #endregion Packet Reading Code

                    if (addr.Direction == WinDivertConstants.WINDIVERT_DIRECTION_OUTBOUND)
                    {
                        WinDivertMethods.WinDivertHelperParsePacket(inBuf, recvLength, &ipV4Header, &ipV6Header, null, null, &tcpHeader, null, &payloadBufferPtr, &payloadBufferLength);

                        #region New TCP Connection Detection

                        if (tcpHeader != null && tcpHeader->Syn > 0)
                        {
                            // Brand new outbound connection. Grab the PID of the process holding
                            // this port and map it.
                            if (ipV4Header != null)
                            {
                                var connInfo = GetLocalPacketInfo(tcpHeader->SrcPortNw, ipV4Header->SrcAddr);

                                HandleNewTcpConnection(connInfo, tcpHeader, false);

                                // Handle the special case of entirely blocking internet for this application/port.
                                if (Volatile.Read(ref m_v4ShouldFilter[tcpHeader->SrcPort]) == (int)FirewallAction.BlockInternetForApplication)
                                {
                                    dropPacket = true;
                                }
                            }

                            if (ipV6Header != null)
                            {
                                var connInfo = GetLocalPacketInfo(tcpHeader->SrcPortNw, ipV6Header->SrcAddr);

                                HandleNewTcpConnection(connInfo, tcpHeader, true);

                                // Handle the special case of entirely blocking internet for this application/port.
                                if (Volatile.Read(ref m_v6ShouldFilter[tcpHeader->SrcPort]) == (int)FirewallAction.BlockInternetForApplication)
                                {
                                    dropPacket = true;
                                }
                            }
                        }

                        #endregion New TCP Connection Detection

                        // I put the checks for ipv4 and ipv6 as a double if statement rather than an
                        // else if because I'm not sure how that would affect dual-mode sockets.
                        // Perhaps it's possible for both headers to be defined. Probably not, but
                        // since I don't know, I err on the side of awesome, or uhh, something like that.

                        // We check local packets for TOR/SOCKS packets here. However, if we don't
                        // find something we want to block on local addresses, then we want to skip
                        // these for the rest of the filtering and just let them through.

                        if (dropPacket == false && ipV4Header != null && tcpHeader != null)
                        {
                            // Let's explain the weird arcane logic here. First, we check if the
                            // current flow should even be filtered. We do this, because there's a
                            // good chance that this flow belongs to our proxy's connections, which
                            // we never want to filter. If we didn't check this, then we would end up
                            // setting the isLocalIpv4 flag to true on every single one of our
                            // proxy's connections, and clients would never get packets ever because
                            // with that flag set, the direction of the packets wouldn't be sorted.
                            //
                            // So, we check this, ensure it's actually something we want to filter.
                            // Then, we check if the packet is destined for a local address. We set
                            // the flag accordingly, and if true, then we will allow these packets to
                            // go out uninterrupted.
                            //
                            // If false, who cares. Regardless of true or false, we check to see if
                            // this is a TOR/SOCKS4/5 proxy CONNECT, and drop it if it is.
                            //
                            // Also note, by letting local/private address destined packets go, we
                            // also solve the problem of private TLS connections using private TLS
                            // self signed certs, such as logging into one's router. If we didn't do
                            // this check and let these through, we would break such connections.

                            if (Volatile.Read(ref m_v4ShouldFilter[tcpHeader->SrcPort]) == (int)FirewallAction.FilterApplication)
                            {
                                isLocalIpv4 = ipV4Header->DstAddr.IsPrivateIpv4Address();

                                if (isLocalIpv4)
                                {
#if !ENGINE_NO_BLOCK_TOR
                                    byte[] payload = null;
                                    if (payloadBufferLength > 0)
                                    {
                                        payload = new byte[payloadBufferLength];
                                        Marshal.Copy((IntPtr)payloadBufferPtr, payload, 0, (int)payloadBufferLength);

                                        if (payload.IsSocksProxyConnect())
                                        {
                                            LoggerProxy.Default.Info("Blocking SOCKS proxy connect.");
                                            continue;
                                        }
                                    }
#endif
                                }
                            }
                        }

                        if (dropPacket == false && !isLocalIpv4)
                        {
                            if (ipV4Header != null && tcpHeader != null)
                            {
                                if (tcpHeader->SrcPort == m_v4HttpProxyPort || tcpHeader->SrcPort == m_v4HttpsProxyPort)
                                {
                                    // Means that the data is originating from our proxy in response
                                    // to a client's request, which means it was originally meant to
                                    // go somewhere else. We need to reorder the data such as the src
                                    // and destination ports and addresses and divert it back
                                    // inbound, so it appears to be an inbound response from the
                                    // original external server.

                                    modifiedPacket = true;

                                    tcpHeader->SrcPort = Volatile.Read(ref m_v4ReturnPorts[tcpHeader->DstPort]);
                                    addr.Direction = WinDivertConstants.WINDIVERT_DIRECTION_INBOUND;

                                    var dstIp = ipV4Header->DstAddr;
                                    ipV4Header->DstAddr = ipV4Header->SrcAddr;
                                    ipV4Header->SrcAddr = dstIp;
                                }
                                else
                                {
                                    // This means outbound traffic has been captured that we know for
                                    // sure is not coming from our proxy in response to a client, but
                                    // we don't know that it isn't the upstream portion of our proxy
                                    // trying to fetch a response on behalf of a connected client.
                                    // So, we need to check if we have a cached result for
                                    // information about the binary generating the outbound traffic
                                    // for two reasons.
                                    //
                                    // First, we need to ensure that it's not us, obviously.
                                    // Secondly, we need to ensure that the binary has been granted
                                    // firewall access to generate outbound traffic.

                                    if (Volatile.Read(ref m_v4ShouldFilter[tcpHeader->SrcPort]) == (int)FirewallAction.FilterApplication)
                                    {
                                        modifiedPacket = true;

                                        // If the process was identified as a process that is
                                        // permitted to access the internet, and is not a system
                                        // process or ourselves, then we divert its packets back
                                        // inbound to the local machine, changing the destination
                                        // port appropriately.
                                        var dstAddress = ipV4Header->DstAddr;

                                        ipV4Header->DstAddr = ipV4Header->SrcAddr;
                                        ipV4Header->SrcAddr = dstAddress;

                                        addr.Direction = WinDivertConstants.WINDIVERT_DIRECTION_INBOUND;

                                        Volatile.Write(ref m_v4ReturnPorts[tcpHeader->SrcPort], tcpHeader->DstPort);

                                        // Unless we know for sure this is an encrypted connection
                                        // via the HTTP port, we should always default to sending to
                                        // the non-encrypted listener.
                                        var encrypted = Volatile.Read(ref m_v4EncryptionHints[tcpHeader->SrcPort]);

                                        tcpHeader->DstPort = encrypted ? m_v4HttpsProxyPort : m_v4HttpProxyPort;
                                    }
                                }
                            }

                            // The ipV6 version works exactly the same, just with larger storage for
                            // the larger addresses. Look at the ipv4 version notes for clarification
                            // on anything.
                            if (ipV6Header != null && tcpHeader != null)
                            {
                                if (tcpHeader->SrcPort == m_v6HttpProxyPort || tcpHeader->SrcPort == m_v6HttpsProxyPort)
                                {
                                    modifiedPacket = true;

                                    tcpHeader->SrcPort = Volatile.Read(ref m_v6ReturnPorts[tcpHeader->DstPort]);
                                    addr.Direction = WinDivertConstants.WINDIVERT_DIRECTION_INBOUND;

                                    var dstIp = ipV6Header->DstAddr;
                                    ipV6Header->DstAddr = ipV6Header->SrcAddr;
                                    ipV6Header->SrcAddr = dstIp;
                                }
                                else
                                {
                                    if (Volatile.Read(ref m_v6ShouldFilter[tcpHeader->SrcPort]) == (int)FirewallAction.FilterApplication)
                                    {
                                        modifiedPacket = true;

                                        // If the process was identified as a process that is
                                        // permitted to access the internet, and is not a system
                                        // process or ourselves, then we divert its packets back
                                        // inbound to the local machine, changing the destination
                                        // port appropriately.
                                        var dstAddress = ipV6Header->DstAddr;

                                        ipV6Header->DstAddr = ipV6Header->SrcAddr;
                                        ipV6Header->SrcAddr = dstAddress;

                                        addr.Direction = WinDivertConstants.WINDIVERT_DIRECTION_INBOUND;

                                        Volatile.Write(ref m_v6ReturnPorts[tcpHeader->SrcPort], tcpHeader->DstPort);

                                        // Unless we know for sure this is an encrypted connection
                                        // via the HTTP port, we should always default to sending to
                                        // the non-encrypted listener.
                                        var encrypted = Volatile.Read(ref m_v6EncryptionHints[tcpHeader->SrcPort]);

                                        tcpHeader->DstPort = encrypted ? m_v6HttpsProxyPort : m_v6HttpProxyPort;
                                    }
                                }
                            }
                        } // if(!isLocalIpv4)
                    }// if (addr.Direction == WINDIVERT_DIRECTION_OUTBOUND)

                    if (dropPacket)
                    {
                        LoggerProxy.Default.Warn("Dropping packet.");
                        continue;
                    }

                    if (modifiedPacket)
                    {
                        WinDivertMethods.WinDivertHelperCalcChecksums(packet, recvLength, 0);
                    }
                    else
                    {
                        WinDivertMethods.WinDivertHelperCalcChecksums(packet, recvLength, WinDivertHelpers.WINDIVERT_HELPER_NO_REPLACE);
                    }

                    WinDivertMethods.WinDivertSendEx(m_diversionHandle, packet, recvLength, 0, ref addr, IntPtr.Zero, IntPtr.Zero);
                } // fixed (byte* inBuf = packet)
            } // while (m_running)
        }

        /// <summary>
        /// If running, stops the diversion process and disposes of diversion handles. 
        /// </summary>
        public void Stop()
        {
            lock (m_startStopLock)
            {
                if (!m_running)
                {
                    return;
                }

                m_running = false;

                foreach (var dt in m_diversionThreads)
                {
                    dt.Join();
                }

                WinDivertMethods.WinDivertClose(m_diversionHandle);
                WinDivertMethods.WinDivertClose(m_QUICDropHandle);
            }
        }

        /// <summary>
        /// Handles the process of inspecting a new TCP connection, seeking the user's decision on
        /// what to do with the connection, and then applying that decision in code in such a way as
        /// to cause the packet filtering loop to apply the user's decision.
        /// </summary>
        /// <param name="connInfo">
        /// The state of the appropriate TCP table at the time of the new connectio. 
        /// </param>
        /// <param name="tcpHeader">
        /// The TCP header from the first packet in the new connection/flow. 
        /// </param>
        /// <param name="isIpv6">
        /// Whether or not this is from an IPV6 connection. 
        /// </param>
        private void HandleNewTcpConnection(ITcpConnectionInfo connInfo, WINDIVERT_TCPHDR* tcpHeader, bool isIpv6)
        {
            if (tcpHeader != null)
            {
                if (connInfo != null && connInfo.OwnerPid == m_thisPid)
                {
                    // This is our process.
                    switch (isIpv6)
                    {
                        case true:
                            {
                                Volatile.Write(ref m_v6ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);
                            }
                            break;

                        case false:
                            {
                                Volatile.Write(ref m_v4ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);
                            }
                            break;
                    }
                }
                else
                {
                    FirewallResponse response = null;
                    if (connInfo == null || connInfo.OwnerPid == 4 || connInfo.OwnerPid == 0)
                    {
                        var firewallRequest = new FirewallRequest("SYSTEM", tcpHeader->SrcPort, tcpHeader->DstPort);
                        response = ConfirmDenyFirewallAccess?.Invoke(firewallRequest);
                    }
                    else
                    {
                        // No need to null check here, because the above IF catches whenever connInfo
                        // is null.
                        var procPath = connInfo.OwnerProcessPath.Length > 0 ? connInfo.OwnerProcessPath : "SYSTEM";
                        var firewallRequest = new FirewallRequest(procPath, tcpHeader->SrcPort, tcpHeader->DstPort);
                        response = ConfirmDenyFirewallAccess?.Invoke(firewallRequest);
                    }

                    if (response == null)
                    {   
                        // The user couldn't be bothered to give us an answer, so just go ahead and
                        // let the packet through.

                        switch (isIpv6)
                        {
                            case true:
                                {
                                    Volatile.Write(ref m_v6ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);

                                    Volatile.Write(ref m_v6EncryptionHints[tcpHeader->SrcPort], (tcpHeader->DstPort == s_httpsStandardPort || tcpHeader->DstPort == s_httpsAltPort));
                                }
                                break;

                            case false:
                                {
                                    Volatile.Write(ref m_v4ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);

                                    Volatile.Write(ref m_v4EncryptionHints[tcpHeader->SrcPort], (tcpHeader->DstPort == s_httpsStandardPort || tcpHeader->DstPort == s_httpsAltPort));
                                }
                                break;
                        }
                    }
                    else
                    {   
                        switch (isIpv6)
                        {
                            case true:
                                {
                                    Volatile.Write(ref m_v6ShouldFilter[tcpHeader->SrcPort], (int)response.Action);

                                    Volatile.Write(ref m_v6EncryptionHints[tcpHeader->SrcPort], response.EncryptedHint ?? (tcpHeader->DstPort == s_httpsStandardPort || tcpHeader->DstPort == s_httpsAltPort));
                                }
                                break;

                            case false:
                                {
                                    Volatile.Write(ref m_v4ShouldFilter[tcpHeader->SrcPort], (int)response.Action);

                                    Volatile.Write(ref m_v4EncryptionHints[tcpHeader->SrcPort], response.EncryptedHint ?? (tcpHeader->DstPort == s_httpsStandardPort || tcpHeader->DstPort == s_httpsAltPort));
                                }
                                break;
                        }
                    }
                }
            }
            else
            {
                // Somehow we fail to have even a valid TCP header here. Let the connection go
                // through, but warn.
                LoggerProxy.Default.Warn("TCP header was a null pointer. Allowing packet.");

                Volatile.Write(ref m_v4ShouldFilter[tcpHeader->SrcPort], (int)FirewallAction.DontFilterApplication);
            }
        }

        private ITcpConnectionInfo GetLocalPacketInfo(ushort localPort, IPAddress localAddress)
        {
            switch (localAddress.AddressFamily)
            {
                case System.Net.Sockets.AddressFamily.InterNetwork:
                    {
                        return NetworkTables.GetTcp4Table().Where(x => x.LocalPort == localPort && (x.LocalAddress.Equals(localAddress) || x.LocalAddress.Equals(IPAddress.Any))).FirstOrDefault();
                    }

                case System.Net.Sockets.AddressFamily.InterNetworkV6:
                    {
                        return NetworkTables.GetTcp6Table().Where(x => x.LocalPort == localPort && (x.LocalAddress.Equals(localAddress) || x.LocalAddress.Equals(IPAddress.IPv6Any))).FirstOrDefault();
                    }
            }

            return null;
        }
    }
}