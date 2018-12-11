/*
* Copyright © 2017-Present Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using CitadelCore.Diversion;
using CitadelCore.Net.Proxy;
using CitadelCore.Windows.Diversion;
using System;
using System.Net;

namespace CitadelCore.Windows.Net.Proxy
{
    /// <summary>
    /// The WindowsProxyServer class implements the diversion functionality required for a functional
    /// transparent proxy server on the Windows platform.
    /// </summary>
    public class WindowsProxyServer : ProxyServer
    {
        /// <summary>
        /// The configuration used to create this proxy server instance.
        /// </summary>
        private readonly ProxyServerConfiguration _sourceCfg;

        /// <summary>
        /// Creates a new WindowsProxyServer instance. Really there should only ever be a single
        /// instance created at a time.
        /// </summary>
        /// <param name="configuration">
        /// The proxy server configuration to use.
        /// </param>
        /// <exception cref="ArgumentException">
        /// Will throw if any one of the callbacks in the supplied configuration are not defined.
        /// </exception>
        public WindowsProxyServer(ProxyServerConfiguration configuration) : base(configuration)
        {
            _sourceCfg = configuration;
        }

        /// <summary>
        /// Internal call to create the platform specific packet diverter. In this case, we create a
        /// Windows-specific diverter.
        /// </summary>
        /// <param name="ipv4HttpEp">
        /// The endpoint where the proxy is listening for IPV4 HTTP connections.
        /// </param>
        /// <param name="ipv4HttpsEp">
        /// The endpoint where the proxy is listening for IPV4 HTTPS connections.
        /// </param>
        /// <param name="ipv6HttpEp">
        /// The endpoint where the proxy is listening for IPV6 HTTP connections.
        /// </param>
        /// <param name="ipv6HttpsEp">
        /// The endpoint where the proxy is listening for IPV6 HTTPS connections.
        /// </param>
        /// <returns>
        /// The platform specific diverter.
        /// </returns>
        protected override IDiverter CreateDiverter(IPEndPoint ipv4HttpEp, IPEndPoint ipv4HttpsEp, IPEndPoint ipv6HttpEp, IPEndPoint ipv6HttpsEp)
        {
            var diverter = new WindowsDiverter((ushort)ipv4HttpEp.Port, (ushort)ipv4HttpsEp.Port, (ushort)ipv6HttpEp.Port, (ushort)ipv6HttpsEp.Port)
            {
                DropExternalProxies = _sourceCfg != null ? _sourceCfg.BlockExternalProxies : true
            };
            return diverter;
        }
    }
}