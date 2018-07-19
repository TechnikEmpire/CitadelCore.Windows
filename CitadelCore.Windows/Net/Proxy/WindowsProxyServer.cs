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

using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using CitadelCore.Diversion;
using CitadelCore.Net.Proxy;
using CitadelCore.Windows.Diversion;

namespace CitadelCore.Windows.Net.Proxy
{
    /// <summary>
    /// The WindowsProxyServer class implements the diversion functionality required for a functional transparent proxy server on the Windows platform.
    /// </summary>
    public class WindowsProxyServer : ProxyServer
    {
        /// <summary>
        /// Creates a new WindowsProxyServer instance. Really there should only ever be a single instance
        /// created at a time.
        /// </summary>
        /// <param name="configuration">
        /// The proxy server configuration to use.
        /// </param>       
        /// <exception cref="ArgumentException">
        /// Will throw if any one of the callbacks in the supplied configuration are not defined. 
        /// </exception>
        public WindowsProxyServer(ProxyServerConfiguration configuration) : base(configuration)
        {
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
            return new WindowsDiverter((ushort)ipv4HttpEp.Port, (ushort)ipv4HttpsEp.Port, (ushort)ipv6HttpEp.Port, (ushort)ipv6HttpsEp.Port);
        }
    }
}