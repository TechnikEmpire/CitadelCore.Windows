/*
 * Copyright © 2017 Jesse Nicholson
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
using CitadelCore.Net.Proxy;
using CitadelCore.Windows.Diversion;
using System.Net;

namespace CitadelCore.Windows.Net.Proxy
{
    public class WindowsProxyServer : ProxyServer
    {
        public WindowsProxyServer(FirewallCheckCallback firewallCallback, MessageBeginCallback messageBeginCallback, MessageEndCallback messageEndCallback) : base(firewallCallback, messageBeginCallback, messageEndCallback)
        {
        }

        protected override IDiverter CreateDiverter(IPEndPoint ipv4HttpEp, IPEndPoint ipv4HttpsEp, IPEndPoint ipv6HttpEp, IPEndPoint ipv6HttpsEp)
        {
            return new WindowsDiverter((ushort)ipv4HttpEp.Port, (ushort)ipv4HttpsEp.Port, (ushort)ipv6HttpEp.Port, (ushort)ipv6HttpsEp.Port);
        }
    }
}