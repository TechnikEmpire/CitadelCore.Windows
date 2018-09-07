/*
* Copyright © 2017-Present Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using CitadelCore.IO;
using CitadelCore.Logging;
using CitadelCore.Net.Http;
using CitadelCore.Net.Proxy;
using CitadelCore.Windows.Net.Proxy;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Text;
using System.Threading;
using WindowsFirewallHelper;

namespace CitadelCoreTest
{
    internal class Program
    {
        private static byte[] s_blockPageBytes;

        private static readonly ushort s_standardHttpPortNetworkOrder = (ushort)IPAddress.HostToNetworkOrder((short)80);
        private static readonly ushort s_standardHttpsPortNetworkOrder = (ushort)IPAddress.HostToNetworkOrder((short)443);

        private static FirewallResponse OnFirewallCheck(FirewallRequest request)
        {
            // Only filter chrome.
            var filtering = request.BinaryAbsolutePath.IndexOf("chrome", StringComparison.OrdinalIgnoreCase) != -1;

            if (filtering)
            {
                if (request.RemotePort == s_standardHttpPortNetworkOrder || request.RemotePort == s_standardHttpsPortNetworkOrder)
                {
                    // Let's allow chrome to access TCP 80 and 443, but block all other ports.
                    Console.WriteLine("Filtering application {0} destined for {1}", request.BinaryAbsolutePath, (ushort)IPAddress.HostToNetworkOrder((short)request.RemotePort));
                    return new FirewallResponse(CitadelCore.Net.Proxy.FirewallAction.FilterApplication);
                }
                else
                {
                    // Let's allow chrome to access TCP 80 and 443, but block all other
                    // ports. This is where we're blocking any non-80/443 bound transmission.
                    Console.WriteLine("Blocking internet for application {0} destined for {1}", request.BinaryAbsolutePath, (ushort)IPAddress.HostToNetworkOrder((short)request.RemotePort));
                    return new FirewallResponse(CitadelCore.Net.Proxy.FirewallAction.BlockInternetForApplication);
                }
            }

            // For all other applications, just let them access the internet without filtering.
            Console.WriteLine("Not filtering application {0} destined for {1}", request.BinaryAbsolutePath, (ushort)IPAddress.HostToNetworkOrder((short)request.RemotePort));
            return new FirewallResponse(CitadelCore.Net.Proxy.FirewallAction.DontFilterApplication);
        }

        /// <summary>
        /// Force all bing-destined requests to go to yahoo.com.
        /// </summary>
        /// <param name="messageInfo">
        /// The message info.
        /// </param>
        private static bool RedirectBingToYahoo(HttpMessageInfo messageInfo)
        {
            if (messageInfo.MessageType == MessageType.Request && messageInfo.Url.Host.Contains("bing."))
            {
                messageInfo.MakeTemporaryRedirect("https://www.yahoo.com");
                messageInfo.ProxyNextAction = ProxyNextAction.DropConnection;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Rewrites the message URL to force safe search on if the host is a google.X domain.
        /// </summary>
        /// <param name="messageInfo">
        /// The message info.
        /// </param>
        private static void ForceGoogleSafeSearch(HttpMessageInfo messageInfo)
        {
            // If the host has google in it, we'll append the safe search command.
            if(messageInfo.Url.Host.IndexOf("google.", StringComparison.OrdinalIgnoreCase) > -1)
            {
                // Take everything but query params.
                string newUri = messageInfo.Url.GetLeftPart(UriPartial.Path);

                // Parse the params.
                var queryParams = QueryHelpers.ParseQuery(messageInfo.Url.Query);
                
                // Iterate over all parsed params.
                foreach (var param in queryParams)
                {   
                    // Skip any param named "safe" because who knows, the user might
                    // explicitly have &safe=inative, disabling safe search, so just
                    // ignore anything named this.
                    if (param.Key.Equals("safe", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    // Anything not "safe" param, append to the new URI.
                    foreach (var value in param.Value)
                    {
                        newUri = QueryHelpers.AddQueryString(newUri, param.Key, value);
                    }
                }

                // When we're all done, append safe search enforcement.
                newUri = QueryHelpers.AddQueryString(newUri, "safe", "active");

                // if we end up with a valid URI, overwrite it.
                if (Uri.TryCreate(newUri, UriKind.Absolute, out Uri result))
                {
                    messageInfo.Url = result;
                }
            }
        }

        /// <summary>
        /// Called whenever a new request or response message is intercepted.
        /// </summary>
        /// <param name="messageInfo">
        /// The message info.
        /// </param>
        /// <remarks>
        /// In this callback we can do all kinds of crazy things, including fully modify the HTTP
        /// headers, the request target, etc etc.
        /// </remarks>
        private static void OnNewMessage(HttpMessageInfo messageInfo)
        {
            ForceGoogleSafeSearch(messageInfo);

            if (RedirectBingToYahoo(messageInfo))
            {
                return;
            }

            // Block only this casino website.
            if (messageInfo.Url.Host.Equals("777.com", StringComparison.OrdinalIgnoreCase))
            {
                messageInfo.MessageType = MessageType.Response;
                messageInfo.ProxyNextAction = ProxyNextAction.DropConnection;
                messageInfo.BodyContentType = "text/html";
                messageInfo.Body = s_blockPageBytes;
                return;
            }

            // By default, allow and ignore content, but not any responses to this content.
            messageInfo.ProxyNextAction = ProxyNextAction.AllowAndIgnoreContent;

            // If the new message is a response, we want to inspect the payload if it is HTML.
            if (messageInfo.MessageType == MessageType.Response)
            {
                foreach (string headerName in messageInfo.Headers)
                {
                    if (messageInfo.Headers[headerName].IndexOf("html") != -1)
                    {
                        Console.WriteLine("Requesting to inspect HTML response for request {0}.", messageInfo.Url);
                        messageInfo.ProxyNextAction = ProxyNextAction.AllowButRequestContentInspection;
                        return;
                    }                    
                }

                // The other kind of filtering we want to do here is to monitor video
                // streams. So, if we find a video content type in a response, we'll subscribe
                // the very new, and extremely exciting streaming inspection callback!!!!!
                var contentTypeKey = "Content-Type";                
                var contentType = messageInfo.Headers[contentTypeKey];

                if (contentType != null && (contentType.IndexOf("video/", StringComparison.OrdinalIgnoreCase) != -1 || contentType.IndexOf("mpeg", StringComparison.OrdinalIgnoreCase) != -1))
                {
                    // Means we have a video response coming.
                    // We want to get the video stream too! Because we have the tools to tell
                    // if video is naughty or nice!
                    Console.WriteLine("Requesting to inspect streamed video response.");
                    messageInfo.ProxyNextAction = ProxyNextAction.AllowButRequestStreamedContentInspection;
                }
            }
        }

        /// <summary>
        /// Called whenever we've requested to inspect an entire message payload.
        /// </summary>
        /// <param name="messageInfo">
        /// The message info.
        /// </param>
        private static void OnWholeBodyContentInspection(HttpMessageInfo messageInfo)
        {
            if (messageInfo.Body.Length > 0)
            {
                // We assume it's HTML because HTML is the only type we request
                // to inspect, but you can double-check if you'd like.
                // We should check Content-Type for charset=XXXX.
                var htmlResponse = Encoding.UTF8.GetString(messageInfo.Body.ToArray());

                // Any HTML that has 777.com in it, we want to block.
                if (htmlResponse.IndexOf("777.com") != -1)
                {
                    Console.WriteLine("Request {0} blocked by content inspection.", messageInfo.Url);
                    messageInfo.ProxyNextAction = ProxyNextAction.DropConnection;
                }
            }
        }

        /// <summary>
        /// Called whenever we've subscribed to monitor a payload in a streaming fashion. This is
        /// useful for say, virus scanning without forcing the entire payload to be buffered into
        /// memory before it is streamed to the user, or to monitor and decode video on the fly
        /// without affecting the user. You can terminate the stream at any time while monitoring.
        /// </summary>
        /// <param name="messageInfo">
        /// The originating http message item.
        /// </param>
        /// <param name="operation">
        /// The operation kind.
        /// </param>
        /// <param name="buffer">
        /// The data that passed through the stream.
        /// </param>
        /// <param name="dropConnection">
        /// Whether or not to immediately terminate the connection.
        /// </param>
        private static void OnStreamedContentInspection(HttpMessageInfo messageInfo, StreamOperation operation, Memory<byte> buffer, out bool dropConnection)
        {
            var toFrom = operation == StreamOperation.Read ? "from" : "to";
            Console.WriteLine($"Stream {operation} {buffer.Length} bytes {toFrom} {messageInfo.Url}");
            dropConnection = false;

            // Drop googlevideo.com videos.
            if (messageInfo.Url.Host.IndexOf(".googlevideo.com") > -1)
            {
                // This basically means you can't watch anything on youtube. You can still load the
                // site, but you can't play any videos.
                // This is just to demonstrate that it's possible to have complete
                // control over unbuffered streams.
                dropConnection = true;
            }
        }

        private static void GrantSelfFirewallAccess()
        {
            string processName = System.Diagnostics.Process.GetCurrentProcess().ProcessName;
            var hostAssembly = Assembly.GetEntryAssembly() ?? Assembly.GetExecutingAssembly();

            // We want to delete all rules that match our process name, so we can create new ones
            // that we know will work.
            var myRules = FirewallManager.Instance.Rules.Where(r => r.Name.Equals(processName, StringComparison.OrdinalIgnoreCase)).ToList();
            if (myRules != null)
            {
                foreach (var rule in myRules)
                {
                    FirewallManager.Instance.Rules.Remove(rule);
                }
            }

            // Allow all inbound and outbound communications from our process.
            var inboundRule = FirewallManager.Instance.CreateApplicationRule(
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
                processName,
                WindowsFirewallHelper.FirewallAction.Allow, hostAssembly.Location
            );
            inboundRule.Direction = FirewallDirection.Inbound;

            FirewallManager.Instance.Rules.Add(inboundRule);

            var outboundRule = FirewallManager.Instance.CreateApplicationRule(
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public,
                processName,
                WindowsFirewallHelper.FirewallAction.Allow, hostAssembly.Location
            );
            outboundRule.Direction = FirewallDirection.Outbound;

            // Add the rules to the manager, which will commit them to Windows.
            FirewallManager.Instance.Rules.Add(outboundRule);
        }

        private static void Main(string[] args)
        {
            GrantSelfFirewallAccess();

            s_blockPageBytes = File.ReadAllBytes(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "BlockedPage.html"));

            // Let the user decide when to quit with ctrl+c.
            var manualResetEvent = new ManualResetEvent(false);

            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                manualResetEvent.Set();
                Console.WriteLine("Shutting Down");
            };

            // Hooking into these properties gives us an abstract interface where we may use
            // informational, warning and error messages generated by the internals of the proxy in
            // whatsoever way we see fit, though the design was to allow users to choose logging mechanisms.
            LoggerProxy.Default.OnInfo += (msg) =>
            {
                Console.WriteLine("INFO: {0}", msg);
            };

            LoggerProxy.Default.OnWarning += (msg) =>
            {
                Console.WriteLine("WARN: {0}", msg);
            };

            LoggerProxy.Default.OnError += (msg) =>
            {
                Console.WriteLine("ERRO: {0}", msg);
            };

            var cfg = new ProxyServerConfiguration
            {
                AuthorityName = "Fake Authority",
                FirewallCheckCallback = OnFirewallCheck,
                NewHttpMessageHandler = OnNewMessage,
                HttpMessageWholeBodyInspectionHandler = OnWholeBodyContentInspection,
                HttpMessageStreamedInspectionHandler = OnStreamedContentInspection
            };
            

            // Just create the server.
            var proxyServer = new WindowsProxyServer(cfg);

            // Give it a kick.
            proxyServer.Start(0);

            // And you're up and running.
            Console.WriteLine("Proxy Running");

            Console.WriteLine("Listening for IPv4 HTTP connections on port {0}.", proxyServer.V4HttpEndpoint.Port);
            Console.WriteLine("Listening for IPv4 HTTPS connections on port {0}.", proxyServer.V4HttpsEndpoint.Port);
            Console.WriteLine("Listening for IPv6 HTTP connections on port {0}.", proxyServer.V6HttpEndpoint.Port);
            Console.WriteLine("Listening for IPv6 HTTPS connections on port {0}.", proxyServer.V6HttpsEndpoint.Port);

            // Don't exit on me yet fam.
            manualResetEvent.WaitOne();

            Console.WriteLine("Exiting.");

            // Stop if you must.
            proxyServer.Stop();
        }
    }
}