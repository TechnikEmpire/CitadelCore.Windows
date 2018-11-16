/*
* Copyright © 2017-Present Jesse Nicholson
* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/.
*/

using CitadelCore.Extensions;
using CitadelCore.IO;
using CitadelCore.Logging;
using CitadelCore.Net.Http;
using CitadelCore.Net.Proxy;
using CitadelCore.Windows.Net.Proxy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using WindowsFirewallHelper;

namespace CitadelCoreTest
{
    internal class Program
    {
        private static byte[] s_blockPageBytes;

        private static readonly ushort s_standardHttpPortNetworkOrder = (ushort)IPAddress.HostToNetworkOrder((short)80);
        private static readonly ushort s_standardHttpsPortNetworkOrder = (ushort)IPAddress.HostToNetworkOrder((short)443);
        private static readonly ushort s_altHttpPortNetworkOrder = (ushort)IPAddress.HostToNetworkOrder((short)8080);
        private static readonly ushort s_altHttpsPortNetworkOrder = (ushort)IPAddress.HostToNetworkOrder((short)8443);

        /// <summary>
        /// We pass this in to stream copy operations whenever the user has asked us to pull a
        /// payload from the net into memory. We set a hard limit of ~128 megs simply to avoid being
        /// vulnerable to an attack that would balloon memory consumption.
        /// </summary>
        private static readonly long s_maxInMemoryData = 128000000;

        private static HttpClient s_client = new HttpClient(new HttpClientHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            UseCookies = false,
            ClientCertificateOptions = ClientCertificateOption.Automatic,
            AllowAutoRedirect = true,
            Proxy = null
        }, true);

        private static FirewallResponse OnFirewallCheck(FirewallRequest request)
        {
            // Only filter chrome.
            //var filtering = request.BinaryAbsolutePath.IndexOf("chrome", StringComparison.OrdinalIgnoreCase) != -1;
            var filtering = true;

            if (filtering)
            {
                if (
                    request.RemotePort == s_standardHttpPortNetworkOrder || 
                    request.RemotePort == s_standardHttpsPortNetworkOrder ||
                    request.RemotePort == s_altHttpPortNetworkOrder ||
                    request.RemotePort == s_altHttpsPortNetworkOrder
                    )
                {
                    // Let's allow chrome to access TCP 80 and 443, but block all other ports.
                    //Console.WriteLine("Filtering application {0} destined for {1}", request.BinaryAbsolutePath, (ushort)IPAddress.HostToNetworkOrder((short)request.RemotePort));
                    return new FirewallResponse(CitadelCore.Net.Proxy.FirewallAction.FilterApplication);
                }
                else
                {
                    // Let's allow chrome to access TCP 80 and 443, but ignore all other
                    // ports. We want to allow non 80/443 requests to go through because
                    // this example now demonstrates the replay API, which will cause
                    // a bunch of browser tabs to open whenever you visit my website.
                    //
                    // If we filtered the replays back through the proxy, who knows
                    // what would happen! Actually that's not true, you'd invoke an infinite
                    // loopback, spawn a ton of browser tabs and then call me a bad programmer.
                    //Console.WriteLine("Ignoring internet for application {0} destined for {1}", request.BinaryAbsolutePath, (ushort)IPAddress.HostToNetworkOrder((short)request.RemotePort));
                    return new FirewallResponse(CitadelCore.Net.Proxy.FirewallAction.DontFilterApplication);
                }
            }

            // For all other applications, just let them access the internet without filtering.
            //Console.WriteLine("Not filtering application {0} destined for {1}", request.BinaryAbsolutePath, (ushort)IPAddress.HostToNetworkOrder((short)request.RemotePort));
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
        /// Checks whether the host is MSNBC.com and if so, we will tell the proxy to let us fulfill
        /// the request ourselves.
        /// </summary>
        /// <param name="messageInfo">
        /// The message info.
        /// </param>
        /// <returns>
        /// True if we should fulfill the request ourselves, false otherwise.
        /// </returns>
        private static bool ManuallyFulfill(HttpMessageInfo messageInfo)
        {
            if (messageInfo.MessageType == MessageType.Request)
            {
                if (messageInfo.Url.Host.Equals("msnbc.com", StringComparison.OrdinalIgnoreCase))
                {
                    messageInfo.ProxyNextAction = ProxyNextAction.AllowButDelegateHandler;
                    return true;
                }
            }

            return false;
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
            if (messageInfo.BodyContentType != string.Empty)
            {
                Console.WriteLine("New message with content of type: {0}\n\t{1}\n\t{2}", messageInfo.BodyContentType, messageInfo.Url, messageInfo.MessageProtocol);
            }
            else
            {
                Console.WriteLine("New message: {0}\n\t{1}", messageInfo.Url, messageInfo.MessageProtocol);
            }
            

            ForceGoogleSafeSearch(messageInfo);

            if (RedirectBingToYahoo(messageInfo))
            {
                return;
            }

            if (ManuallyFulfill(messageInfo))
            {
                return;
            }

            // Get Technikempire.com as a replay request. 
            // Replay requests are only available on response message types.
            // This will cause us to receive a request URI on the IpV4 loopback adapter
            // that will enable us to "replay" the request.
            //
            // This "replay" is a mirroring of the data, allowing it to pass through
            // but being duplicated in real time. This means you can inspect the
            // stream in-parallel without interrupting the original stream.
            //
            // At any time, you can force the original, mirrored stream to abort and
            // close by invoking the callback provided in the relay inspection
            // callback handler.
            if (messageInfo.Url.Host.Equals("technikempire.com", StringComparison.OrdinalIgnoreCase))
            {
                messageInfo.ProxyNextAction = ProxyNextAction.AllowButRequestResponseReplay;
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
                // dropConnection = true;
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

        /// <summary>
        /// Called whenever a requested replay is available for access.
        /// </summary>
        /// <param name="replayUrl">
        /// The localhost URL to request the replay on.
        /// </param>
        /// <param name="cancellationCallback">
        /// A callback that you can use to terminate the playback and, optionally, the source stream with.
        /// </param>
        private static void OnReplayInspection(HttpMessageInfo messageInfo, string replayUrl, HttpReplayTerminationCallback cancellationCallback)
        {
            // Just get the default browser to open the URL.
            Console.WriteLine(replayUrl);
            Process.Start(replayUrl);

            // Note - Once you access a replay, it's gone. Resources are flushed and it's not persisted anywhere.
            // Note - You must access a replay as soon as possible. There is a 65 megabyte internal memory limit
            // for buffering while waiting for a client to connect.
            // Note - A replay is a verbatum copy, headers and all, of a filtered transaction in progress. It is
            // a real-time duplicate of a filtered stream. The only exception is the transfer-encoding and
            // content-length headers. They will be changed and Kestrel most certainly will always chunk the
            // replay.

            // The original reason for the replay API was to duplicate video streams in real-time so they
            // the duplicate can be fed to Windows Media Foundation and image classification can be
            // performed on the video frames. If and when bad images are found in the video stream,
            // the cancellationCallback can be used to kill the original, source video stream.
        }

        /// <summary>
        /// Called whenever we request to fulfill a request ourselves.
        /// </summary>
        /// <param name="messageInfo">
        /// The message info.
        /// </param>
        /// <param name="context">
        /// The http context to read and write to and from.
        /// </param>
        /// <returns>
        /// Completion task.
        /// </returns>
        private static async Task OnManualFulfillmentCallback(HttpMessageInfo messageInfo, HttpContext context)
        {
            // Create the message AFTER we give the user a chance to alter things.
            var requestMsg = new HttpRequestMessage(messageInfo.Method, messageInfo.Url);

            // Ignore failed headers. We don't really care.
            var initialFailedHeaders = requestMsg.PopulateHeaders(messageInfo.Headers, messageInfo.ExemptedHeaders);

            // Make sure we send the body.
            if (context.Request.Body != null)
            {
                if (context.Request.Body != null && (context.Request.Headers.ContainsKey("Transfer-Encoding") || (context.Request.ContentLength.HasValue && context.Request.ContentLength.Value > 0)))
                {
                    // We have a body, but the user doesn't want to inspect it. So,
                    // we'll just set our content to wrap the context's input stream.
                    requestMsg.Content = new StreamContent(context.Request.Body);
                }
            }

            try
            {
                var response = await s_client.SendAsync(requestMsg, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

                // Blow away all response headers. We wanna clone these now from our upstream request.
                context.Response.ClearAllHeaders();

                // Ensure our client's response status code is set to match ours.
                context.Response.StatusCode = (int)response.StatusCode;

                var upstreamResponseHeaders = response.ExportAllHeaders();

                bool responseHasZeroContentLength = false;
                bool responseIsFixedLength = false;

                foreach (var kvp in upstreamResponseHeaders.ToIHeaderDictionary())
                {
                    foreach (var value in kvp.Value)
                    {
                        if (kvp.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase))
                        {
                            responseIsFixedLength = true;

                            if (value.Length <= 0 && value.Equals("0"))
                            {
                                responseHasZeroContentLength = true;
                            }
                        }
                    }
                }

                // Copy over the upstream headers.
                context.Response.PopulateHeaders(upstreamResponseHeaders, new System.Collections.Generic.HashSet<string>());

                // Copy over the upstream body.
                using (var responseStream = await response?.Content.ReadAsStreamAsync())
                {
                    context.Response.StatusCode = (int)response.StatusCode;
                    context.Response.PopulateHeaders(response.ExportAllHeaders(), new System.Collections.Generic.HashSet<string>());

                    if (!responseHasZeroContentLength && responseIsFixedLength)
                    {
                        using (var ms = new MemoryStream())
                        {
                            await Microsoft.AspNetCore.Http.Extensions.StreamCopyOperation.CopyToAsync(responseStream, ms, s_maxInMemoryData, context.RequestAborted);

                            var responseBody = ms.ToArray();

                            context.Response.Headers.Remove("Content-Length");

                            context.Response.Headers.Add("Content-Length", responseBody.Length.ToString());

                            await context.Response.Body.WriteAsync(responseBody, 0, responseBody.Length);
                        }
                    }
                    else
                    {
                        context.Response.Headers.Remove("Content-Length");

                        if (responseHasZeroContentLength)
                        {
                            context.Response.Headers.Add("Content-Length", "0");
                        }
                        else
                        {
                            await Microsoft.AspNetCore.Http.Extensions.StreamCopyOperation.CopyToAsync(responseStream, context.Response.Body, null, context.RequestAborted);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                while (e != null)
                {
                    Console.WriteLine(e.Message);
                    Console.WriteLine(e.StackTrace);
                }
            }
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
                HttpMessageReplayInspectionCallback = OnReplayInspection,
                NewHttpMessageHandler = OnNewMessage,
                HttpMessageWholeBodyInspectionHandler = OnWholeBodyContentInspection,
                HttpMessageStreamedInspectionHandler = OnStreamedContentInspection,
                HttpExternalRequestHandlerCallback = OnManualFulfillmentCallback,
                BlockExternalProxies = true
            };
            

            // Just create the server.
            var proxyServer = new WindowsProxyServer(cfg);

            // Give it a kick.
            proxyServer.Start(0);

            // And you're up and running.
            Console.WriteLine("Proxy Running");

            Console.WriteLine("Listening for IPv4 HTTP/HTTPS connections on port {0}.", proxyServer.V4HttpEndpoint.Port);
            Console.WriteLine("Listening for IPv6 HTTP/HTTPS connections on port {0}.", proxyServer.V6HttpEndpoint.Port);

            // Don't exit on me yet fam.
            manualResetEvent.WaitOne();

            Console.WriteLine("Exiting.");

            // Stop if you must.
            proxyServer.Stop();
        }
    }
}