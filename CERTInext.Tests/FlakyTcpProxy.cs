// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Tests
{
    /// <summary>
    /// Loopback TCP proxy in front of a WireMock server that resets chosen connections before any
    /// HTTP response, so the client sees a real transport failure (RestSharp status 0). WireMock's own
    /// faults still send a 200 status line. Connections are numbered from 1 in accept order.
    /// </summary>
    internal sealed class FlakyTcpProxy : IDisposable
    {
        private readonly TcpListener _listener = new TcpListener(IPAddress.Loopback, 0);
        private readonly int _targetPort;
        private readonly Func<int, bool> _drop;
        private readonly CancellationTokenSource _cts = new CancellationTokenSource();
        private int _connections;

        public FlakyTcpProxy(string targetUrl, Func<int, bool> drop)
        {
            _targetPort = new Uri(targetUrl).Port;
            _drop = drop;
            _listener.Start();
            _ = Task.Run(AcceptLoopAsync);
        }

        public string Url => $"http://127.0.0.1:{((IPEndPoint)_listener.LocalEndpoint).Port}";

        public int Connections => Volatile.Read(ref _connections);

        private async Task AcceptLoopAsync()
        {
            while (!_cts.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await _listener.AcceptTcpClientAsync(_cts.Token);
                }
                catch
                {
                    return;
                }
                int n = Interlocked.Increment(ref _connections);
                if (_drop(n))
                {
                    // Linger 0 sends RST: the request fails with no HTTP response at all.
                    client.Client.LingerState = new LingerOption(true, 0);
                    client.Close();
                    continue;
                }
                _ = Task.Run(() => PipeAsync(client));
            }
        }

        private async Task PipeAsync(TcpClient client)
        {
            using (client)
            using (var upstream = new TcpClient())
            {
                try
                {
                    await upstream.ConnectAsync(IPAddress.Loopback, _targetPort, _cts.Token);
                    var a = client.GetStream();
                    var b = upstream.GetStream();
                    await Task.WhenAny(a.CopyToAsync(b, _cts.Token), b.CopyToAsync(a, _cts.Token));
                }
                catch
                {
                    // A test ended or a side closed: nothing to do.
                }
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _listener.Stop();
        }
    }
}
