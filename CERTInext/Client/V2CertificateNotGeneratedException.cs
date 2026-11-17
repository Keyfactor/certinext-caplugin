// Copyright 2026 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using System;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Client
{
    /// <summary>
    /// Thrown by <c>DownloadCertificateV2Async</c> when CERTInext answers HTTP 422 with
    /// <c>EMS-1165 Invalid request status.</c>. The same code also means "never downloadable" for a
    /// revoked order, so the response alone can't distinguish the cases; a caller that already knows
    /// the order is <c>issued</c> (Track Order, or the report row) treats it as "issued at the CA,
    /// certificate not generated yet" - normally resolved within about 20 seconds - and keeps
    /// waiting instead of reporting a download failure. Carries the same message text the generic
    /// V2 failure would have had, so existing message-based handling is unaffected.
    /// </summary>
    public sealed class V2CertificateNotGeneratedException : Exception
    {
        public V2CertificateNotGeneratedException(string message) : base(message) { }
    }
}
