// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions
// and limitations under the License.

using Keyfactor.PKI.Enums.EJBCA;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.Models
{
    /// <summary>
    /// Maps CERTInext status identifiers to Keyfactor <see cref="EndEntityStatus"/> codes
    /// used internally by the AnyCA gateway.
    ///
    /// The real CERTInext API returns numeric status IDs (certificateStatusId from
    /// TrackOrder, or orderStatusId from GetOrderReport).  String-based overloads are
    /// provided for backward compatibility with the legacy inferred REST design.
    /// </summary>
    internal static class StatusMapper
    {
        // -----------------------------------------------------------------------
        // Certificate status ID mapping (TrackOrder.orderDetails.certificateStatusId)
        // -----------------------------------------------------------------------

        /// <summary>
        /// Converts a CERTInext <c>certificateStatusId</c> integer to the closest matching
        /// <see cref="EndEntityStatus"/> code expected by the AnyCA gateway.
        /// </summary>
        public static int CertificateStatusIdToRequestDisposition(int certificateStatusId)
        {
            switch (certificateStatusId)
            {
                // Successfully issued and available for download
                case Constants.CertificateStatusId.CertificateGenerated:   // 20
                case Constants.CertificateStatusId.CertificateDownloaded:  // 9
                case Constants.CertificateStatusId.RekeyApproved:          // 23
                case Constants.CertificateStatusId.OrderAutoApproved:      // 15
                case Constants.CertificateStatusId.ApprovedBySecondApprover: // 7
                    return (int)EndEntityStatus.GENERATED;

                // Pending human approval or validation steps
                case Constants.CertificateStatusId.SetupPending:                   // 1
                case Constants.CertificateStatusId.PendingForApprover:             // 2
                case Constants.CertificateStatusId.PendingSecondApprover:          // 6
                case Constants.CertificateStatusId.PendingLra:                     // 16
                case Constants.CertificateStatusId.Approved:                       // 4
                case Constants.CertificateStatusId.ApprovedLra:                    // 17
                case Constants.CertificateStatusId.PendingForApproverAutoApproval: // 24
                    return (int)EndEntityStatus.EXTERNALVALIDATION;

                // Revoked
                case Constants.CertificateStatusId.CertificateRevoked: // 22
                    return (int)EndEntityStatus.REVOKED;

                // Expired — remain in inventory as GENERATED so they appear in the database
                case Constants.CertificateStatusId.CertificateExpired: // 12
                    return (int)EndEntityStatus.GENERATED;

                // Terminal failure states
                case Constants.CertificateStatusId.Rejected:                       // 5
                case Constants.CertificateStatusId.RejectedBySecondApprover:       // 8
                case Constants.CertificateStatusId.RejectedDueToOrderCancellation: // 13
                case Constants.CertificateStatusId.AutoRejected:                   // 14
                case Constants.CertificateStatusId.RejectedLra:                    // 18
                case Constants.CertificateStatusId.InvalidConfiguration:            // 19
                case Constants.CertificateStatusId.DownloadRejected:               // 21
                case Constants.CertificateStatusId.UnderDiscrepancy:               // 3
                    return (int)EndEntityStatus.FAILED;

                default:
                    return (int)EndEntityStatus.FAILED;
            }
        }

        /// <summary>
        /// Converts a CERTInext <c>certificateStatusId</c> string (as returned by the
        /// API response) to the closest matching <see cref="EndEntityStatus"/> code.
        /// </summary>
        public static int CertificateStatusIdToRequestDisposition(string certificateStatusIdString)
        {
            if (string.IsNullOrWhiteSpace(certificateStatusIdString))
                return (int)EndEntityStatus.FAILED;

            if (int.TryParse(certificateStatusIdString, out int id))
                return CertificateStatusIdToRequestDisposition(id);

            // Fall back to legacy string mapping for any code path that still uses strings
            return ToRequestDisposition(certificateStatusIdString);
        }

        // -----------------------------------------------------------------------
        // Legacy string-status mapping — kept for backward compat with the
        // inferred REST design.  The real API does not return these strings.
        // -----------------------------------------------------------------------

        /// <summary>
        /// Converts a legacy CERTInext status string to the closest matching
        /// <see cref="EndEntityStatus"/> integer code.
        /// </summary>
        /// <param name="certinextStatus">Raw status string (legacy inferred format).</param>
        public static int ToRequestDisposition(string certinextStatus)
        {
            if (string.IsNullOrWhiteSpace(certinextStatus))
                return (int)EndEntityStatus.FAILED;

            switch (certinextStatus.ToLowerInvariant())
            {
                case Constants.CertificateStatus.Active:
                case Constants.CertificateStatus.Issued:
                    return (int)EndEntityStatus.GENERATED;

                case Constants.CertificateStatus.Pending:
                case Constants.CertificateStatus.PendingApproval:
                case Constants.CertificateStatus.Processing:
                    return (int)EndEntityStatus.EXTERNALVALIDATION;

                case Constants.CertificateStatus.Revoked:
                    return (int)EndEntityStatus.REVOKED;

                case Constants.CertificateStatus.Expired:
                    // Expired-but-not-revoked certs remain in inventory as GENERATED
                    return (int)EndEntityStatus.GENERATED;

                case Constants.CertificateStatus.Rejected:
                case Constants.CertificateStatus.Failed:
                case Constants.CertificateStatus.Cancelled:
                    return (int)EndEntityStatus.FAILED;

                default:
                    return (int)EndEntityStatus.FAILED;
            }
        }

        // -----------------------------------------------------------------------
        // Revocation reason mapping
        // -----------------------------------------------------------------------

        /// <summary>
        /// Converts a CRL reason code integer (RFC 5280) to the CERTInext
        /// <c>revokeReasonId</c> integer.
        ///
        /// CERTInext only accepts: 1 (KeyCompromise), 3 (AffiliationChanged),
        /// 4 (Superseded), 5 (CessationOfOperation), 9 (PrivilegeWithdrawn).
        /// All other CRL codes are mapped to KeyCompromise (1) as the closest
        /// equivalent that CERTInext accepts.
        /// </summary>
        /// <param name="crlReason">RFC 5280 CRL reason code from the gateway.</param>
        /// <returns>CERTInext revokeReasonId integer string.</returns>
        public static string ToRevocationReasonId(uint crlReason)
        {
            switch (crlReason)
            {
                case 1: return Constants.RevocationReasonId.KeyCompromise.ToString();          // RFC: keyCompromise
                case 3: return Constants.RevocationReasonId.AffiliationChanged.ToString();     // RFC: affiliationChanged
                case 4: return Constants.RevocationReasonId.Superseded.ToString();             // RFC: superseded
                case 5: return Constants.RevocationReasonId.CessationOfOperation.ToString();   // RFC: cessationOfOperation
                case 9: return Constants.RevocationReasonId.PrivilegeWithdrawn.ToString();     // RFC: privilegeWithdrawn

                // RFC codes with no CERTInext equivalent — map to KeyCompromise
                case 0:  // unspecified
                case 2:  // cACompromise
                case 6:  // certificateHold
                case 8:  // removeFromCRL
                case 10: // aACompromise
                default:
                    return Constants.RevocationReasonId.KeyCompromise.ToString();
            }
        }

        /// <summary>
        /// Converts a CRL reason code integer (RFC 5280) to the corresponding
        /// legacy CERTInext revocation reason string (from the inferred REST design).
        /// Retained for backward compatibility.
        /// </summary>
        public static string ToRevocationReason(uint crlReason)
        {
            switch (crlReason)
            {
                case 0: return Constants.RevocationReason.Unspecified;
                case 1: return Constants.RevocationReason.KeyCompromise;
                case 2: return Constants.RevocationReason.CACompromise;
                case 3: return Constants.RevocationReason.AffiliationChanged;
                case 4: return Constants.RevocationReason.Superseded;
                case 5: return Constants.RevocationReason.CessationOfOperation;
                case 6: return Constants.RevocationReason.CertificateHold;
                case 8: return Constants.RevocationReason.RemoveFromCRL;
                case 9: return Constants.RevocationReason.PrivilegeWithdrawn;
                case 10: return Constants.RevocationReason.AACompromise;
                default: return Constants.RevocationReason.Unspecified;
            }
        }

        // -----------------------------------------------------------------------
        // V2 API status mapping
        // -----------------------------------------------------------------------

        /// <summary>
        /// Maps a V2 REST API order status string to the Keyfactor
        /// <see cref="EndEntityStatus"/> integer code expected by the gateway.
        /// </summary>
        /// <param name="v2Status">Status string from the V2 order response.</param>
        public static int V2StatusToRequestDisposition(string v2Status) =>
            v2Status?.ToLowerInvariant() switch
            {
                Constants.ApiV2.StatusIssued           => (int)EndEntityStatus.GENERATED,
                Constants.ApiV2.StatusPendingDcv       => (int)EndEntityStatus.EXTERNALVALIDATION,
                Constants.ApiV2.StatusPendingCsr       => (int)EndEntityStatus.EXTERNALVALIDATION,
                Constants.ApiV2.StatusPendingAgreement => (int)EndEntityStatus.EXTERNALVALIDATION,
                Constants.ApiV2.StatusRevoked          => (int)EndEntityStatus.REVOKED,
                Constants.ApiV2.StatusCancelled        => (int)EndEntityStatus.FAILED,
                _                                      => (int)EndEntityStatus.FAILED
            };

        /// <summary>
        /// Converts an RFC 5280 CRL reason code to the V2 API revocation reason string.
        /// Codes without a direct V2 equivalent are mapped to "unspecified".
        /// </summary>
        /// <param name="crlReason">RFC 5280 CRL reason code from the gateway.</param>
        public static string ToV2RevocationReason(uint crlReason) =>
            crlReason switch
            {
                1 => Constants.RevocationReason.KeyCompromise,        // RFC: keyCompromise
                3 => Constants.RevocationReason.AffiliationChanged,   // RFC: affiliationChanged
                4 => Constants.RevocationReason.Superseded,           // RFC: superseded
                5 => Constants.RevocationReason.CessationOfOperation, // RFC: cessationOfOperation
                9 => Constants.RevocationReason.PrivilegeWithdrawn,   // RFC: privilegeWithdrawn
                _ => Constants.RevocationReason.Unspecified
            };

        /// <summary>
        /// Converts a CERTInext <c>revokeReasonId</c> integer back to the RFC 5280 CRL
        /// reason code for storage in the Keyfactor Command database.
        /// </summary>
        public static int RevokeReasonIdToCrlCode(int revokeReasonId)
        {
            switch (revokeReasonId)
            {
                case 1: return 1; // keyCompromise
                case 3: return 3; // affiliationChanged
                case 4: return 4; // superseded
                case 5: return 5; // cessationOfOperation
                case 9: return 9; // privilegeWithdrawn
                default: return 0; // unspecified
            }
        }
    }
}
