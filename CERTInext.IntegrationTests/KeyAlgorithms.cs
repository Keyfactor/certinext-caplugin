// Copyright 2024 Keyfactor
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
// At http://www.apache.org/licenses/LICENSE-2.0

using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace Keyfactor.Extensions.CAPlugin.CERTInext.IntegrationTests
{
    internal enum KeyKind { Rsa, Ecdsa, Ed25519, Ed448 }

    /// <summary>One row of the key-algorithm coverage matrix.</summary>
    internal sealed class KeyAlgorithmSpec
    {
        public string Tag;                   // stable, human-readable id ("RSA-2048", "ECDSA-P256", ...)
        public KeyKind Kind;
        public int Strength;                 // RSA modulus bits, or EC field size in bits (informational for Ed)
        public string SignatureAlgorithm;    // BouncyCastle signature-algorithm name used to sign the CSR
        public DerObjectIdentifier CurveOid; // EC named-curve OID (null for non-EC)
    }

    /// <summary>
    /// Shared key-algorithm matrix + BouncyCastle CSR generation, used by both the offline
    /// submission/round-trip tests (<c>AlgorithmMatrixTests</c>) and the live DCV-issuance
    /// theory (<c>DcvLifecycleTests</c>). BouncyCastle only — never BCL crypto.
    ///
    /// Hash pairing follows the CA/Browser Forum Baseline Requirements: P-256→SHA256,
    /// P-384→SHA384, P-521→SHA512.
    /// </summary>
    internal static class KeyAlgorithms
    {
        public static readonly KeyAlgorithmSpec[] All =
        {
            new() { Tag = "RSA-2048",   Kind = KeyKind.Rsa,     Strength = 2048, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-3072",   Kind = KeyKind.Rsa,     Strength = 3072, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-4096",   Kind = KeyKind.Rsa,     Strength = 4096, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-6144",   Kind = KeyKind.Rsa,     Strength = 6144, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "RSA-8192",   Kind = KeyKind.Rsa,     Strength = 8192, SignatureAlgorithm = "SHA256withRSA" },
            new() { Tag = "ECDSA-P256", Kind = KeyKind.Ecdsa,   Strength = 256,  SignatureAlgorithm = "SHA256withECDSA", CurveOid = SecObjectIdentifiers.SecP256r1 },
            new() { Tag = "ECDSA-P384", Kind = KeyKind.Ecdsa,   Strength = 384,  SignatureAlgorithm = "SHA384withECDSA", CurveOid = SecObjectIdentifiers.SecP384r1 },
            new() { Tag = "ECDSA-P521", Kind = KeyKind.Ecdsa,   Strength = 521,  SignatureAlgorithm = "SHA512withECDSA", CurveOid = SecObjectIdentifiers.SecP521r1 },
            new() { Tag = "Ed25519",    Kind = KeyKind.Ed25519, Strength = 256,  SignatureAlgorithm = "Ed25519" },
            new() { Tag = "Ed448",      Kind = KeyKind.Ed448,   Strength = 448,  SignatureAlgorithm = "Ed448" },
        };

        public static KeyAlgorithmSpec For(string tag) => All.Single(s => s.Tag == tag);

        /// <summary>xUnit member-data source — one row per key type, keyed by its stable tag.</summary>
        public static IEnumerable<object[]> AsMemberData => All.Select(s => new object[] { s.Tag });

        public static AsymmetricCipherKeyPair GenerateKeyPair(KeyAlgorithmSpec spec)
        {
            switch (spec.Kind)
            {
                case KeyKind.Rsa:
                {
                    var gen = new RsaKeyPairGenerator();
                    gen.Init(new KeyGenerationParameters(new SecureRandom(), spec.Strength));
                    return gen.GenerateKeyPair();
                }
                case KeyKind.Ecdsa:
                {
                    var gen = new ECKeyPairGenerator("ECDSA");
                    gen.Init(new ECKeyGenerationParameters(spec.CurveOid, new SecureRandom()));
                    return gen.GenerateKeyPair();
                }
                case KeyKind.Ed25519:
                {
                    var gen = new Ed25519KeyPairGenerator();
                    gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
                    return gen.GenerateKeyPair();
                }
                case KeyKind.Ed448:
                {
                    var gen = new Ed448KeyPairGenerator();
                    gen.Init(new Ed448KeyGenerationParameters(new SecureRandom()));
                    return gen.GenerateKeyPair();
                }
                default:
                    throw new ArgumentOutOfRangeException(nameof(spec), spec.Kind, "unhandled key kind");
            }
        }

        public static string GenerateCsrPem(string commonName, KeyAlgorithmSpec spec)
        {
            var keyPair = GenerateKeyPair(spec);
            var subject = new X509Name($"CN={commonName}");
            var csr = new Pkcs10CertificationRequest(spec.SignatureAlgorithm, subject, keyPair.Public, null, keyPair.Private);

            return "-----BEGIN CERTIFICATE REQUEST-----\n"
                + Convert.ToBase64String(csr.GetEncoded(), Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE REQUEST-----";
        }

        /// <summary>Strips PEM armor and returns the DER bytes of a CSR.</summary>
        public static byte[] DerFromPem(string pem)
        {
            var b64 = pem
                .Replace("-----BEGIN CERTIFICATE REQUEST-----", string.Empty)
                .Replace("-----END CERTIFICATE REQUEST-----", string.Empty)
                .Replace("\r", string.Empty)
                .Replace("\n", string.Empty)
                .Trim();
            return Convert.FromBase64String(b64);
        }

        /// <summary>A filesystem/DNS-safe slug for a tag, e.g. "ECDSA-P256" → "ecdsap256".</summary>
        public static string Slug(string tag) => tag.ToLowerInvariant().Replace("-", string.Empty);

        /// <summary>
        /// Classifies a CERTInext order-rejection message so the algorithm matrix doesn't
        /// conflate "this key algorithm is unsupported" with "the account can't place orders
        /// right now". CERTInext's live envelope (observed): RSA 2048/3072/4096 + ECC P-256/P-384
        /// are accepted; larger RSA, P-521, and the Ed* curves return "Invalid key size" /
        /// "Something went Wrong". A credit shortfall returns "Insufficient Credits" regardless
        /// of algorithm.
        /// </summary>
        public static string ClassifyRejection(string caMessage)
        {
            caMessage ??= string.Empty;
            if (caMessage.IndexOf("Invalid key size", StringComparison.OrdinalIgnoreCase) >= 0)
                return "key algorithm/size not supported by CERTInext";
            if (caMessage.IndexOf("Insufficient Credits", StringComparison.OrdinalIgnoreCase) >= 0)
                return "CERTInext account is out of credits — algorithm support was not exercised";
            return "rejected by CERTInext";
        }
    }
}
