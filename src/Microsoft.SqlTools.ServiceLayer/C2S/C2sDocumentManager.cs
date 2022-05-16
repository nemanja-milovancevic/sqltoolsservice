//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.SqlTools.ServiceLayer.C2S.Providers;


namespace Microsoft.SqlTools.ServiceLayer.C2S
{
    public class C2sDocumentManager
    {
        private ISymmetricCryptoProvider SymmetricCryptoProvider { get; set; }
        private IAsymmetricCryptoProvider AsymmetricCryptoProvider { get; set; }
        private ICertificateStoreProvider CertificateStoreProvider { get; set; }
        private ISignatureProvider SignatureProvider { get; set; }

        public C2sDocumentManager()
            : this(
                  new DpapiCryptoProvider(),
                  new RsaPkcs1CryptoProvider(),
                  new X509CertificateStoreProvider(),
                  new XmlDigSigSignatureProvider()
                  )
        {

        }
        public C2sDocumentManager(
            ISymmetricCryptoProvider symmetricCryptoProvider,
            IAsymmetricCryptoProvider asymmetricCryptoProvider,
            ICertificateStoreProvider certificateStoreProvider,
            ISignatureProvider signatureProvider
            )
        {
            SymmetricCryptoProvider = symmetricCryptoProvider;
            AsymmetricCryptoProvider = asymmetricCryptoProvider;
            CertificateStoreProvider = certificateStoreProvider;
            SignatureProvider = signatureProvider;
        }

        public C2sDocument Create()
        {
            return Create("", null, null);
        }

        internal C2sDocument Create(
            string path,
            Dictionary<string,string> content,
            X509Certificate2 decryptionCertificate
            )
        {
            return new C2sDocument(
                SymmetricCryptoProvider,
                AsymmetricCryptoProvider,
                CertificateStoreProvider,
                SignatureProvider,
                path,
                content,
                decryptionCertificate
                );
        }

        public C2sDocument Read(
            string path,
            X509Certificate2 decryptionCertificate = null
            )
        {
            if (string.IsNullOrEmpty(path)) throw new ArgumentNullException("path", "Path cannot be empty.");
            if (!File.Exists(path)) throw new ArgumentException("path", "Invalid path.");
            using (var stream = File.OpenRead(path))
            {
                return Read(path, stream, decryptionCertificate);
            }
        }

        public C2sDocument Read(
            Stream stream,
            X509Certificate2 decryptionCertificate = null
            )
        {
            return Read("", stream, decryptionCertificate);
        }

        private C2sDocument Read(
            string path,
            Stream stream,
            X509Certificate2 decryptionCertificate
            )
        {
            if (stream == null) throw new ArgumentNullException("stream", "Invalid path.");
            YamlHandler YamlHandler = new YamlHandler();

            using (var reader = new StreamReader(stream))
            {
                var yaml = reader.ReadToEnd();

                //var content = YamlHandler.Deserialize(yaml);
                var adsContent = YamlHandler.DeserializeToDict(yaml);

                if (!string.IsNullOrEmpty(adsContent["signingCertificate"]))
                {
                    var signingCertificate = new X509Certificate2(Convert.FromBase64String(adsContent["signingCertificate"]));

                    VerifySignature(yaml, signingCertificate);
                }

                return Create(path, adsContent, decryptionCertificate);
            }
        }

        private void VerifySignature(string yaml, X509Certificate2 certificate)
        {
            var signatureSeparator = "# SIG # Begin signature block";

            var index = yaml.IndexOf(signatureSeparator);

            if (index != -1)
            {
                var signature = yaml.Substring(index);
                yaml = yaml.Substring(0, index);

                var base64SignatureLines =
                    signature
                    .Replace("# ", "")
                    .Split(new[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries)
                    .ToList();
                base64SignatureLines.RemoveAt(0);
                base64SignatureLines.RemoveAt(base64SignatureLines.Count - 1);
                var xmlSignature = Encoding.UTF8.GetString(
                    Convert.FromBase64String(
                        string.Join("", base64SignatureLines.ToArray()))
                    );
                if (!SignatureProvider.Verify(yaml, xmlSignature, certificate))
                {
                    throw new CryptographicException("Signature validation failed. Document may have been tampered with.");
                }
            }
        }
    }
}
