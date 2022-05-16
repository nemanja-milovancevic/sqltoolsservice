//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    public class XmlDigSigSignatureProvider : ISignatureProvider
    {
        public string Sign(string data, X509Certificate2 certificate)
        {
            if (data == null || certificate == null)
                throw new ArgumentNullException("signature", "Signing document failed.");

            var doc = new XmlDocument();
            doc.PreserveWhitespace = false;
            doc.LoadXml("<c2s>" + data + "</c2s>");

            var signedXml = new SignedXml(doc);
            var key = certificate.GetRSAPrivateKey();
            signedXml.SigningKey = key;

            var xmlSignature = signedXml.Signature;

            Reference reference = new Reference("");
            XmlDsigEnvelopedSignatureTransform env = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            xmlSignature.SignedInfo.AddReference(reference);

            KeyInfo keyInfo = new KeyInfo();
            keyInfo.AddClause(new RSAKeyValue(key));

            xmlSignature.KeyInfo = keyInfo;

            signedXml.ComputeSignature();

            return signedXml.GetXml().OuterXml;
        }

        public bool Verify(string data, string signature, X509Certificate2 certificate)
        {
            if (data == null || signature == null || certificate == null)
                return false;

            var doc = new XmlDocument();
            doc.PreserveWhitespace = true;

            doc.LoadXml("<c2s>" + data + "</c2s>");

            var signedXml = new SignedXml(doc);

            var signatureDoc = new XmlDocument();
            signatureDoc.LoadXml(signature);

            signedXml.LoadXml(signatureDoc.DocumentElement);

            return signedXml.CheckSignature(certificate, true);
        }
    }

}
