//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    public class RsaPkcs1CryptoProvider : IAsymmetricCryptoProvider
    {
        public byte[] Decrypt(byte[] data, X509Certificate2 certificate)
        {
            if (data == null || certificate == null)
                throw new ArgumentNullException();
            // GetRSAPrivateKey returns an object with an independent lifetime, so it should be
            // handled via a using statement.
            using (RSA rsa = certificate.GetRSAPrivateKey())
            {
                return rsa.Decrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }

        public string Decrypt(string dataBase64, X509Certificate2 certificate)
        {
            if (dataBase64 == null || certificate == null)
                throw new ArgumentNullException();
            return Encoding.UTF8.GetString(
                Decrypt(
                    Convert.FromBase64String(dataBase64),
                    certificate
                    )
                );
        }

        public byte[] Encrypt(byte[] data, X509Certificate2 certificate)
        {
            if (data == null || certificate == null)
                throw new ArgumentNullException();
            // GetRSAPublicKey returns an object with an independent lifetime, so it should be
            // handled via a using statement.
            using (RSA rsa = certificate.GetRSAPublicKey())
            {
                // OAEP allows for multiple hashing algorithms, what was formermly just "OAEP" is
                // now OAEP-SHA1.
                return rsa.Encrypt(data, RSAEncryptionPadding.Pkcs1);
            }
        }

        public string Encrypt(string original, X509Certificate2 certificate)
        {
            if (original == null || certificate == null)
                throw new ArgumentNullException();
            return Convert.ToBase64String(
                Encrypt(Encoding.UTF8.GetBytes(original), certificate)
                );
        }
    }

}
