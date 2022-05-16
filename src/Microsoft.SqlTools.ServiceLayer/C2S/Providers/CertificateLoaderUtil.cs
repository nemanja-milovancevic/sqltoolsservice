//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    class CertificateLoaderUtil
    {

        //Veljko
        /// <summary>
        /// tries to load the certificate for password encryption from the given path
        /// </summary>
        public static bool TryLoadEncryptionCertificate(string path, out X509Certificate2 certificate)
        {
            certificate = null;

            if (!File.Exists(path))
                return false;

            try
            {
                certificate = new X509Certificate2(path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        //Veljko
        /// <summary>
        /// tries to load the certificate for document signing from certificate store
        /// </summary>
        public static bool TryLoadSigningCertificateFromStore(string base64Certificate, out X509Certificate2 certificate)
        {
            certificate = null;

            if (string.IsNullOrEmpty(base64Certificate))
                return false;

            try
            {
                var publicCertificate = new X509Certificate2(Convert.FromBase64String(base64Certificate));
                certificate = (new X509CertificateStoreProvider()).GetCertificateByThumbprint(publicCertificate.Thumbprint);
                if (certificate == null) return false;
                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
