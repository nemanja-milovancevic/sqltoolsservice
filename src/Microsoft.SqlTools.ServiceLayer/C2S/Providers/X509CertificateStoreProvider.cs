//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System.Security.Cryptography.X509Certificates;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    public class X509CertificateStoreProvider : ICertificateStoreProvider
    {
        public X509Certificate2 GetCertificateByThumbprint(string thumbprint)
        {
            if (thumbprint == null) return null;
            var result = GetFromStoreByThumbprint(StoreName.My, StoreLocation.CurrentUser, thumbprint);
            if (result == null)
            {
                result = GetFromStoreByThumbprint(StoreName.My, StoreLocation.LocalMachine, thumbprint);
            }
            return result;
        }

        public X509Certificate2Collection GetMyCertificates()
        {
            var certStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            certStore.Open(OpenFlags.ReadOnly);
            return certStore.Certificates;
        }

        private X509Certificate2 GetFromStoreByThumbprint(StoreName storeName, StoreLocation storeLocation, string thumbprint)
        {
            var certStore = new X509Store(storeName, storeLocation);
            certStore.Open(OpenFlags.ReadOnly);
            var certCollection = certStore.Certificates.Find(
                X509FindType.FindByThumbprint, thumbprint, false);
            certStore.Close();
            return certCollection.Count == 0 ?
                default(X509Certificate2) : certCollection[0];
        }
    }

}
