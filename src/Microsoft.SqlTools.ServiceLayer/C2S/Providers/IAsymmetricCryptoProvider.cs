//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System.Security.Cryptography.X509Certificates;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    public interface IAsymmetricCryptoProvider
    {
        byte[] Decrypt(byte[] data, X509Certificate2 certificate);
        byte[] Encrypt(byte[] data, X509Certificate2 certificate);
        string Decrypt(string dataBase64, X509Certificate2 certificate);
        string Encrypt(string original, X509Certificate2 certificate);
    }
}
