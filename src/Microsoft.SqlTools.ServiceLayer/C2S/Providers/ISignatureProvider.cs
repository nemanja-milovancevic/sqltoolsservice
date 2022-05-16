//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System.Security.Cryptography.X509Certificates;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    public interface ISignatureProvider
    {
        string Sign(string data, X509Certificate2 certificate);
        bool Verify(string data, string signature, X509Certificate2 certificate);
    }
}
