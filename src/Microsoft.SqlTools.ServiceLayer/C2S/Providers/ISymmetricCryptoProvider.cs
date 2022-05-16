//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    public interface ISymmetricCryptoProvider
    {
        byte[] Decrypt(byte[] data, byte[] entropy);
        byte[] Encrypt(byte[] data, out byte[] entropy);
        string Decrypt(string dataBase64, string entropyBase64);
        string Encrypt(string original, out string entropyBase64);
    }
}
