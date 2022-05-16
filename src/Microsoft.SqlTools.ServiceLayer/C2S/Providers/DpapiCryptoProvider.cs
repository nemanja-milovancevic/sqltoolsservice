//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Providers
{
    public class DpapiCryptoProvider : ISymmetricCryptoProvider
    {
        public byte[] Decrypt(byte[] data, byte[] entropy)
        {
            if (data == null || entropy == null)
                throw new ArgumentNullException();
            return ProtectedData.Unprotect(data, entropy,
                DataProtectionScope.CurrentUser);
        }

        public byte[] Encrypt(byte[] data, out byte[] entropy)
        {
            if (data == null)
                throw new ArgumentNullException();
            entropy = CreateRandomEntropy();
            return ProtectedData.Protect(data, entropy,
                DataProtectionScope.CurrentUser);
        }

        public static byte[] CreateRandomEntropy()
        {
            // Create a byte array to hold the random value.
            byte[] entropy = new byte[16];

            // Create a new instance of the RNGCryptoServiceProvider.
            // Fill the array with a random value.
            new RNGCryptoServiceProvider().GetBytes(entropy);

            // Return the array.
            return entropy;
        }

        public string Decrypt(string dataBase64, string entropyBase64)
        {
            if (dataBase64 == null || entropyBase64 == null)
                throw new ArgumentNullException();
            return Encoding.UTF8.GetString(
                Decrypt(
                    Convert.FromBase64String(dataBase64),
                    Convert.FromBase64String(entropyBase64)
                    )
                );
        }

        public string Encrypt(string original, out string entropyBase64)
        {
            if (original == null)
                throw new ArgumentNullException();
            var bytes = Encoding.UTF8.GetBytes(original);
            byte[] entropy;
            var bytesBase64 = Convert.ToBase64String(
                Encrypt(bytes, out entropy)
                );
            entropyBase64 = Convert.ToBase64String(entropy);
            return bytesBase64;
        }
    }
}
