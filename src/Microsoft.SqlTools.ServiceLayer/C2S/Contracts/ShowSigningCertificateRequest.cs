//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using Microsoft.SqlTools.Hosting.Protocol.Contracts;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Contracts
{
    public class ShowSigningCertificateRequest
    {
        public static readonly
            RequestType<ShowSigningCertificateParams, ShowSigningCertificateResponse> Type =
               RequestType<ShowSigningCertificateParams, ShowSigningCertificateResponse>.Create("c2s/showSigningCertificate");
    }

    public class ShowSigningCertificateParams
    {
        public string SigningCertificate { get; set; }
    }

    public class ShowSigningCertificateResponse
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
    }

}
