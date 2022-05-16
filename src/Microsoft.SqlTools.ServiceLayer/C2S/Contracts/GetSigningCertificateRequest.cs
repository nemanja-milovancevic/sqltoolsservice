//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//
using Microsoft.SqlTools.Hosting.Protocol.Contracts;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Contracts
{
    public class GetSigningCertificateRequest
    {
        public static readonly
            RequestType<GetSigningCertificateParams, GetSigningCertificateResponse> Type =
                RequestType<GetSigningCertificateParams, GetSigningCertificateResponse>.Create("c2s/getSigningCertificate");
    }

    public class GetSigningCertificateParams
    {
    }
   
    public class GetSigningCertificateResponse
    {
        public string Base64Certificate { get; set; }
        public string Subject { get; set; }
    }
}
