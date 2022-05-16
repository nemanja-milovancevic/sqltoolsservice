//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System.Collections.Generic;
using Microsoft.SqlTools.Hosting.Protocol.Contracts;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Contracts
{
    public class OpenRequest
    {
        public static readonly
            RequestType<OpenParams, OpenResponse> Type =
                RequestType<OpenParams, OpenResponse>.Create("c2s/open");
    }

    public class OpenParams
    {
        public string OpenPath { get; set; }
    }

    public class OpenResponse
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
        public Dictionary<string, string> ConnectionParams { get; set; }
        public string SigningCertificate { get; set; }
    }
}
