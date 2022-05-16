//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using Microsoft.SqlTools.Hosting.Protocol.Contracts;

namespace Microsoft.SqlTools.ServiceLayer.C2S
{
    public class C2sTestRequest
    {
        public static readonly
            RequestType<C2sTestParams, C2sTestResponse> Type =
                RequestType<C2sTestParams, C2sTestResponse>.Create("c2s/test");
    }

    public class C2sTestResponse
    {
        //public bool Result { get; set; }
        public string ResultText { get; set; }
        //public int TaskId { get; set; }
    }

    public class C2sTestParams
    {
        public string content { get; set; }
    }
}
