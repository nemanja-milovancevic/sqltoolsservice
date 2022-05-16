//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System.Collections.Generic;
using Microsoft.SqlTools.Hosting.Protocol.Contracts;

namespace Microsoft.SqlTools.ServiceLayer.C2S.Contracts
{
    public class SaveRequest
    {
        public static readonly
            RequestType<SaveParams, SaveResponse> Type =
                RequestType<SaveParams, SaveResponse>.Create("c2s/save");
    }
    public class SaveParams
    {
        public string savePath { get; set; }
        public Dictionary<string, string> connectionParams { get; set; }
        public bool shouldSignFile { get; set; }
        public string signingCertificate { get; set; }
        public string passwordEncryptionOption { get; set; }
        public string encryptionCertificatePath { get; set; }
    }

    public class SaveResponse
    {
        public bool IsSuccess { get; set; }
        public string Message { get; set; }
    }
    
}
