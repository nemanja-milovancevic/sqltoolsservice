//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using Microsoft.SqlTools.ServiceLayer.Hosting.Protocol.Contracts;

namespace Microsoft.SqlTools.ServiceLayer.Connection.Contracts
{
    /// <summary>
    /// Parameters for the ConnectionChanged Notification.
    /// </summary>
    public class ConnectionChangedParams
    {
        /// <summary>
        /// A URI identifying the owner of the connection. This will most commonly be a file in the workspace
        /// or a virtual file representing an object in a database.         
        /// </summary>
        public string OwnerUri { get; set; }
        /// <summary>
        /// Contains the high-level properties about the connection, for display to the user.
        /// </summary>
        public ConnectionSummary Connection { get; set; }
    }

    /// <summary>
    /// ConnectionChanged notification mapping entry 
    /// </summary>
    public class ConnectionChangedNotification
    {
        public static readonly
            EventType<ConnectionChangedParams> Type =
            EventType<ConnectionChangedParams>.Create("connection/connectionchanged");
    }

}
