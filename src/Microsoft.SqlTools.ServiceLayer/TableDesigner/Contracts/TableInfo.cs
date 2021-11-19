//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;
using Newtonsoft.Json.Converters;

namespace Microsoft.SqlTools.ServiceLayer.TableDesigner.Contracts
{
    /// <summary>
    /// The information of the table being designed.
    /// </summary>
    public class TableInfo
    {
        public string Server { get; set; }

        public string Database { get; set; }

        public string Schema { get; set; }

        public string Name { get; set; }

        public bool IsNewTable { get; set; }

        public string ConnectionString { get; set; }

        public string Id { get; set; }

        public TableType TableType { get; set; }
    }

    [JsonConverter(typeof(StringEnumConverter))]
    public enum TableType
    {
        [EnumMember(Value = "Regular")]
        Regular,
        [EnumMember(Value = "Node")]
        Node,
        [EnumMember(Value = "Edge")]
        Edge
    }
}