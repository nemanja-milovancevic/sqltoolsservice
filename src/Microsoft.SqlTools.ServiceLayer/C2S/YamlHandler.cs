//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Collections.Generic;

namespace Microsoft.SqlTools.ServiceLayer.C2S
{
    public class YamlHandler
    {
        public static C2sDocument.C2sDocumentContent Deserialize(String yaml)
        {
            if (string.IsNullOrEmpty(yaml)) throw new FormatException("Empty document.");
            yaml = yaml.Trim('\n').Trim();
            CheckIfAllPropertiesArePresent(yaml);
            C2sDocument.C2sDocumentContent content = new C2sDocument.C2sDocumentContent();
            string label, value;
            string[] splitRow;
            foreach (string row in yaml.Split("\n".ToCharArray()))
            {
                if (row.Contains("# SIG # Begin signature block")) break;
                splitRow = row.Split(':');
                label = splitRow[0];
                value = splitRow.Length > 1 ? splitRow[1].Trim() : "";

                var prop = content.GetType().GetProperty(label);
                if (prop == null) throw new FormatException("Invalid c2s format.");

                if (label.Equals("PacketSize") || label.Equals("ConnectionTimeOut") || label.Equals("ExecutionTimeOut") || label.Equals("CustomColorSample"))
                {
                    int intValue;
                    if (!int.TryParse(value, out intValue)) throw new FormatException("Invalid c2s format.");
                    prop.GetSetMethod().Invoke(content, new object[] { intValue });
                }
                else if (label.Equals("EncryptConnection") || label.Equals("TrustServerCertificate") || label.Equals("UseCustomColor") || label.Equals("AlwaysEncrypted"))
                {
                    bool boolValue;
                    if (!bool.TryParse(value, out boolValue)) throw new FormatException("Invalid c2s format.");
                    prop.GetSetMethod().Invoke(content, new object[] { boolValue });
                }
                else
                {
                    prop.GetSetMethod().Invoke(content, new object[] { value });
                }
            }
            return content;
        }

        public static Dictionary<string, string> DeserializeToDict(String yaml)
        {
            Dictionary<string, string> dict = new Dictionary<string, string>();
            if (string.IsNullOrEmpty(yaml)) throw new FormatException("Empty document.");
            yaml = yaml.Trim('\n').Trim();
            string label, value;
            string[] splitRow;
            string netProtocol = "";
            foreach (string row in yaml.Split("\n".ToCharArray()))
            {
                if (row.Contains("# SIG # Begin signature block")) break;
                splitRow = row.Split(':');
                label = splitRow[0];
                value = splitRow.Length > 1 ? splitRow[1].Trim() : "";
                
                if (label == "SSMS_networkProtocol")
                {
                    if (value == "dbnmpntw") netProtocol = "np";
                    if (value == "dbmslpcn") netProtocol = "lpc";
                    if (value == "dbmssocn") netProtocol = "tcp";
                }

                if (label.StartsWith("SSMS_")) continue;
                else if (label.StartsWith("ADS_CS_")) label = label.Split('_')[2];
                else if (label.StartsWith("ADS_")) label = label.Split('_')[1];

                if (label == "columnEncryptionSetting") value = value.Replace("True", "Enabled").Replace("False", "Disabled");
                if (label == "authenticationType")
                {
                    if (value == "SqlLogin" || value == "SqlServerAuthentication") value = "SqlLogin";
                    else if (value == "AzureMFA" || value == "AzureActiveDirectoryUniversalWithMFA") value = "AzureMFA";
                    else value = "Integrated";
                }

                dict.Add(label, value);
            }
            if (!string.IsNullOrEmpty(netProtocol)) dict["server"] = netProtocol + ":" + dict["server"];
            return dict;
        }

        private static void CheckIfAllPropertiesArePresent(string yaml)
        {
            System.Reflection.PropertyInfo[] Properties = typeof(C2sDocument.C2sDocumentContent).GetProperties();
            foreach (System.Reflection.PropertyInfo property in Properties)
            {
                if (!yaml.StartsWith(property.Name, StringComparison.CurrentCultureIgnoreCase) && !yaml.Contains("\n" + property.Name + ":"))
                {
                    throw new FormatException("Invalid c2s document format.");
                }
            }
        }

        internal static string Serialize(C2sDocument.C2sDocumentContent content)
        {
            string text = "";
            foreach (var property in typeof(C2sDocument.C2sDocumentContent).GetProperties())
            {
                text += property.Name.ToString() + ": " + (property.GetValue(content) == null ? "" : property.GetValue(content)) + "\n";
            }
            text = text.Trim();
            return text;
        }

        internal static string Serialize(Dictionary<string, string> content)
        {
            string text = "";
            foreach (KeyValuePair<string, string> kv in content)
            {
                text += C2sDocument.MapToFileName(kv.Key) + ": " + kv.Value + "\n";
            }
            text = text.Trim();
            return text;
        }
    }
}
