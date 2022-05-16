//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.SqlTools.ServiceLayer.C2S.Providers;

namespace Microsoft.SqlTools.ServiceLayer.C2S
{
    public class C2sDocument
    {
        public class C2sDocumentContent
        {
            public string ServerType { get; set; }
            public string ServerName { get; set; }
            public string DatabaseName { get; set; }
            public string UserName { get; set; }
            public string NetworkProtocol { get; set; }
            public int PacketSize { get; set; }
            public int ConnectionTimeOut { get; set; }
            public int ExecutionTimeOut { get; set; }
            public bool EncryptConnection { get; set; }
            public bool TrustServerCertificate { get; set; }
            public bool UseCustomColor { get; set; }
            public int CustomColorSample { get; set; }
            public bool AlwaysEncrypted { get; set; }
            public string AESecureEnclavesURL { get; set; }
            public string OtherParams { get; set; }
            public string Authentication { get; set; }
            public string EncryptedPassword { get; set; }
            public string EncryptedPasswordEntropy { get; set; }
            public string EncryptionCertificate { get; set; }
            public string SigningCertificate { get; set; }
        }

        //public Microsoft.SqlServer.Management.Smo.RegSvrEnum.UIConnectionInfo ConnectionInfo { get; set; }
        public string Path { get; private set; }
        internal string Password { private get; set; }
        public string Signer { get; set; }
        public Dictionary<String, String> AdsContent { get; set; }

        private ISymmetricCryptoProvider SymmetricCryptoProvider { get; set; }
        private IAsymmetricCryptoProvider AsymmetricCryptoProvider { get; set; }
        private ICertificateStoreProvider CertificateStoreProvider { get; set; }
        private ISignatureProvider SignatureProvider { get; set; }

        internal C2sDocument(
            ISymmetricCryptoProvider symmetricCryptoProvider,
            IAsymmetricCryptoProvider asymmetricCryptoProvider,
            ICertificateStoreProvider certificateStoreProvider,
            ISignatureProvider signatureProvider,
            string path
            ) : this(
                symmetricCryptoProvider,
                asymmetricCryptoProvider,
                certificateStoreProvider,
                signatureProvider,
                path,
                null,
                null
                )
        {

        }

        internal C2sDocument(
            ISymmetricCryptoProvider symmetricCryptoProvider,
            IAsymmetricCryptoProvider asymmetricCryptoProvider,
            ICertificateStoreProvider certificateStoreProvider,
            ISignatureProvider signatureProvider,
            string path,
            Dictionary<string,string> content,
            X509Certificate2 decryptionCertificate
            )
        {
            SymmetricCryptoProvider = symmetricCryptoProvider;
            AsymmetricCryptoProvider = asymmetricCryptoProvider;
            CertificateStoreProvider = certificateStoreProvider;
            SignatureProvider = signatureProvider;
            Path = path;
            AdsContent = content;
            if(content!=null) ProcessContent(content, decryptionCertificate);
            //ToConnectionInfo(content, decryptionCertificate);
        }

        private void ProcessContent(
            Dictionary<string,string> content,
            X509Certificate2 decryptionCertificate)
        {

            content.Add("password","");
            if (!string.IsNullOrEmpty(content["signingCertificate"]))
            {
                this.Signer = content["signingCertificate"];
            }
            if (
                !string.IsNullOrEmpty(content["encryptedPassword"]) ||
                !string.IsNullOrEmpty(content["encryptionCertificate"]))
            {
                LoadEncryptedPassword(content, decryptionCertificate);
            }

            content.Remove("encryptedPassword");
            content.Remove("encryptedPasswordEntropy");
            content.Remove("encryptionCertificate");
            content.Remove("signingCertificate");
        }



        //private void ToConnectionInfo(
        //    C2sDocumentContent content,
        //    X509Certificate2 decryptionCertificate)
        //{
        //    ConnectionInfo = new Smo.RegSvrEnum.UIConnectionInfo();

        //    if (content != null)
        //    {
        //        ConnectionInfo.Password = this.Password;
        //        ConnectionInfo.ServerType = SqlServerType.ServerType;
        //        ConnectionInfo.ServerName = content.ServerName;
        //        UIConnectionInfoUtil.SetDatabaseName(ConnectionInfo, content.DatabaseName);
        //        if (content.UserName != null) ConnectionInfo.UserName = content.UserName;
        //        UIConnectionInfoUtil.SetConnectionProtocol(ConnectionInfo, content.NetworkProtocol);
        //        UIConnectionInfoUtil.SetPacketSize(ConnectionInfo, content.PacketSize);
        //        UIConnectionInfoUtil.SetConnectionTimeout(ConnectionInfo, content.ConnectionTimeOut);
        //        UIConnectionInfoUtil.SetExecutionTimeout(ConnectionInfo, content.ExecutionTimeOut);
        //        UIConnectionInfoUtil.SetEncryptConnection(ConnectionInfo, content.EncryptConnection);
        //        UIConnectionInfoUtil.SetTrustServerCertificate(ConnectionInfo, content.TrustServerCertificate);
        //        UIConnectionInfoUtil.SetUseCustomConnectionColor(ConnectionInfo, content.UseCustomColor);
        //        UIConnectionInfoUtil.SetCustomConnectionColor(ConnectionInfo, System.Drawing.Color.FromArgb(content.CustomColorSample));
        //        UIConnectionInfoUtil.SetColumnEncryption(ConnectionInfo, content.AlwaysEncrypted);
        //        UIConnectionInfoUtil.SetColumnEncryptionAttestationURL(ConnectionInfo, content.AESecureEnclavesURL);
        //        ConnectionInfo.OtherParams = content.OtherParams;
        //        //ConnectionInfo.AuthenticationType = MapToUIAuthenticationType(AuthenticationType.SupportedTypes
        //            .FirstOrDefault(t => t.ValueName == content.Authentication));

        //        if (!string.IsNullOrEmpty(content.SigningCertificate))
        //        {
        //            this.Signer = new X509Certificate2(
        //                Convert.FromBase64String(content.SigningCertificate));
        //        }
        //        if (
        //            !string.IsNullOrEmpty(content.EncryptedPassword) ||
        //            !string.IsNullOrEmpty(content.EncryptionCertificate))
        //        {
        //            LoadEncryptedPassword(content, decryptionCertificate);
        //        }

        //    }
        //}

        //private int MapToUIAuthenticationType(AuthenticationType AuthenticationType)
        //{
        //    switch (AuthenticationType.Id)
        //    {
        //        case 0:
        //            return 0;
        //        case 1:
        //            return 1;
        //        case 2:
        //            return 5;
        //        case 3:
        //            return 2;
        //        case 4:
        //            return 3;
        //        default:
        //            return 0;
        //    }
        //}

        private void LoadEncryptedPassword(Dictionary<string,string> content, X509Certificate2 decryptionCertificate)
        {
            if (!string.IsNullOrEmpty(content["encryptionCertificate"]))
            {
                var certificate = new X509Certificate2(Convert.FromBase64String(content["encryptionCertificate"]));

                if (decryptionCertificate == null)
                {
                    decryptionCertificate = CertificateStoreProvider.GetCertificateByThumbprint(certificate.Thumbprint);
                    if (decryptionCertificate == null)
                    {
                        throw new ArgumentNullException("decryptionCertificate", "Couldn't find the right decryption certificate.");
                    }
                }

                if (decryptionCertificate.Thumbprint != certificate.Thumbprint)
                {
                    throw new ArgumentException("Provided certificate thumbprint [{decryptionCertificate.Thumbprint}] is different from thumbprint used [{certificate.Thumbprint}].");
                }

                this.Password =
                    AsymmetricCryptoProvider.Decrypt(
                        content["encryptedPassword"],
                        decryptionCertificate);
            }
            else if (!string.IsNullOrEmpty(content["encryptedPasswordEntropy"]))
            {
                this.Password =
                    SymmetricCryptoProvider.Decrypt(
                        content["encryptedPassword"],
                        content["encryptedPasswordEntropy"]);
            }
            content["password"] = this.Password;
        }

        public void Save(
            bool shouldStorePassword = false,
            X509Certificate2 encryptionCertificate = null,
            X509Certificate2 signingCertificate = null
            )
        {
            if (string.IsNullOrEmpty(Path))
                throw new ArgumentNullException("path", "Invalid path.");

            SaveAs(Path, shouldStorePassword, encryptionCertificate, signingCertificate);
        }

        public void SaveAs(
            string path,
            bool shouldStorePassword = false,
            X509Certificate2 encryptionCertificate = null,
            X509Certificate2 signingCertificate = null
            )
        {
            if (string.IsNullOrEmpty(path))
                throw new ArgumentNullException("path", "Invalid path.");
            using (var stream = File.Create(path))
            {
                SaveAs(stream, shouldStorePassword, encryptionCertificate, signingCertificate);
                Path = path;
            }
        }

        public void SaveAs(
            Stream stream,
            bool shouldStorePassword = false,
            X509Certificate2 encryptionCertificate = null,
            X509Certificate2 signingCertificate = null
            )
        {
            if (stream == null) throw new ArgumentNullException();

            YamlHandler YamlHandler = new YamlHandler();
            prepareAdsContent();
            

            //var content = GetContentFromConnectionInfo(shouldStorePassword, encryptionCertificate);

            var yaml = "";

            if (shouldStorePassword)
            {
                StoreEncryptedPassword(AdsContent, encryptionCertificate);
            }

            if (signingCertificate != null)
            {
                AdsContent["signingCertificate"] = Convert.ToBase64String(signingCertificate.GetRawCertData());
                yaml = YamlHandler.Serialize(AdsContent);
                yaml += "\n";
                yaml += Sign(yaml, signingCertificate);
            } else
            {
                yaml = YamlHandler.Serialize(AdsContent);
            }

            using (var writer = new StreamWriter(stream))
            {
                writer.Write(yaml);
                writer.Flush();
            }
        }

        private void prepareAdsContent()
        {
            AdsContent.Add("encryptedPassword", "");
            AdsContent.Add("encryptionCertificate", "");
            AdsContent.Add("encryptedPasswordEntropy", "");
            AdsContent.Add("signingCertificate", "");
        }

        private void RenameKey(IDictionary<string, string> dic,
                                      string fromKey, string toKey)
        {
            string value = dic[fromKey];
            dic.Remove(fromKey);
            dic[toKey] = value;
        }

        private void StoreEncryptedPassword(
            C2sDocumentContent content,
            X509Certificate2 encryptionCertificate = null
            )
        {
            if (this.Password == null) throw new ArgumentNullException("password", "Error while saving password.");
            if (encryptionCertificate != null)
            {
                var encryptedPassword = AsymmetricCryptoProvider.Encrypt(
                    this.Password,
                    encryptionCertificate);
                content.EncryptedPassword = encryptedPassword;
                content.EncryptionCertificate = Convert.ToBase64String(encryptionCertificate.GetRawCertData());
            }
            else
            {
                string entropy;
                var encryptedPassword = SymmetricCryptoProvider.Encrypt(
                                            this.Password,
                                            out entropy);
                content.EncryptedPassword = encryptedPassword;
                content.EncryptedPasswordEntropy = entropy;
            }
        }

        private void StoreEncryptedPassword(
            Dictionary<String, String> content,
            X509Certificate2 encryptionCertificate = null
            )
        {
            if (this.Password == null) throw new ArgumentNullException("password", "Error while saving password.");
            if (encryptionCertificate != null)
            {
                var encryptedPassword = AsymmetricCryptoProvider.Encrypt(
                    this.Password,
                    encryptionCertificate);
                this.AdsContent["encryptedPassword"] = encryptedPassword;
                this.AdsContent["encryptionCertificate"] = Convert.ToBase64String(encryptionCertificate.GetRawCertData());
            }
            else
            {
                string entropy;
                var encryptedPassword = SymmetricCryptoProvider.Encrypt(
                                            this.Password,
                                            out entropy);
                this.AdsContent["encryptedPassword"] = encryptedPassword;
                this.AdsContent["encryptedPasswordEntropy"] = entropy;
            }
        }

        private string Sign(string yaml, X509Certificate2 signingCertificate)
        {
            var signature = Encoding.UTF8.GetBytes(
                SignatureProvider.Sign(yaml, signingCertificate));
            var base64Signature = Convert.ToBase64String(signature, Base64FormattingOptions.InsertLineBreaks)
                .Replace("\r\n", "\r\n# ");
            var result = new StringBuilder();
            result.AppendLine("# SIG # Begin signature block");
            result.Append("# ");
            result.AppendLine(base64Signature);
            result.AppendLine("# SIG # End signature block");
            return result.ToString();
        }

        public static string MapToFileName(string propName)
        {
            if (AdsSpecificProperties.Contains(propName)) propName = "ADS_" + propName;
            if (ConnectionStringProperties.Contains(propName)) propName = "ADS_CS_" + propName;
            return propName;
        }

        private static HashSet<string> AdsSpecificProperties = new HashSet<string>() {
            "connectionName",
            "applicationName",
            "port",
            "azureTenantId",
            "azureAccount",
            "azureResourceId",
            "azurePortalEndpoint",
            "azureAccountToken",
            "groupId",
            "databaseDisplayName",
            "attachedDBFileName"
        };

        private static HashSet<string> ConnectionStringProperties = new HashSet<string>() {
            "failoverPartner",
            "attachDbFilename",
            "pooling",
            "maxPoolSize",
            "minPoolSize",
            "multipleActiveResultSets",
            "replication",
            "loadBalanceTimeout",
            "typeSystemVersion",
            "currentLanguage",
            "workstationId",
            "applicationIntent",
            "multiSubnetFailover",
            "connectRetryCount",
            "connectRetryInterval",
            "attestationProtocol",
            "contextConnection",
            "asynchronousProcessing",
            "persistSecurityInfo",
            "contextConnection"
        };

        //private C2sDocumentContent GetContentFromConnectionInfo(
        //        bool shouldStorePassword,
        //        X509Certificate2 encryptionCertificate = null
        //        )
        //{
        //    if (this.ConnectionInfo == null)
        //        throw new ArgumentNullException();

        //    //Only store username for username/password authentication types
        //    string userNameTemp = null;
        //    if (UIConnectionInfoUtil.GetAuthenticationType(ConnectionInfo) == AuthenticationType.SQLServerAuthentication
        //            || UIConnectionInfoUtil.GetAuthenticationType(ConnectionInfo) == AuthenticationType.AzureActiveDirectoryPassword)
        //    {
        //        userNameTemp = ConnectionInfo.UserName;
        //    }

        //    var content = new C2sDocumentContent
        //    {
        //        ServerType = "SqlServerType",
        //        ServerName = ConnectionInfo.ServerName,
        //        DatabaseName = UIConnectionInfoUtil.GetDatabaseName(ConnectionInfo),
        //        UserName = userNameTemp,
        //        NetworkProtocol = ConnectionInfo.AdvancedOptions[SqlServerType.NetworkProtocol],
        //        PacketSize = UIConnectionInfoUtil.GetPacketSize(ConnectionInfo),
        //        ConnectionTimeOut = UIConnectionInfoUtil.GetConnectionTimeout(ConnectionInfo),
        //        ExecutionTimeOut = UIConnectionInfoUtil.GetExecutionTimeout(ConnectionInfo),
        //        EncryptConnection = UIConnectionInfoUtil.GetEncryptConnection(ConnectionInfo),
        //        TrustServerCertificate = UIConnectionInfoUtil.GetTrustServerCertificate(ConnectionInfo),
        //        UseCustomColor = UIConnectionInfoUtil.GetUseCustomConnectionColor(ConnectionInfo),
        //        CustomColorSample = UIConnectionInfoUtil.GetCustomConnectionColor(ConnectionInfo).ToArgb(),
        //        AlwaysEncrypted = UIConnectionInfoUtil.GetColumnEncryption(ConnectionInfo),
        //        AESecureEnclavesURL = UIConnectionInfoUtil.GetColumnEncryptionAttestationURL(ConnectionInfo),
        //        OtherParams = ConnectionInfo.OtherParams,
        //        EncryptedPassword = null,
        //        EncryptedPasswordEntropy = null,
        //        EncryptionCertificate = null,
        //        SigningCertificate = null,
        //        Authentication = UIConnectionInfoUtil.GetAuthenticationType(ConnectionInfo).ValueName,
        //    };

        //    if (shouldStorePassword)
        //    {
        //        StoreEncryptedPassword(content, encryptionCertificate);
        //    }

        //    return content;
        //}
    }
}
