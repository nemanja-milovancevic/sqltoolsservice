//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Microsoft.SqlTools.Hosting.Protocol;
using Microsoft.SqlTools.ServiceLayer.C2S.Contracts;
using Microsoft.SqlTools.ServiceLayer.C2S.Providers;


namespace Microsoft.SqlTools.ServiceLayer.C2S
{
    public class C2sService
    {
        private static readonly Lazy<C2sService> instance = new Lazy<C2sService>(() => new C2sService());

        /// <summary>
        /// Gets the singleton instance object
        /// </summary>
        public static C2sService Instance
        {
            get { return instance.Value; }
        }

        /// <summary>
        /// Initializes the service instance
        /// </summary>
        public void InitializeService(IProtocolEndpoint serviceHost)
        {
            // Test
            serviceHost.SetRequestHandler(C2sTestRequest.Type, HandleC2sTestRequest);

            // Get Signing Certificate
            serviceHost.SetRequestHandler(GetSigningCertificateRequest.Type, HandleGetSigningCertificateRequest);

            // Save
            serviceHost.SetRequestHandler(SaveRequest.Type, HandleSave);

            // Open 
            serviceHost.SetRequestHandler(OpenRequest.Type, HandleOpen);

            // Show Signing Certificate
            serviceHost.SetRequestHandler(ShowSigningCertificateRequest.Type, HandleShowSigningCertificate);
        }

        /// <summary>
        /// Handles a c2s test request
        /// </summary>
        internal async Task HandleC2sTestRequest(
            C2sTestParams c2sTestParams,
            RequestContext<C2sTestResponse> requestContext)
        {
            try
            {
                C2sTestResponse response = new C2sTestResponse();
                response.ResultText = "Hello world!";

                await requestContext.SendResult(response);
            }
            catch (Exception ex)
            {
                await requestContext.SendError(ex.ToString());
            }
        }

        /// <summary>
        /// Handles a get signing certificate request
        /// </summary>
        internal async Task HandleGetSigningCertificateRequest(
            GetSigningCertificateParams requestParams,
            RequestContext<GetSigningCertificateResponse> requestContext)
        {
            try
            {
                GetSigningCertificateResponse response = new GetSigningCertificateResponse();

                var myCertificates = new X509Certificate2Collection();
                foreach (var certificate in (new X509CertificateStoreProvider()).GetMyCertificates())
                {
                    if (!certificate.IssuerName.Name.Contains("DO_NOT_TRUST"))
                    {
                        myCertificates.Add(certificate);
                    }
                }
                var result = X509Certificate2UI.SelectFromCollection(
                    myCertificates,
                    "Pick a certificate",
                    "",
                    X509SelectionFlag.SingleSelection);
                if (result.Count > 0)
                {
                    var certificate = result[0];
                    response.Subject= certificate.Subject;
                    response.Base64Certificate = Convert.ToBase64String(certificate.GetRawCertData());
                }
                else
                {
                    throw new Exception("Could not load certificates!");
                }

                await requestContext.SendResult(response);
            }
            catch (Exception ex)
            {
                await requestContext.SendError(ex.ToString());
            }
        }

        internal async Task HandleSave(
            SaveParams requestParams,
            RequestContext<SaveResponse> requestContext)
        {
            try
            {
                SaveResponse response = new SaveResponse();
                C2sDocumentManager c2SDocumentManager = new C2sDocumentManager();
                C2sDocument c2sDocument = c2SDocumentManager.Create();
                string password = null;
                requestParams.connectionParams.TryGetValue("password", out password);
                c2sDocument.Password = password;
                c2sDocument.AdsContent = requestParams.connectionParams;
                c2sDocument.AdsContent.Remove("password");
                X509Certificate2 encryptionCertificate = default(X509Certificate2);
                X509Certificate2 signingCertificate = default(X509Certificate2);

                if (requestParams.passwordEncryptionOption == "epwc")
                {
                    CertificateLoaderUtil.TryLoadEncryptionCertificate(requestParams.encryptionCertificatePath, out encryptionCertificate);
                }

                if (requestParams.shouldSignFile)
                {
                    CertificateLoaderUtil.TryLoadSigningCertificateFromStore(requestParams.signingCertificate, out signingCertificate);
                }
                c2sDocument.SaveAs(requestParams.savePath, requestParams.passwordEncryptionOption != "dsp", encryptionCertificate, signingCertificate);

                response.IsSuccess = true;
                response.Message = "File successfully saved.";

                await requestContext.SendResult(response);
            }
            catch (Exception ex)
            {
                await requestContext.SendError(ex.ToString());
            }
        }

        internal async Task HandleOpen(
            OpenParams requestParams,
            RequestContext<OpenResponse> requestContext)
        {
            try
            {
                OpenResponse response = new OpenResponse();

                C2sDocumentManager c2sDocumentManager = new C2sDocumentManager();
                C2sDocument c2SDocument = c2sDocumentManager.Read(requestParams.OpenPath);

                response.SigningCertificate = c2SDocument.Signer;
                response.ConnectionParams = c2SDocument.AdsContent;
                response.IsSuccess = true;
                response.Message = "File opened successfully.";

                await requestContext.SendResult(response);
            }
            catch (Exception ex)
            {
                await requestContext.SendError(ex.ToString());
            }
        }

        internal async Task HandleShowSigningCertificate(
            ShowSigningCertificateParams requestParams,
            RequestContext<ShowSigningCertificateResponse> requestContext)
        {
            try
            {
                ShowSigningCertificateResponse response = new ShowSigningCertificateResponse();
                X509Certificate2 signingCertificate = new X509Certificate2(
                        Convert.FromBase64String(requestParams.SigningCertificate));
                X509Certificate2UI.DisplayCertificate(signingCertificate);

                response.IsSuccess = true;
                response.Message = "Successfully shown signing certificate.";

                await requestContext.SendResult(response);
            }
            catch (Exception ex)
            {
                await requestContext.SendError(ex.ToString());
            }
        }
    }
}
