//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.SqlTools.Hosting.Protocol;
using Microsoft.SqlTools.Hosting.Protocol.Contracts;
using Microsoft.Kusto.ServiceLayer.Connection;
using Microsoft.Kusto.ServiceLayer.Scripting.Contracts;
using Microsoft.SqlTools.Utility;
using Microsoft.Kusto.ServiceLayer.Utility;

namespace Microsoft.Kusto.ServiceLayer.Scripting
{
    /// <summary>
    /// Main class for Scripting Service functionality
    /// </summary>
    public sealed class ScriptingService : IDisposable
    {
        private static readonly Lazy<ScriptingService> LazyInstance = new Lazy<ScriptingService>(() => new ScriptingService());

        public static ScriptingService Instance => LazyInstance.Value;

        private IConnectionService _connectionService;

        private IConnectionManager _connectionManager;

        private readonly Lazy<ConcurrentDictionary<string, ScriptingOperation>> operations =
            new Lazy<ConcurrentDictionary<string, ScriptingOperation>>(() => new ConcurrentDictionary<string, ScriptingOperation>());

        private bool disposed;
        
        private IScripter _scripter;

        /// <summary>
        /// The collection of active operations
        /// </summary>
        internal ConcurrentDictionary<string, ScriptingOperation> ActiveOperations => operations.Value;

        /// <summary>
        /// Initializes the Scripting Service instance
        /// </summary>
        /// <param name="serviceHost"></param>
        /// <param name="scripter"></param>
        /// <param name="connectionService"></param>
        public void InitializeService(ServiceHost serviceHost, IScripter scripter, IConnectionService connectionService, IConnectionManager connectionManager)
        {
            _scripter = scripter;
            _connectionService = connectionService;
            _connectionManager = connectionManager;
            
            serviceHost.SetRequestHandler(ScriptingRequest.Type, this.HandleScriptExecuteRequest);
            serviceHost.SetRequestHandler(ScriptingCancelRequest.Type, this.HandleScriptCancelRequest);
            serviceHost.SetRequestHandler(ScriptingListObjectsRequest.Type, this.HandleListObjectsRequest);

            // Register handler for shutdown event
            serviceHost.RegisterShutdownTask((shutdownParams, requestContext) =>
            {
                this.Dispose();
                return Task.FromResult(0);
            });
        }

        /// <summary>
        /// Handles request to execute start the list objects operation.
        /// </summary>
        private async Task HandleListObjectsRequest(ScriptingListObjectsParams parameters, RequestContext<ScriptingListObjectsResult> requestContext)
        {
            try
            {
                ScriptingListObjectsOperation operation = new ScriptingListObjectsOperation(parameters);
                operation.CompleteNotification += (sender, e) => requestContext.SendEvent(ScriptingListObjectsCompleteEvent.Type, e);

                RunTask(requestContext, operation);

                await requestContext.SendResult(new ScriptingListObjectsResult { OperationId = operation.OperationId });
            }
            catch (Exception e)
            {
                await requestContext.SendError(e);
            }
        }

        /// <summary>
        /// Handles request to start the scripting operation
        /// </summary>
        public async Task HandleScriptExecuteRequest(ScriptingParams parameters, RequestContext<ScriptingResult> requestContext)
        {
            try
            {
                // if a connection string wasn't provided as a parameter then
                // use the owner uri property to lookup its associated ConnectionInfo
                // and then build a connection string out of that
                if (parameters.DatabaseName == null)
                {
                    ConnectionInfo connInfo;
                    _connectionManager.TryGetValue(parameters.OwnerUri, out connInfo);
                    if (connInfo != null)
                    {
                        parameters.DatabaseName = connInfo.ConnectionDetails.DatabaseName;
                    }
                    else
                    {
                        throw new Exception("Could not find ConnectionInfo");
                    }
                }

                if (!ShouldCreateScriptAsOperation(parameters))
                {
                    throw new InvalidOperationException("Unable to create script.");
                }
                
                var datasource = _connectionService.GetOrOpenConnection(parameters.OwnerUri, ConnectionType.Default)
                    .Result.GetUnderlyingConnection();

                SmoScriptingOperation operation = new ScriptAsScriptingOperation(parameters, _scripter, datasource);
                operation.PlanNotification += (sender, e) => requestContext.SendEvent(ScriptingPlanNotificationEvent.Type, e).Wait();
                operation.ProgressNotification += (sender, e) => requestContext.SendEvent(ScriptingProgressNotificationEvent.Type, e).Wait();
                operation.CompleteNotification += (sender, e) => this.SendScriptingCompleteEvent(requestContext, ScriptingCompleteEvent.Type, e, operation, parameters.ScriptDestination);

                RunTask(requestContext, operation);

            }
            catch (Exception e)
            {
                await requestContext.SendError(e);
            }
        }

        private bool ShouldCreateScriptAsOperation(ScriptingParams parameters)
        {
            // Scripting as operation should be used to script one object.
            // Scripting data and scripting to file is not supported by scripting as operation
            // To script Select, alter and execute use scripting as operation. The other operation doesn't support those types
            return parameters.ScriptingObjects != null && parameters.ScriptingObjects.Count == 1 && parameters.ScriptOptions != null 
                   && parameters.ScriptOptions.TypeOfDataToScript == "SchemaOnly" && parameters.ScriptDestination == "ToEditor" 
                   || parameters.Operation == ScriptingOperationType.Select 
                   || parameters.Operation == ScriptingOperationType.Execute 
                   || parameters.Operation == ScriptingOperationType.Alter;
        }

        /// <summary>
        /// Handles request to cancel a script operation.
        /// </summary>
        public async Task HandleScriptCancelRequest(ScriptingCancelParams parameters, RequestContext<ScriptingCancelResult> requestContext)
        {
            try
            {
                ScriptingOperation operation = null;
                if (this.ActiveOperations.TryRemove(parameters.OperationId, out operation))
                {
                    operation.Cancel();
                }
                else
                {
                    Logger.Write(TraceEventType.Information, string.Format("Operation {0} was not found", operation.OperationId));
                }

                await requestContext.SendResult(new ScriptingCancelResult());
            }
            catch (Exception e)
            {
                await requestContext.SendError(e);
            }
        }

        private async void SendScriptingCompleteEvent<TParams>(RequestContext<ScriptingResult> requestContext, EventType<TParams> eventType, TParams parameters, 
                                                               SmoScriptingOperation operation, string scriptDestination)
        {
            await requestContext.SendEvent(eventType, parameters);
            switch (scriptDestination)
            {
                case "ToEditor":
                    await requestContext.SendResult(new ScriptingResult { OperationId = operation.OperationId, Script = operation.ScriptText });
                    break;
                case "ToSingleFile":
                    await requestContext.SendResult(new ScriptingResult { OperationId = operation.OperationId });
                    break;
                default:
                    await requestContext.SendError(string.Format("Operation {0} failed", operation.ToString()));
                    break;
            }
        }

        /// <summary>
        /// Runs the async task that performs the scripting operation.
        /// </summary>
        private void RunTask<T>(RequestContext<T> context, ScriptingOperation operation)
        {
            ScriptingTask = Task.Run(async () =>
            {
                try
                {
                    this.ActiveOperations[operation.OperationId] = operation;
                    operation.Execute();
                }
                catch (Exception e)
                {
                    await context.SendError(e);
                }
                finally
                {
                    ScriptingOperation temp;
                    this.ActiveOperations.TryRemove(operation.OperationId, out temp);
                }
            }).ContinueWithOnFaulted(async t => await context.SendError(t.Exception));
        }

        internal Task ScriptingTask { get; set; }

        /// <summary>
        /// Disposes the scripting service and all active scripting operations.
        /// </summary>
        public void Dispose()
        {
            if (!disposed)
            {
                disposed = true;
                
                foreach (var operation in this.ActiveOperations.Values)
                {
                    operation.Dispose();
                }
            }
        }
    }
}
