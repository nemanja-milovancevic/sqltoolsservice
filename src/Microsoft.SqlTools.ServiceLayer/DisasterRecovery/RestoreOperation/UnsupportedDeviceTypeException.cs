﻿//
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//

using System;
using Microsoft.SqlServer.Management.Smo;

namespace Microsoft.SqlTools.ServiceLayer.DisasterRecovery.RestoreOperation
{
    class UnsupportedDeviceTypeException: Exception
    {
        public UnsupportedDeviceTypeException(DeviceType deviceType) : base("Unsupported device type " + deviceType.ToString() + ".")
        {
        }
    }
}
