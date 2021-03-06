/**
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT License.
 */

using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;

namespace RDGateway.Functions
{
    public static class HealthCheck
    {
        [FunctionName(nameof(HealthCheck))]
        public static IActionResult Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "health")] HttpRequest req)
        {
            // This function is used to by the Azure Load Balancer to check the backend health.
            // Add additional checks, if you need more precise health reporting for the load
            // balancer probes.


            return new OkResult();
        }
    }
}
