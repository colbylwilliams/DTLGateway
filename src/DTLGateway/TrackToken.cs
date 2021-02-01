/**
 *  Copyright (c) Microsoft Corporation.
 *  Licensed under the MIT License.
 */

using System.Threading.Tasks;
using DTLGateway.Model;
using Microsoft.Azure.Cosmos.Table;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;

namespace DTLGateway
{
    public static class TrackToken
    {
        private static async Task Track(CloudTable table, ITableEntity entity, ILogger log)
        {
            log.LogInformation($"Track {entity.GetType().Name}: {entity.RowKey}");

            var operation = TableOperation.InsertOrReplace(entity);

            await table.ExecuteAsync(operation).ConfigureAwait(false);
        }

        [FunctionName(nameof(TrackToken))]
        public static async Task Run(
            [QueueTrigger("track-token")] TokenEntity tokenEntity,
            [Table("tokens")] CloudTable tokenTable,
            [Table("users")] CloudTable userTable,
            ILogger log)
        {
            await Track(tokenTable, tokenEntity, log);

            var userEntity = new UserEntity(tokenEntity.UserId);

            await Track(userTable, userEntity, log);
        }
    }
}
