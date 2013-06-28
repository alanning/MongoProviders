using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MongoDB.Driver;

namespace MongoProviders
{
    internal class ClientMongo
    {
        /// <summary>
        /// Gets the mongo connection.
        /// </summary>
        /// <param name="connectionString">The connection string.</param>
        /// <returns></returns>
        internal static MongoDatabase GetMongoConnection(String connectionString)
        {
            UserClassMap.Register();
            var mongoUrl = MongoUrl.Create(connectionString);
            var server = new MongoClient(connectionString).GetServer();
            return server.GetDatabase(mongoUrl.DatabaseName);
        }
    }
}
