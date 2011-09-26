using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web.Profile;
using System.Configuration;
using MongoDB.Driver;
using MongoDB.Driver.Builders;
using MongoDB.Bson;
using System.Collections.Specialized;
using System.Web.Hosting;
using System.Configuration.Provider;

namespace MongoProviders
{
    /// <summary>
    /// Fork of: https://github.com/freshlogic/MongoDB.Web
    /// </summary>
    public class ProfileProvider : System.Web.Profile.ProfileProvider
    {

        public const string DEFAULT_NAME = "MongoProfileProvider";
        public const string DEFAULT_DATABASE_NAME = "test";
        public const string DEFAULT_PROFILE_COLLECTION_SUFFIX = "profiles";

        protected MongoServer _server;
        protected MongoDatabase _db;
        protected string _connectionString;
        protected string _databaseName;
        protected string _collectionSuffix;

        public struct ProfileElements
        {
            public string Username;
            public string IsAnonymous;
            public string LastActivityDate;
            public string LastUpdatedDate;
        }

        #region Public Properties/Fields

        public override string ApplicationName { get; set; }

        public string CollectionName { get; protected set; }

        public MongoCollection<BsonDocument> Collection { get; protected set; }

        public ProfileElements ElementNames { get; protected set; }

        #endregion


        #region Public Methods

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
               throw new ArgumentNullException("config");

            if (String.IsNullOrEmpty(name))
                name = DEFAULT_NAME;

            if (String.IsNullOrEmpty(config["description"])) {
                config.Remove("description");
                config.Add("description", Resources.ProfileProvider_description);
            }
            base.Initialize(name, config);


            // Get config values

            this.ApplicationName = config["applicationName"] ?? HostingEnvironment.ApplicationVirtualPath;
            _databaseName = Helper.GetConfigValue(config["databaseName"], DEFAULT_DATABASE_NAME);
            _collectionSuffix = Helper.GetConfigValue(config["collectionSuffix"], DEFAULT_PROFILE_COLLECTION_SUFFIX);


            // Initialize Connection String

            string temp = config["connectionStringName"];
            if (String.IsNullOrWhiteSpace(temp))
                throw new ProviderException(Resources.Connection_name_not_specified);

            ConnectionStringSettings ConnectionStringSettings = ConfigurationManager.ConnectionStrings[temp];
            if (null == ConnectionStringSettings || String.IsNullOrWhiteSpace(ConnectionStringSettings.ConnectionString))
                throw new ProviderException(String.Format(Resources.Connection_string_not_found, temp));

			_connectionString = ConnectionStringSettings.ConnectionString;


            // Check for unrecognized config values

            config.Remove("applicationName");
            config.Remove("connectionStringName");
            config.Remove("databaseName");
            config.Remove("collectionSuffix");

            if (config.Count > 0)
            {
                string key = config.GetKey(0);
                if (!String.IsNullOrEmpty(key))
                    throw new ProviderException(String.Format(Resources.Provider_unrecognized_attribute, key));
            }


            // Initialize MongoDB Server

            ProfileInfoClassMap.Register();
            _server = MongoServer.Create(_connectionString);
            _db = _server.GetDatabase(_databaseName);
            this.CollectionName = Helper.GenerateCollectionName(this.ApplicationName, _collectionSuffix);
            this.Collection = _db.GetCollection(this.CollectionName);


            // store element names

            var names = new ProfileElements();
            names.Username = Helper.GetElementNameFor<ProfileInfo>(p => p.UserName);
            names.IsAnonymous = Helper.GetElementNameFor<ProfileInfo, bool>(p => p.IsAnonymous);
            names.LastActivityDate = Helper.GetElementNameFor<ProfileInfo, DateTime>(p => p.LastActivityDate);
            names.LastUpdatedDate = Helper.GetElementNameFor<ProfileInfo, DateTime>(p => p.LastUpdatedDate );
            ElementNames = names;


            // ensure indexes

            this.Collection.EnsureIndex(ElementNames.IsAnonymous, ElementNames.LastActivityDate, ElementNames.Username);
            this.Collection.EnsureIndex(ElementNames.IsAnonymous, ElementNames.Username);
            this.Collection.EnsureIndex(ElementNames.LastActivityDate);
            this.Collection.EnsureIndex(ElementNames.Username);
            this.Collection.EnsureIndex(ElementNames.Username, ElementNames.IsAnonymous);

        }


        public override int DeleteInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
        {
            QueryComplete query = Query.LTE(ElementNames.LastActivityDate, userInactiveSinceDate);

            if (authenticationOption != ProfileAuthenticationOption.All)
            {
                query = Query.And(query, Query.EQ(ElementNames.IsAnonymous, authenticationOption == ProfileAuthenticationOption.Anonymous));
            }

            return (int)this.Collection.Remove(query).DocumentsAffected;
        }

        public override int DeleteProfiles(string[] usernames)
        {
            var query = Query.In(ElementNames.Username, new BsonArray(usernames));
            return (int)this.Collection.Remove(query).DocumentsAffected;
        }

        public override int DeleteProfiles(ProfileInfoCollection profiles)
        {
            return this.DeleteProfiles(profiles.Cast<ProfileInfo>().Select(profile => profile.UserName).ToArray());
        }

        public override ProfileInfoCollection FindInactiveProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            return GetProfiles(authenticationOption, usernameToMatch, userInactiveSinceDate, pageIndex, pageSize, out totalRecords);
        }

        public override ProfileInfoCollection FindProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return GetProfiles(authenticationOption, usernameToMatch, null, pageIndex, pageSize, out totalRecords);
        }

        public override ProfileInfoCollection GetAllInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            return GetProfiles(authenticationOption, null, userInactiveSinceDate, pageIndex, pageSize, out totalRecords);
        }

        public override ProfileInfoCollection GetAllProfiles(ProfileAuthenticationOption authenticationOption, int pageIndex, int pageSize, out int totalRecords)
        {
            return GetProfiles(authenticationOption, null, null, pageIndex, pageSize, out totalRecords);
        }

        public override int GetNumberOfInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
        {
            QueryComplete query = Query.LTE(ElementNames.LastActivityDate, userInactiveSinceDate);

            if (ProfileAuthenticationOption.All != authenticationOption)
            {
                query = Query.And(query, Query.EQ(ElementNames.IsAnonymous, authenticationOption == ProfileAuthenticationOption.Anonymous));
            }

            return (int)this.Collection.Count(query);
        }

        public override SettingsPropertyValueCollection GetPropertyValues(SettingsContext context, SettingsPropertyCollection collection)
        {
            var settingsPropertyValueCollection = new SettingsPropertyValueCollection();
            
            if (context == null || collection == null || collection.Count < 1)
            {
                return settingsPropertyValueCollection;
            }

            var username = (string)context["UserName"];

            if(String.IsNullOrWhiteSpace(username))
            {
                return settingsPropertyValueCollection;
            }

            var query = Query.EQ(ElementNames.Username, username);
            var bsonDocument = this.Collection.FindOneAs<BsonDocument>(query);

            foreach (SettingsProperty settingsProperty in collection)
            {
                var settingsPropertyValue = new SettingsPropertyValue(settingsProperty);
                settingsPropertyValueCollection.Add(settingsPropertyValue);

                var value = bsonDocument[settingsPropertyValue.Name].RawValue;

                if (value != null)
                {
                    settingsPropertyValue.PropertyValue = value;
                    settingsPropertyValue.IsDirty = false;
                    settingsPropertyValue.Deserialized = true;
                }
            }

            var update = Update.Set(ElementNames.LastActivityDate, DateTime.Now);
            this.Collection.Update(query, update);

            return settingsPropertyValueCollection;
        }

        public override void SetPropertyValues(SettingsContext context, SettingsPropertyValueCollection collection)
        {
            var username = (string)context["UserName"];
            var isAuthenticated = (bool)context["IsAuthenticated"];

            if (String.IsNullOrWhiteSpace(username) || collection.Count < 1)
            {
                return;
            }

            var values = new Dictionary<string, object>();

            foreach (SettingsPropertyValue settingsPropertyValue in collection)
            {
                if (!settingsPropertyValue.IsDirty)
                {
                    continue;
                }
                
                if (!isAuthenticated && !(bool)settingsPropertyValue.Property.Attributes["AllowAnonymous"])
                {
                    continue;
                }

                values.Add(settingsPropertyValue.Name, settingsPropertyValue.PropertyValue);
            }

            var query = Query.EQ(ElementNames.Username, username);
            var bsonDocument = this.Collection.FindOneAs<BsonDocument>(query);

            if (bsonDocument == null)
            {
                bsonDocument = new BsonDocument
                {
                    { ElementNames.Username, username }
                };
            }

            var mergeDocument = new BsonDocument
            {
                { ElementNames.LastActivityDate, DateTime.Now },
                { ElementNames.LastUpdatedDate, DateTime.Now }
            };

            mergeDocument.Add(values as IDictionary<string, object>);
            bsonDocument.Merge(mergeDocument);

            this.Collection.Save(bsonDocument);
        }

        #endregion


        #region Private Methods

        private ProfileInfoCollection GetProfiles(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime? userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            var query = GetQuery(authenticationOption, usernameToMatch, userInactiveSinceDate);

            totalRecords = (int)this.Collection.Count(query);

            var profileInfoCollection = new ProfileInfoCollection();
            MongoCursor<BsonDocument> cursor = null;

            cursor = this.Collection.FindAs<BsonDocument>(query).SetSkip(pageIndex * pageSize).SetLimit(pageSize);
            foreach (var bsonDocument in cursor)
            {
                profileInfoCollection.Add(ToProfileInfo(bsonDocument));
            }

            return profileInfoCollection;
        }

        private IMongoQuery GetQuery(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime? userInactiveSinceDate)
        {
            IList<QueryComplete> queries = new List<QueryComplete>();
            
            if (authenticationOption != ProfileAuthenticationOption.All)
            {
                queries.Add(Query.EQ(ElementNames.IsAnonymous, authenticationOption == ProfileAuthenticationOption.Anonymous));
            }

            if(!String.IsNullOrWhiteSpace(usernameToMatch))
            {
                queries.Add(Query.Matches(ElementNames.Username, usernameToMatch));
            }

            if(userInactiveSinceDate.HasValue)
            {
                queries.Add(Query.LTE(ElementNames.LastActivityDate, userInactiveSinceDate));
            }

            if (0 == queries.Count)
            {
                return null;
            }
            if (1 == queries.Count)
            {
                return queries[0];
            }
            else
            {
                return Query.And(queries.ToArray());
            }
        }

        protected ProfileInfo ToProfileInfo(BsonDocument bsonDocument)
        {
            return new ProfileInfo(bsonDocument[ElementNames.Username].AsString, bsonDocument[ElementNames.IsAnonymous].AsBoolean, bsonDocument[ElementNames.LastActivityDate].AsDateTime, bsonDocument[ElementNames.LastUpdatedDate].AsDateTime, 0);
        }

        #endregion
    }
}
