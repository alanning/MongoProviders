// The MIT License (MIT)
//
// Copyright (c) 2011 Adrian Lanning <adrian@nimblejump.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software 
// and associated documentation files (the "Software"), to deal in the Software without restriction, 
// including without limitation the rights to use, copy, modify, merge, publish, distribute, 
// sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is 
// furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or 
// substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT 
// NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND 
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, 
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Web.Security;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Web.Configuration;
using System.Text.RegularExpressions;
using MongoDB.Driver;
using MongoDB.Driver.Builders;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using FluentMongo.Linq;

namespace MongoProviders
{
    /// <summary>
    /// ASP.NET Role Provider that uses MongoDB
    /// 
    /// Notes:
    ///
    ///   Role Collection documents consist only of an Id which is the roleName.
    ///     Ex: { _id:"admin" }
    ///   Roles will be stored as lowercase to prevent duplicates ("Admin" vs "admin").
    ///
    /// Non-standard configuration attributes:
    ///
    ///   invalidUsernameCharacters - characters that are illegal in Usernames.  Default: ",%"
    ///        Ex: invalidUsernameCharacters=",%&"
    ///        Note: the percent character, "%", should generally always be illegal since it is used in the FindUsersBy*
    ///        methods to indicate a wildcard.  This matches the behavior of the SQL Membership provider in supporting 
    ///        basic SQL Like syntax, although only the "%" is supported (not "_" or "[]")
    ///
    ///   invalidRoleCharacters - characters that are illegal in a Role name.  Default: ",%"
    ///        Ex: invalidRoleCharacters=",!%*"
    ///        Note: the percent character, "%", should generally always be illegal since it is used in the FindUsersBy*
    ///        methods to indicate a wildcard.  This matches the behavior of the SQL Membership provider in supporting 
    ///        basic SQL Like syntax, although only the "%" is supported (not "_" or "[]")
    ///
    ///   writeExceptionsToEventLog - boolean indicating whether database exceptions should be 
    ///        written to the EventLog rather than returned to UI.  Default: "true"
    ///        Ex: writeExceptionsToEventLog="false"
    ///
    ///   databaseName - name of the MongoDB database to connect to.  Default: "test"
    ///        Ex: databaseName="userdb"
    ///
    ///   roleCollectionSuffix - suffix of the collection to use for role data.  Default: "users"
    ///        Ex: userCollectionSuffix="users"
    ///        Note: the actual collection name used will be the combination of the ApplicationName and the roleCollectionSuffix.
    ///        For example, if the ApplicationName is "/", then the default user Collection name will be "/users".
    ///        This relieves us from having to include the ApplicationName in every query and also saves space in two ways:
    ///          1. ApplicationName does not need to be stored with the User data
    ///          2. Indexes no longer need to be composite. ie. "LowercaseUsername" rather than "ApplicationName", "LowercaseUsername"
    ///
    ///   userCollectionSuffix - suffix of the collection to use for Membership User data.  Default: "users"
    ///        Ex: userCollectionSuffix="users"
    ///
    /// </summary>
    public class RoleProvider : System.Web.Security.RoleProvider
    {
        #region Public Properties/Fields

        public const string DEFAULT_NAME = "MongoRoleProvider";
        public const string DEFAULT_DATABASE_NAME = "test";
        public const string DEFAULT_ROLE_COLLECTION_SUFFIX = "roles";
        public const string DEFAULT_USER_COLLECTION_SUFFIX = MongoProviders.MembershipProvider.DEFAULT_USER_COLLECTION_SUFFIX;
        public const string DEFAULT_INVALID_CHARACTERS = ",%";
		public const int MAX_USERNAME_LENGTH = 256;
		public const int MAX_ROLE_LENGTH = 256;

        public string RoleCollectionName
        {
            get
            {
                return _roleCollectionName;
            }
        }
        public string UserCollectionName
        {
            get
            {
                return _userCollectionName;
            }
        }

        public MongoCollection<BsonDocument> RoleCollection
        {
            get
            {
                return _db.GetCollection(_roleCollectionName);
            }
        }

        public MongoCollection<User> UserCollection
        {
            get
            {
                return _db.GetCollection<User>(_userCollectionName);
            }
        }

		/// <summary>
		/// The name of the application using the custom membership provider.
		/// </summary>
		/// <value></value>
		/// <returns>
		/// The name of the application using the custom membership provider.
		/// </returns>
        public override string ApplicationName
        {
            get { return _applicationName; }
            set
            {
                _applicationName = value;
                _roleCollectionName = Helper.GenerateCollectionName(_applicationName, _roleCollectionSuffix);
                _userCollectionName = Helper.GenerateCollectionName(_applicationName, _userCollectionSuffix);
            }
        }

        public RoleMembershipElements ElementNames { get; set; }

        public struct RoleMembershipElements
        {
            public string LowercaseUsername;
            public string Roles;
        }

        #endregion

        #region Protected Properties/Fields

        protected string _connectionString;
        protected MachineKeySection _machineKey;
        protected string _databaseName;
        protected string _userCollectionSuffix;
        protected string _roleCollectionSuffix;
        protected string _userCollectionName;
        protected string _roleCollectionName;

        protected MongoServer _server;
        protected MongoDatabase _db;

        protected string _applicationName;
        protected string _invalidUsernameCharacters;
        protected string _invalidRoleCharacters;


        protected string InvalidUsernameCharacters
        {
            get { return _invalidUsernameCharacters; }
            set { _invalidUsernameCharacters = value; }
        }
        protected string InvalidRoleCharacters
        {
            get { return _invalidRoleCharacters; }
            set { _invalidRoleCharacters = value; }
        }


        /// <summary>
        /// The list of Roles for this Application
        /// </summary>
        protected IEnumerable<string> Roles 
        {
            get
            {
                var docs = RoleCollection.FindAll();
                var ids = docs.Select(d => d["_id"].AsString);
                return ids;
            }
        }

        #endregion

        #region Public Methods

        public override void Initialize(string name, NameValueCollection config){

            if (config == null)
               throw new ArgumentNullException("config");

            if (String.IsNullOrEmpty(name))
                name = DEFAULT_NAME;

            if (String.IsNullOrEmpty(config["description"])) {
                config.Remove("description");
                config.Add("description", Resources.RoleProvider_description);
            }
            base.Initialize(name, config);


            _applicationName = config["applicationName"] ?? System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath;
            _invalidUsernameCharacters = Helper.GetConfigValue(config["invalidUsernameCharacters"], DEFAULT_INVALID_CHARACTERS);
            _invalidRoleCharacters = Helper.GetConfigValue(config["invalidRoleCharacters"], DEFAULT_INVALID_CHARACTERS);
            _databaseName = Helper.GetConfigValue(config["databaseName"], DEFAULT_DATABASE_NAME);
            _roleCollectionSuffix = Helper.GetConfigValue(config["roleCollectionSuffix"], DEFAULT_ROLE_COLLECTION_SUFFIX);
            _userCollectionSuffix = Helper.GetConfigValue(config["userCollectionSuffix"], DEFAULT_USER_COLLECTION_SUFFIX);



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
            config.Remove("invalidUsernameCharacters"); 
            config.Remove("invalidRoleCharacters"); 
            config.Remove("databaseName");
            config.Remove("roleCollectionSuffix");
            config.Remove("userCollectionSuffix");

            if (config.Count > 0)
            {
                string key = config.GetKey(0);
                if (!String.IsNullOrEmpty(key))
                    throw new ProviderException(String.Format(Resources.Provider_unrecognized_attribute, key));
            }



            // Initialize MongoDB Server
            UserClassMap.Register();
            _server = MongoServer.Create(_connectionString);
            _db = _server.GetDatabase(_databaseName);

            _userCollectionName = Helper.GenerateCollectionName(_applicationName, _userCollectionSuffix);
            _roleCollectionName = Helper.GenerateCollectionName(_applicationName, _roleCollectionSuffix);


            // store element names

            var names = new RoleMembershipElements();
            names.LowercaseUsername = Helper.GetElementNameFor<User>(p => p.LowercaseUsername);
            names.Roles = Helper.GetElementNameFor<User>(p => p.Roles);

            ElementNames = names;


            // ensure indexes

            // MongoDB automatically indexes the _id field
            this.UserCollection.EnsureIndex(ElementNames.LowercaseUsername);
            this.UserCollection.EnsureIndex(ElementNames.Roles);

        }
        

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref usernames, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, "usernames");
            SecUtility.CheckArrayParameter(ref roleNames, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleNames");

            // ensure lowercase
            var roles = new List<string>();
            foreach (var role in roleNames)
            {
                roles.Add(role.ToLowerInvariant());
            }
            var users = new List<string>();
            foreach (var username in usernames)
            {
                users.Add(username.ToLowerInvariant());
            }


            // first add any non-existant roles to roles collection
            
            // a) pull all roles, filter out existing, push new
            //    ...or 
            // b) save all passed in roles 

            foreach (var role in roles)
            {
                CreateRole(role);
            }


            // now update all users' roles

            var query = Query.In(ElementNames.LowercaseUsername, new BsonArray(users.ToArray()));

            var update = Update.AddToSetEachWrapped<string>(ElementNames.Roles, roles);

            var result = UserCollection.Update(query, update, UpdateFlags.Multi, SafeMode.True);
            if (result.HasLastErrorMessage)
            {
                throw new ProviderException(result.LastErrorMessage);
            }
        }

        public override void CreateRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleName");

            var doc = new BsonDocument();
            doc.SetDocumentId(roleName.ToLowerInvariant());
            var result = RoleCollection.Save(doc, SafeMode.True);
            if (!result.Ok)
            {
                throw new ProviderException(String.Format("Could not create role '{0}'. Reason: {1}", roleName, result.LastErrorMessage));
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleName");

            var rolePopulated = UserCollection.AsQueryable().Where(u => u.Roles.Contains(roleName.ToLowerInvariant())).Any();
            if (throwOnPopulatedRole && rolePopulated)
            {
                throw new ProviderException(Resources.Role_is_not_empty);
            }

            var result = RoleCollection.Remove(Query.EQ("_id", roleName.ToLowerInvariant()), SafeMode.True);
            return result.Ok;
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
			SecUtility.CheckParameter(ref roleName, true, true, null, MAX_ROLE_LENGTH, "roleName");

            if (String.IsNullOrWhiteSpace(usernameToMatch)){
                return new string[0];
            }

            var username = ElementNames.LowercaseUsername;
            QueryComplete userQuery = Helper.FindQuery(usernameToMatch.ToLowerInvariant(), username);
            var query = Query.And(
                Query.EQ(ElementNames.Roles, roleName.ToLowerInvariant()),
                userQuery
                );
            var cursor = UserCollection.FindAs<BsonDocument>(query);

            // only want the usernames
            cursor.SetFields(Fields.Include(username).Exclude("_id"));

            var names = new List<string>();
            foreach (var doc in cursor)
            {
                var str = doc[username].AsString;
                names.Add(str);
            }

            return names.ToArray();
        }


        public override string[] GetAllRoles()
        {
            return Roles.ToArray();
        }

        public override string[] GetRolesForUser(string username)
        {
			SecUtility.CheckParameter(ref username, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, "username");

            string[] roles = UserCollection.AsQueryable()
                .Where(u => u.LowercaseUsername == username.ToLowerInvariant())
                .Select(u => u.Roles.ToArray()).FirstOrDefault();

            return roles;
        }

        public override string[] GetUsersInRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleName");

            var usernames = UserCollection.AsQueryable()
                .Where(u => u.Roles.Contains(roleName.ToLowerInvariant()))
                .Select(u => u.Username).ToArray();

            return usernames;
        }

        public override bool IsUserInRole(string username, string roleName)
        {
			SecUtility.CheckParameter(ref roleName, true, true, null, MAX_ROLE_LENGTH, "roleName");

            var found = UserCollection.AsQueryable()
                .Where(u => u.LowercaseUsername == username.ToLowerInvariant() &&
                            u.Roles.Contains(roleName.ToLowerInvariant()) ).Any();
            return found;
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref usernames, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, "usernames");
            SecUtility.CheckArrayParameter(ref roleNames, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleNames");

            // update all users' roles

            var roles = new List<string>();
            foreach (var role in roleNames)
            {
                roles.Add(role.ToLowerInvariant());
            }
            var users = new List<string>();
            foreach (var username in usernames)
            {
                users.Add(username.ToLowerInvariant());
            }

            var query = Query.In(ElementNames.LowercaseUsername, new BsonArray(users.ToArray()));

            var update = Update.PullAllWrapped<string>(ElementNames.Roles, roles);

            var result = _db.GetCollection<User>(_userCollectionName).Update(query, update, UpdateFlags.Multi, SafeMode.True);
            if (result.HasLastErrorMessage)
            {
                throw new ProviderException(result.LastErrorMessage);
            }

        }

        public override bool RoleExists(string roleName)
        {
			SecUtility.CheckParameter(ref roleName, true, true, null, MAX_ROLE_LENGTH, "roleName");
            return Roles.Contains(roleName.ToLowerInvariant());
        }


        #endregion


    }
}
