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
using MongoDB.Driver.Linq;

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
        public const string DEFAULT_USER_COLLECTION_SUFFIX = MembershipProvider.DEFAULT_USER_COLLECTION_SUFFIX;
        public const string DEFAULT_INVALID_CHARACTERS = ",%";
		public const int MAX_USERNAME_LENGTH = 256;
		public const int MAX_ROLE_LENGTH = 256;

        private const string DOCUMENT_ID_NAME = "_id";
        private const string ROLE_NAMES = "roleNames";
        private const string ROLE_NAME = "roleName";
        private const string USER_NAMES = "usernames";
        private const string USER_NAME = "username";

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
                return Database.GetCollection(_roleCollectionName);
            }
        }

        public MongoCollection<User> UserCollection
        {
            get
            {
                return Database.GetCollection<User>(_userCollectionName);
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
                _roleCollectionName = Helper.GenerateCollectionName(_applicationName, RoleCollectionSuffix);
                _userCollectionName = Helper.GenerateCollectionName(_applicationName, UserCollectionSuffix);
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

        protected string ConnectionString;
        protected MachineKeySection MachineKey;
        protected string UserCollectionSuffix;
        protected string RoleCollectionSuffix;
        protected string _userCollectionName;
        protected string _roleCollectionName;

        protected MongoDatabase Database;

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
                var ids = docs.Select(d => d[DOCUMENT_ID_NAME].AsString);
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
            RoleCollectionSuffix = Helper.GetConfigValue(config["roleCollectionSuffix"], DEFAULT_ROLE_COLLECTION_SUFFIX);
            UserCollectionSuffix = Helper.GetConfigValue(config["userCollectionSuffix"], DEFAULT_USER_COLLECTION_SUFFIX);



            // Initialize Connection String

            var temp = config["connectionStringName"];

            if (String.IsNullOrWhiteSpace(temp))
                throw new ProviderException(Resources.Connection_name_not_specified);

            var connectionStringSettings = ConfigurationManager.ConnectionStrings[temp];
            if (null == connectionStringSettings || String.IsNullOrWhiteSpace(connectionStringSettings.ConnectionString))
                throw new ProviderException(String.Format(Resources.Connection_string_not_found, temp));

			ConnectionString = connectionStringSettings.ConnectionString;


            // Check for unrecognized config values

            config.Remove("applicationName");
            config.Remove("connectionStringName");
            config.Remove("invalidUsernameCharacters"); 
            config.Remove("invalidRoleCharacters"); 
            config.Remove("roleCollectionSuffix");
            config.Remove("userCollectionSuffix");

            if (config.Count > 0)
            {
                var key = config.GetKey(0);

                if (!String.IsNullOrEmpty(key))
                    throw new ProviderException(String.Format(Resources.Provider_unrecognized_attribute, key));
            }

            // Initialize MongoDB Server
            Database = ClientMongo.GetMongoConnection(ConnectionString);

            _userCollectionName = Helper.GenerateCollectionName(_applicationName, UserCollectionSuffix);
            _roleCollectionName = Helper.GenerateCollectionName(_applicationName, RoleCollectionSuffix);


            // store element names
            var names = new RoleMembershipElements
                {
                    LowercaseUsername = Helper.GetElementNameFor<User>(p => p.LowercaseUsername),
                    Roles = Helper.GetElementNameFor<User>(p => p.Roles)
                };

            ElementNames = names;


            // ensure indexes

            // MongoDB automatically indexes the _id field
            this.UserCollection.EnsureIndex(ElementNames.LowercaseUsername);
            this.UserCollection.EnsureIndex(ElementNames.Roles);
        }

        


        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref usernames, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, USER_NAMES);
            SecUtility.CheckArrayParameter(ref roleNames, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, ROLE_NAMES);

            // ensure lowercase
            var roles = roleNames.Select(role => role.ToLowerInvariant()).ToList();

            var users = usernames.Select(username => username.ToLowerInvariant()).ToList();


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
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, ROLE_NAME);

            var doc = new BsonDocument();
            doc.Set(DOCUMENT_ID_NAME, roleName.ToLowerInvariant());

            
            var result = RoleCollection.Save(doc, WriteConcern.Acknowledged);

            if (!result.Ok)
            {
                throw new ProviderException(String.Format("Could not create role '{0}'. Reason: {1}", roleName, result.LastErrorMessage));
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, ROLE_NAME);

            var rolePopulated = UserCollection.AsQueryable().Any(u => u.Roles.Contains(roleName.ToLowerInvariant()));
            if (throwOnPopulatedRole && rolePopulated)
            {
                throw new ProviderException(Resources.Role_is_not_empty);
            }

            var result = RoleCollection.Remove(Query.EQ(DOCUMENT_ID_NAME, roleName.ToLowerInvariant()), WriteConcern.Acknowledged);
            return result.Ok;
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            SecUtility.CheckParameter(ref roleName, true, true, null, MAX_ROLE_LENGTH, ROLE_NAME);

            if (String.IsNullOrWhiteSpace(usernameToMatch)){
                return new string[0];
            }

            var username = ElementNames.LowercaseUsername;
            var userQuery = Helper.FindQuery(usernameToMatch.ToLowerInvariant(), username);
            var query = Query.And(
                Query.EQ(ElementNames.Roles, roleName.ToLowerInvariant()),
                userQuery
                );
            var cursor = UserCollection.FindAs<BsonDocument>(query);

            // only want the usernames
            cursor.SetFields(Fields.Include(username).Exclude(DOCUMENT_ID_NAME));

            return cursor.Select(doc => doc[username].AsString).ToArray();
        }


        public override string[] GetAllRoles()
        {
            return Roles.ToArray();
        }

        public override string[] GetRolesForUser(string username)
        {
            SecUtility.CheckParameter(ref username, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, USER_NAME);

            var roles = UserCollection.AsQueryable()
                .Where(u => u.LowercaseUsername == username.ToLowerInvariant())
                .Select(u => u.Roles.ToArray()).FirstOrDefault();

            return roles;
        }

        public override string[] GetUsersInRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, ROLE_NAME);

            var usernames = UserCollection.AsQueryable()
                .Where(u => u.Roles.Contains(roleName.ToLowerInvariant()))
                .Select(u => u.Username).ToArray();

            return usernames;
        }

        public override bool IsUserInRole(string username, string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, null, MAX_ROLE_LENGTH, ROLE_NAME);

            var found = UserCollection.AsQueryable().Any(u => u.LowercaseUsername == username.ToLowerInvariant() &&
                                                               u.Roles.Contains(roleName.ToLowerInvariant()));
            return found;
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref usernames, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, USER_NAMES);
            SecUtility.CheckArrayParameter(ref roleNames, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, ROLE_NAMES);

            // update all users' roles
            var roles = roleNames.Select(role => role.ToLowerInvariant()).ToList();
            var users = usernames.Select(username => username.ToLowerInvariant()).ToList();

            var query = Query.In(ElementNames.LowercaseUsername, new BsonArray(users.ToArray()));

            var update = Update.PullAllWrapped<string>(ElementNames.Roles, roles);

            var result = Database.GetCollection<User>(_userCollectionName).Update(query, update, UpdateFlags.Multi, SafeMode.True);

            if (result.HasLastErrorMessage)
            {
                throw new ProviderException(result.LastErrorMessage);
            }
        }

        public override bool RoleExists(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, null, MAX_ROLE_LENGTH, ROLE_NAME);
            return Roles.Contains(roleName.ToLowerInvariant());
        }


        #endregion


    }
}
