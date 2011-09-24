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
    /// Role Provider Conventions:
    ///   Role Collection Name:
    ///     If 'roleCollectionName' is not specified, it will default to 'roles-{appname}'
    ///       where {appname} is the ApplicationName.  If ApplicationName is later changed, 
    ///       the referenced roleCollectionName will also be updated (but only if it was 
    ///       not manually specified).
    ///
    ///     Role Collection documents consist only of and Id which is the roleName.
    ///       Ex: { _id:"Admin" }
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

        public string DefaultCollectionName
        {
            get
            {
                return GenerateCollectionName(_applicationName, DEFAULT_ROLE_COLLECTION_SUFFIX);
            }
        }

        public string GenerateCollectionName (string application, string collection)
        {
            if (String.IsNullOrWhiteSpace(application))
                return collection;

            if (application.EndsWith("/"))
                return application + collection;
            else
                return application + "/" + collection;
        }
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
                if (_defaultRoleCollection)
                {
                    _roleCollectionName = DefaultCollectionName;
                }
                if (_defaultUserCollection)
                {
                    _userCollectionName = GenerateCollectionName(_applicationName, DEFAULT_USER_COLLECTION_SUFFIX);
                    _users = null;  // so it will get refreshed with new collection name
                }
            }
        }

        #endregion


        #region Protected Properties/Fields

        protected string _connectionString;
        protected MachineKeySection _machineKey;
        protected string _databaseName;
        protected string _userCollectionName;
        protected string _roleCollectionName;

        protected MongoServer _server;
        protected MongoDatabase _db;

        protected string _applicationName;
        protected string _invalidUsernameCharacters;
        protected string _invalidRoleCharacters;
        protected bool _defaultRoleCollection;
        protected bool _defaultUserCollection;


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


        protected IQueryable<User> _users;

        /// <summary>
        /// A IQueryable list of Users for this Application (User.ApplicationName == this.ApplicationName)
        /// </summary>
        protected IQueryable<User> Users
        {
            get
            {
                if (null == _users)
                {
                    _users = _db.GetCollection<User>(_userCollectionName).AsQueryable();
                }

                return _users;
            }
        }


        /// <summary>
        /// The list of Roles for this Application
        /// </summary>
        protected IEnumerable<string> Roles 
        {
            get
            {
                // Loading of the users collection is delayed until the collection is actually accessed
                var docs = _db.GetCollection(_roleCollectionName).FindAll();
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


            _applicationName = GetConfigValue(config["applicationName"], System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath);
            _invalidUsernameCharacters = GetConfigValue(config["invalidUsernameCharacters"], DEFAULT_INVALID_CHARACTERS);
            _invalidRoleCharacters = GetConfigValue(config["invalidRoleCharacters"], DEFAULT_INVALID_CHARACTERS);
            _databaseName = GetConfigValue(config["databaseName"], DEFAULT_DATABASE_NAME);
            _userCollectionName = GetConfigValue(config["userCollectionName"], GenerateCollectionName(_applicationName, DEFAULT_USER_COLLECTION_SUFFIX));
            _roleCollectionName = GetConfigValue(config["roleCollectionName"], DefaultCollectionName);

            // set default collection flag
            _defaultRoleCollection = !config.AllKeys.Contains("roleCollectionName");
            _defaultUserCollection = !config.AllKeys.Contains("userCollectionName");


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
            config.Remove("roleCollectionName");
            config.Remove("userCollectionName");

            if (config.Count > 0)
            {
                string key = config.GetKey(0);
                if (!String.IsNullOrEmpty(key))
                    throw new ProviderException(String.Format(Resources.Provider_unrecognized_attribute, key));
            }


            //RoleClassMap.Register();

            // Initialize MongoDB Server
            _server = MongoServer.Create(_connectionString);
            _db = _server.GetDatabase(_databaseName);

        }
        

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref usernames, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, "usernames");

            // Roles are checked in CreateRole
            //SecUtility.CheckArrayParameter(ref roleNames, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleNames");


            // first add any non-existant roles to roles collection
            
            // a) pull all roles, filter out existing, push new
            //    ...or 
            // b) save all passed in roles 

            foreach (var role in roleNames)
            {
                CreateRole(role);
            }


            // now update all users' roles

            // http://www.pastie.org/2225343

            var query = Query.In("uname", new BsonArray(usernames));

            var update = Update.AddToSetEachWrapped<string>("roles", roleNames);

            var result = _db.GetCollection<User>(_userCollectionName).Update(query, update, UpdateFlags.Multi, SafeMode.True);
            if (result.HasLastErrorMessage)
            {
                throw new ProviderException(result.LastErrorMessage);
            }
        }

        public override void CreateRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleName");

            var doc = new BsonDocument();
            doc.SetDocumentId(roleName);
            var result = _db.GetCollection(_roleCollectionName).Save(doc, SafeMode.True);
            if (!result.Ok)
            {
                throw new ProviderException(String.Format("Could not create role '{0}'. Reason: {1}", roleName, result.LastErrorMessage));
            }
        }

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleName");

            var rolePopulated = Users.Where(u => u.Roles.Contains(roleName)).Any();
            if (throwOnPopulatedRole && rolePopulated)
            {
                throw new ProviderException(Resources.Role_is_not_empty);
            }

            var result = _db.GetCollection<string>(_roleCollectionName).Remove(Query.EQ("_id", roleName), SafeMode.True);
            return result.Ok;
        }

        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            if (String.IsNullOrWhiteSpace(usernameToMatch)){
                return new string[0];
            }

            var map = BsonClassMap.LookupClassMap(typeof(User));
            var elementName = map.GetMemberMap("LowercaseUsername").ElementName;
            var rolesName = map.GetMemberMap("Roles").ElementName;
            QueryComplete userQuery = MakeQuery(usernameToMatch.ToLowerInvariant(), elementName);
            var query = Query.And(
                Query.EQ(rolesName, roleName),
                userQuery
                );
            var cursor = _db.GetCollection(_userCollectionName).Find(query);

            // only want the usernames
            cursor.SetFields(Fields.Include(elementName).Exclude("_id"));

            var names = new List<string>();
            foreach (var doc in cursor)
            {
                var str = doc[elementName].AsString;
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

            string[] roles = Users.Where(u => u.LowercaseUsername == username.ToLowerInvariant()).Select(u => u.Roles.ToArray()).FirstOrDefault();

            return roles;
        }

        public override string[] GetUsersInRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleName");

            var usernames = Users.Where(u => u.Roles.Contains(roleName)).Select(u => u.Username).ToArray();

            return usernames;
        }

        public override bool IsUserInRole(string username, string roleName)
        {
			SecUtility.CheckParameter(ref roleName, true, true, null, MAX_ROLE_LENGTH, "roleName");

            var found = Users.Where(u => u.LowercaseUsername == username.ToLowerInvariant() &&
                                         u.Roles.Contains(roleName) ).Any();
            return found;
        }

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref usernames, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, "usernames");
            SecUtility.CheckArrayParameter(ref roleNames, true, true, InvalidRoleCharacters, MAX_ROLE_LENGTH, "roleNames");

            // update all users' roles

            var query = Query.In("uname", new BsonArray(usernames));

            var update = Update.PullAllWrapped<string>("roles", roleNames);

            var result = _db.GetCollection<User>(_userCollectionName).Update(query, update, UpdateFlags.Multi, SafeMode.True);
            if (result.HasLastErrorMessage)
            {
                throw new ProviderException(result.LastErrorMessage);
            }

        }

        public override bool RoleExists(string roleName)
        {
            return Roles.Contains(roleName);
        }


        #endregion


        #region Protected Methods

        protected T GetConfigValue<T>(string configValue, T defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
                return defaultValue;

            return ((T)Convert.ChangeType(configValue, typeof(T)));
        }


        protected QueryComplete MakeQuery(string strToMatch, string elementName)
        {
            if (String.IsNullOrWhiteSpace(strToMatch))
                throw new ArgumentException("strToMatch can not be empty", "strToMatch");

            var startsWith = strToMatch.StartsWith("%");
            var endsWith = strToMatch.EndsWith("%");

            // check for "%" and "%%" cases
            if ((startsWith && 1 == strToMatch.Length) ||
                (startsWith && endsWith && 2 == strToMatch.Length)) {
                throw new ArgumentException("strToMatch must contain at least one character other than '%'", "strToMatch");
            }

            // strip leading and trailing percent
            if (startsWith) {
                strToMatch = strToMatch.Substring(1);
            }
            if (endsWith) {
                strToMatch = strToMatch.Substring(0, strToMatch.Length - 1);
            }

            var value = Regex.Escape(strToMatch);
            
            if (startsWith && endsWith)
            {
                // %mit% 
                return Query.Matches(elementName, new BsonRegularExpression(value));
            }
            else if (startsWith) {
                // "%ith"
                return Query.Matches(elementName, new BsonRegularExpression(string.Format("{0}$", value)));
            }
            else if (endsWith)
            {
                // "smi%"
                return Query.Matches(elementName, new BsonRegularExpression(string.Format("^{0}", value)));
            }
            else
            {
                return Query.EQ(elementName, strToMatch);
            }
        }

        #endregion

    }
}
