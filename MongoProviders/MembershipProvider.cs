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
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Configuration;
using System.Web.Hosting;
using System.Web.Security;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using MongoDB.Driver.Linq;

namespace MongoProviders
{
    /// <summary>
    ///     ASP.NET Membership Provider that uses MongoDB
    ///     Non-standard configuration attributes:
    ///     invalidUsernameCharacters - characters that are illegal in Usernames.  Default: ",%"
    ///     Ex: invalidUsernameCharacters=",%&"
    ///     Note: the percent character, "%", should generally always be illegal since it is used in the FindUsersBy*
    ///     methods to indicate a wildcard.  This matches the behavior of the SQL Membership provider in supporting
    ///     basic SQL Like syntax, although only the "%" is supported (not "_" or "[]")
    ///     invalidEmailCharacters - characters that are illegal in Email addresses.  Default: ",%"
    ///     Ex: invalidEmailCharacters=",!%*"
    ///     Note: the percent character, "%", should generally always be illegal since it is used in the FindUsersBy*
    ///     methods to indicate a wildcard.  This matches the behavior of the SQL Membership provider in supporting
    ///     basic SQL Like syntax, although only the "%" is supported (not "_" or "[]")
    ///     writeExceptionsToEventLog - boolean indicating whether database exceptions should be
    ///     written to the EventLog rather than returned to UI.  Default: "true"
    ///     Ex: writeExceptionsToEventLog="false"
    ///     collectionSuffix - suffix of the collection to use for Membership User data.  Default: "users"
    ///     Ex: collectionSuffix="users"
    ///     Note: the actual collection name used will be the combination of the ApplicationName and the CollectionSuffix.
    ///     For example, if the ApplicationName is "/", then the default Collection name will be "/users".
    ///     This relieves us from having to include the ApplicationName in every query and also saves space in two ways:
    ///     1. ApplicationName does not need to be stored with the User data
    ///     2. Indexes no longer need to be composite. ie. "LowercaseUsername" rather than "ApplicationName",
    ///     "LowercaseUsername"
    /// </summary>
    public class MembershipProvider : System.Web.Security.MembershipProvider
    {
        #region Custom Public Properties

        public const string DEFAULT_NAME = "MongoMembershipProvider";
        public const string DEFAULT_DATABASE_NAME = "test";
        public const string DEFAULT_USER_COLLECTION_SUFFIX = "users";
        public const string DEFAULT_INVALID_CHARACTERS = ",%";
        public const int NEW_PASSWORD_LENGTH = 8;
        public const int MAX_USERNAME_LENGTH = 256;
        public const int MAX_PASSWORD_LENGTH = 128;
        public const int MAX_PASSWORD_ANSWER_LENGTH = 128;
        public const int MAX_EMAIL_LENGTH = 256;
        public const int MAX_PASSWORD_QUESTION_LENGTH = 256;

        public struct MembershipElements
        {
            public string LowercaseUsername;
            public string LowercaseEmail;
            public string LastActivityDate;
        }

        public MembershipElements ElementNames { get; protected set; }

        //
        // If false, exceptions are thrown to the caller. If true,
        // exceptions are written to the event log.
        //
        public bool WriteExceptionsToEventLog { get; set; }

        public string InvalidUsernameCharacters { get; protected set; }
        public string InvalidEmailCharacters { get; protected set; }
        public string CollectionName { get; protected set; }
        public IMongoCollection<User> Collection { get; protected set; }
        public IMongoDatabase Database { get; protected set; }

        #endregion

        #region Protected Properties

        protected string _connectionString;
        protected MachineKeySection _machineKey;
        protected string _collectionSuffix;

        protected int _newPasswordLength = 8;
        protected string _eventSource = DEFAULT_NAME;
        protected string _eventLog = "Application";
        protected string _exceptionMessage = Resources.ProviderException;

        #endregion

        #region MembershipProvider properties

        // System.Web.Security.MembershipProvider properties.

        protected string _applicationName;
        protected bool _enablePasswordReset;
        protected bool _enablePasswordRetrieval;
        protected bool _requiresQuestionAndAnswer;
        protected bool _requiresUniqueEmail;
        protected int _maxInvalidPasswordAttempts;
        protected int _passwordAttemptWindow;
        protected MembershipPasswordFormat _passwordFormat;
        protected int _minRequiredNonAlphanumericCharacters;
        protected int _minRequiredPasswordLength;
        protected string _passwordStrengthRegularExpression;

        /// <summary>
        ///     The name of the application using the custom membership provider.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     The name of the application using the custom membership provider.
        /// </returns>
        public override string ApplicationName
        {
            get => _applicationName;
            set
            {
                _applicationName = value;
                CollectionName = Helper.GenerateCollectionName(_applicationName, _collectionSuffix);
                Collection = Database.GetCollection<User>(CollectionName);
            }
        }

        /// <summary>
        ///     Indicates whether the membership provider is configured to allow users to reset their passwords.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     true if the membership provider supports password reset; otherwise, false. The default is true.
        /// </returns>
        public override bool EnablePasswordReset => _enablePasswordReset;

        /// <summary>
        ///     Indicates whether the membership provider is configured to allow users to retrieve their passwords.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     true if the membership provider is configured to support password retrieval; otherwise, false. The default is
        ///     false.
        /// </returns>
        public override bool EnablePasswordRetrieval => _enablePasswordRetrieval;

        /// <summary>
        ///     Gets a value indicating whether the membership provider is configured to require the user to answer a password
        ///     question for password reset and retrieval.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     true if a password answer is required for password reset and retrieval; otherwise, false. The default is true.
        /// </returns>
        public override bool RequiresQuestionAndAnswer => _requiresQuestionAndAnswer;

        /// <summary>
        ///     Gets a value indicating whether the membership provider is configured to require a unique e-mail address for each
        ///     user name.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     true if the membership provider requires a unique e-mail address; otherwise, false. The default is true.
        /// </returns>
        public override bool RequiresUniqueEmail => _requiresUniqueEmail;

        /// <summary>
        ///     Gets the number of invalid password or password-answer attempts allowed before the membership user is locked out.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     The number of invalid password or password-answer attempts allowed before the membership user is locked out.
        /// </returns>
        public override int MaxInvalidPasswordAttempts => _maxInvalidPasswordAttempts;

        /// <summary>
        ///     Gets the number of minutes in which a maximum number of invalid password or password-answer attempts are allowed
        ///     before the membership user is locked out.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     The number of minutes in which a maximum number of invalid password or password-answer attempts are allowed before
        ///     the membership user is locked out.
        /// </returns>
        public override int PasswordAttemptWindow => _passwordAttemptWindow;

        /// <summary>
        ///     Gets a value indicating the format for storing passwords in the membership data store.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     One of the <see cref="T:System.Web.Security.MembershipPasswordFormat" /> values indicating the format for storing
        ///     passwords in the data store.
        /// </returns>
        public override MembershipPasswordFormat PasswordFormat => _passwordFormat;

        /// <summary>
        ///     Gets the minimum number of special characters that must be present in a valid password.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     The minimum number of special characters that must be present in a valid password.
        /// </returns>
        public override int MinRequiredNonAlphanumericCharacters => _minRequiredNonAlphanumericCharacters;

        /// <summary>
        ///     Gets the minimum length required for a password.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     The minimum length required for a password.
        /// </returns>
        public override int MinRequiredPasswordLength => _minRequiredPasswordLength;

        /// <summary>
        ///     Gets the regular expression used to evaluate a password.
        /// </summary>
        /// <value></value>
        /// <returns>
        ///     A regular expression used to evaluate a password.
        /// </returns>
        public override string PasswordStrengthRegularExpression => _passwordStrengthRegularExpression;

        #endregion

        #region Public Methods

        /// <summary>
        ///     Initializes the provider.
        /// </summary>
        /// <param name="name">The friendly name of the provider.</param>
        /// <param name="config">
        ///     A collection of the name/value pairs representing the provider-specific attributes specified in
        ///     the configuration for this provider.
        /// </param>
        /// <exception cref="T:System.ArgumentNullException">
        ///     The config collection provided is null.
        /// </exception>
        /// <exception cref="T:System.InvalidOperationException">
        ///     An attempt is made to call
        ///     <see
        ///         cref="M:System.Configuration.Provider.ProviderBase.Initialize(System.String,System.Collections.Specialized.NameValueCollection)" />
        ///     on a provider after the provider has already been initialized.
        /// </exception>
        /// <exception cref="T:System.Configuration.Provider.ProviderException">
        /// </exception>
        public override void Initialize(string name, NameValueCollection config)
        {
            if (null == config)
                throw new ArgumentNullException("config");

            if (string.IsNullOrWhiteSpace(name))
                name = DEFAULT_NAME;

            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", Resources.MembershipProvider_description);
            }

            base.Initialize(name, config);

            // get config values

            _applicationName = config["applicationName"] ?? HostingEnvironment.ApplicationVirtualPath;
            _maxInvalidPasswordAttempts = Helper.GetConfigValue(config["maxInvalidPasswordAttempts"], 5);
            _passwordAttemptWindow = Helper.GetConfigValue(config["passwordAttemptWindow"], 10);
            _minRequiredNonAlphanumericCharacters = Helper.GetConfigValue(config["minRequiredNonAlphanumericCharacters"], 1);
            _minRequiredPasswordLength = Helper.GetConfigValue(config["minRequiredPasswordLength"], 7);
            _passwordStrengthRegularExpression = Helper.GetConfigValue(config["passwordStrengthRegularExpression"], "");
            _enablePasswordReset = Helper.GetConfigValue(config["enablePasswordReset"], true);
            _enablePasswordRetrieval = Helper.GetConfigValue(config["enablePasswordRetrieval"], false);
            _requiresQuestionAndAnswer = Helper.GetConfigValue(config["requiresQuestionAndAnswer"], false);
            _requiresUniqueEmail = Helper.GetConfigValue(config["requiresUniqueEmail"], true);
            InvalidUsernameCharacters = Helper.GetConfigValue(config["invalidUsernameCharacters"], DEFAULT_INVALID_CHARACTERS);
            InvalidEmailCharacters = Helper.GetConfigValue(config["invalidEmailCharacters"], DEFAULT_INVALID_CHARACTERS);
            WriteExceptionsToEventLog = Helper.GetConfigValue(config["writeExceptionsToEventLog"], true);
            _collectionSuffix = Helper.GetConfigValue(config["collectionSuffix"], DEFAULT_USER_COLLECTION_SUFFIX);

            ValidatePwdStrengthRegularExpression();

            if (_minRequiredNonAlphanumericCharacters > _minRequiredPasswordLength)
                throw new ProviderException(Resources.MinRequiredNonalphanumericCharacters_can_not_be_more_than_MinRequiredPasswordLength);

            string tempFormat = config["passwordFormat"] ?? "Hashed";

            switch (tempFormat.ToLowerInvariant())
            {
                case "hashed":
                    _passwordFormat = MembershipPasswordFormat.Hashed;
                    break;
                case "encrypted":
                    _passwordFormat = MembershipPasswordFormat.Encrypted;
                    break;
                case "clear":
                    _passwordFormat = MembershipPasswordFormat.Clear;
                    break;
                default:
                    throw new ProviderException(Resources.Provider_bad_password_format);
            }

            if (PasswordFormat == MembershipPasswordFormat.Hashed && EnablePasswordRetrieval)
            {
                throw new ProviderException(Resources.Provider_can_not_retrieve_hashed_password);
            }

            // Initialize Connection String
            string temp = config["connectionStringName"];
            if (string.IsNullOrWhiteSpace(temp))
                throw new ProviderException(Resources.Connection_name_not_specified);

            ConnectionStringSettings connectionStringSettings = ConfigurationManager.ConnectionStrings[temp];
            if (null == connectionStringSettings || string.IsNullOrWhiteSpace(connectionStringSettings.ConnectionString))
                throw new ProviderException(string.Format(Resources.Connection_string_not_found, temp));

            _connectionString = connectionStringSettings.ConnectionString;

            // Check for invalid parameters in the config

            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("applicationName");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("commandTimeout");
            config.Remove("passwordFormat");
            config.Remove("name");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonAlphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            config.Remove("writeExceptionsToEventLog");
            config.Remove("invalidUsernameCharacters");
            config.Remove("invalidEmailCharacters");
            config.Remove("collectionSuffix");

            if (config.Count > 0)
            {
                string key = config.GetKey(0);
                if (!string.IsNullOrEmpty(key))
                {
                    throw new ProviderException(string.Format(Resources.Provider_unrecognized_attribute, key));
                }
            }

            // Get encryption and decryption key information from the configuration.
            Configuration cfg =
                WebConfigurationManager.OpenWebConfiguration(HostingEnvironment.ApplicationVirtualPath);
            _machineKey = (MachineKeySection)ConfigurationManager.GetSection("system.web/machineKey");

            if (_machineKey.ValidationKey.Contains("AutoGenerate"))
                if (PasswordFormat != MembershipPasswordFormat.Clear)
                    throw new ProviderException(Resources.Provider_can_not_autogenerate_machine_key_with_encrypted_or_hashed_password_format);

            // Initialize MongoDB Server
            Database = ClientMongo.GetMongoConnection(_connectionString);
            CollectionName = Helper.GenerateCollectionName(_applicationName, _collectionSuffix);
            Collection = Database.GetCollection<User>(CollectionName);

            // store element names

            var names = new MembershipElements
            {
                LowercaseUsername = Helper.GetElementNameFor<User>(p => p.LowercaseUsername),
                LastActivityDate = Helper.GetElementNameFor<User, DateTime>(p => p.LastActivityDate),
                LowercaseEmail = Helper.GetElementNameFor<User>(p => p.LowercaseEmail)
            };
            ElementNames = names;

            // ensure indexes

            Collection.Indexes.CreateOne(Builders<User>.IndexKeys.Ascending(u => u.LowercaseUsername), new CreateIndexOptions { Unique = true });
            Collection.Indexes.CreateOne(Builders<User>.IndexKeys.Ascending(u => u.LowercaseEmail), new CreateIndexOptions { Unique = true });
            Collection.Indexes.CreateOne(Builders<User>.IndexKeys.Ascending(u => u.Roles));
        }

        /// <summary>
        ///     Processes a request to update the password for a membership user.
        /// </summary>
        /// <param name="username">The user to update the password for.</param>
        /// <param name="oldPassword">The current password for the specified user.</param>
        /// <param name="newPassword">The new password for the specified user.</param>
        /// <returns>
        ///     true if the password was updated successfully; otherwise, false.
        /// </returns>
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            SecUtility.CheckParameter(ref username, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, "username");
            SecUtility.CheckParameter(ref oldPassword, true, true, null, MAX_PASSWORD_LENGTH, "oldPassword");
            SecUtility.CheckParameter(ref newPassword, true, true, null, MAX_PASSWORD_LENGTH, "newPassword");

            User user = GetUserByName(username, "ChangePassword");
            if (!CheckPassword(user, oldPassword, true))
                return false;

            if (newPassword.Length < MinRequiredPasswordLength)
            {
                throw new ArgumentException(
                    string.Format(
                        CultureInfo.CurrentCulture,
                        Resources.Password_too_short,
                        "newPassword",
                        MinRequiredPasswordLength),
                    "newPassword");
            }

            if (MinRequiredNonAlphanumericCharacters > 0)
            {
                var numNonAlphaNumericChars = 0;
                for (var i = 0; i < newPassword.Length; i++)
                {
                    if (!char.IsLetterOrDigit(newPassword, i))
                    {
                        numNonAlphaNumericChars++;
                    }
                }
                if (numNonAlphaNumericChars < MinRequiredNonAlphanumericCharacters)
                {
                    throw new ArgumentException(
                        string.Format(
                            CultureInfo.CurrentCulture,
                            Resources.Password_need_more_non_alpha_numeric_chars,
                            "newPassword",
                            MinRequiredNonAlphanumericCharacters),
                        "newPassword");
                }
            }

            if (PasswordStrengthRegularExpression.Length > 0 && !Regex.IsMatch(newPassword, PasswordStrengthRegularExpression))
            {
                throw new ArgumentException(
                    string.Format(
                        CultureInfo.CurrentCulture,
                        Resources.Password_does_not_match_regular_expression,
                        "newPassword"),
                    "newPassword");
            }

            // Raise event to let others check new username/password

            var args = new ValidatePasswordEventArgs(username, newPassword, false);
            OnValidatingPassword(args);
            if (args.Cancel)
            {
                if (args.FailureInformation != null)
                    throw args.FailureInformation;
                throw new MembershipPasswordException(Resources.Membership_Custom_Password_Validation_Failure);
            }

            // Save new password

            string encodedPwd = EncodePassword(newPassword, PasswordFormat, user.PasswordSalt);

            user.Password = encodedPwd;
            user.PasswordFormat = PasswordFormat;
            user.LastPasswordChangedDate = DateTime.UtcNow;

            string msg = string.Format("Unable to save new password for user '{0}'", username);
            Save(user, msg, "ChangePassword");

            return true;
        }

        /// <summary>
        ///     Processes a request to update the password question and answer for a membership user.
        /// </summary>
        /// <param name="username">The user to change the password question and answer for.</param>
        /// <param name="password">The password for the specified user.</param>
        /// <param name="newPasswordQuestion">The new password question for the specified user.</param>
        /// <param name="newPasswordAnswer">The new password answer for the specified user.</param>
        /// <returns>
        ///     true if the password question and answer are updated successfully; otherwise, false.
        /// </returns>
        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            SecUtility.CheckParameter(ref username, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH, "username");
            SecUtility.CheckParameter(ref password, true, true, null, MAX_PASSWORD_LENGTH, "password");

            User user = GetUserByName(username, "ChangePasswordQuestionAndAnswer");
            if (!CheckPassword(user, password, true))
                return false;

            SecUtility.CheckParameter(ref newPasswordQuestion, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, null, MAX_PASSWORD_QUESTION_LENGTH, "newPasswordQuestion");
            if (newPasswordAnswer != null)
            {
                newPasswordAnswer = newPasswordAnswer.Trim();
            }

            SecUtility.CheckParameter(ref newPasswordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, null, MAX_PASSWORD_ANSWER_LENGTH, "newPasswordAnswer");
            string encodedPasswordAnswer = null;
            if (!string.IsNullOrEmpty(newPasswordAnswer))
            {
                encodedPasswordAnswer = EncodePassword(newPasswordAnswer.ToLowerInvariant(), user.PasswordFormat, user.PasswordSalt);
            }
            //SecUtility.CheckParameter(ref encodedPasswordAnswer, this.RequiresQuestionAndAnswer, this.RequiresQuestionAndAnswer, false, MAX_PASSWORD_ANSWER_LENGTH, "newPasswordAnswer");

            user.PasswordQuestion = newPasswordQuestion;
            user.PasswordAnswer = encodedPasswordAnswer;

            string msg = string.Format("Unable to save new password question and answer for user '{0}'", username);
            Save(user, msg, "ChangePasswordQuestionAndAnswer");

            return true;
        }

        /// <summary>
        ///     Adds a new membership user to the data source.
        /// </summary>
        /// <param name="username">The user name for the new user.</param>
        /// <param name="password">The password for the new user.</param>
        /// <param name="email">The e-mail address for the new user.</param>
        /// <param name="passwordQuestion">The password question for the new user.</param>
        /// <param name="passwordAnswer">The password answer for the new user</param>
        /// <param name="isApproved">Whether or not the new user is approved to be validated.</param>
        /// <param name="providerUserKey">The unique identifier from the membership data source for the user.</param>
        /// <param name="status">
        ///     A <see cref="T:System.Web.Security.MembershipCreateStatus" /> enumeration value indicating whether
        ///     the user was created successfully.
        /// </param>
        /// <returns>
        ///     A <see cref="T:System.Web.Security.MembershipUser" /> object populated with the information for the newly created
        ///     user.
        /// </returns>
        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            #region Validation

            if (!SecUtility.ValidateParameter(ref username, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref email, RequiresUniqueEmail, RequiresUniqueEmail, InvalidEmailCharacters, MAX_EMAIL_LENGTH))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref password, true, true, null, MAX_PASSWORD_LENGTH))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (password.Length > MAX_PASSWORD_LENGTH)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (null != passwordAnswer)
            {
                passwordAnswer = passwordAnswer.Trim();
            }

            if (string.IsNullOrEmpty(passwordAnswer))
            {
                if (RequiresQuestionAndAnswer)
                {
                    status = MembershipCreateStatus.InvalidAnswer;
                    return null;
                }
            }
            else
            {
                if (passwordAnswer.Length > MAX_PASSWORD_ANSWER_LENGTH)
                {
                    status = MembershipCreateStatus.InvalidAnswer;
                    return null;
                }
            }

            if (!SecUtility.ValidateParameter(ref passwordQuestion, RequiresQuestionAndAnswer, true, null, MAX_PASSWORD_QUESTION_LENGTH))
            {
                status = MembershipCreateStatus.InvalidQuestion;
                return null;
            }

            if (null != providerUserKey && !(providerUserKey is Guid))
            {
                status = MembershipCreateStatus.InvalidProviderUserKey;
                return null;
            }

            if (password.Length < MinRequiredPasswordLength)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (MinRequiredNonAlphanumericCharacters > 0)
            {
                var numNonAlphaNumericChars = 0;
                for (var i = 0; i < password.Length; i++)
                {
                    if (!char.IsLetterOrDigit(password, i))
                    {
                        numNonAlphaNumericChars++;
                    }
                }

                if (numNonAlphaNumericChars < MinRequiredNonAlphanumericCharacters)
                {
                    status = MembershipCreateStatus.InvalidPassword;
                    return null;
                }
            }

            if (PasswordStrengthRegularExpression.Length > 0 && !Regex.IsMatch(password, PasswordStrengthRegularExpression))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            #endregion

            var args = new ValidatePasswordEventArgs(username, password, true);

            OnValidatingPassword(args);

            if (args.Cancel)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (RequiresUniqueEmail && !string.IsNullOrEmpty(GetUserNameByEmail(email)))
            {
                status = MembershipCreateStatus.DuplicateEmail;
                return null;
            }

            MembershipUser u = GetUser(username, false);
            if (null != u)
            {
                status = MembershipCreateStatus.DuplicateUserName;
                return null;
            }

            if (null == providerUserKey)
            {
                providerUserKey = Guid.NewGuid();
            }

            DateTime createAt = DateTime.UtcNow;
            string salt = GenerateSalt();

            string answer = passwordAnswer;
            if (null != answer)
            {
                answer = EncodePassword(passwordAnswer.ToLowerInvariant(), PasswordFormat, salt);
            }

            var user = new User
            {
                Id = (Guid)providerUserKey,
                Username = username,
                LowercaseUsername = username.ToLowerInvariant(),
                DisplayName = username,
                Email = email,
                LowercaseEmail = null == email ? null : email.ToLowerInvariant(),
                Password = EncodePassword(password, PasswordFormat, salt),
                PasswordQuestion = passwordQuestion,
                PasswordAnswer = answer,
                PasswordFormat = PasswordFormat,
                PasswordSalt = salt,
                IsApproved = isApproved,
                LastPasswordChangedDate = DateTime.MinValue,
                CreateDate = createAt,
                IsLockedOut = false,
                LastLockedOutDate = DateTime.MinValue,
                LastActivityDate = createAt,
                FailedPasswordAnswerAttemptCount = 0,
                FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue,
                FailedPasswordAttemptCount = 0,
                FailedPasswordAttemptWindowStart = DateTime.MinValue
            };

            string msg = string.Format("Error creating new User '{0}'", username);
            Save(user, msg, "CreateUser");

            status = MembershipCreateStatus.Success;
            return GetUser(username, false);
        }

        /// <summary>
        ///     Removes a user from the membership data source.
        /// </summary>
        /// <param name="username">The name of the user to delete.</param>
        /// <param name="deleteAllRelatedData">
        ///     true to delete data related to the user from the database; false to leave data
        ///     related to the user in the database.
        /// </param>
        /// <returns>
        ///     true if the user was successfully deleted; otherwise, false.
        /// </returns>
        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            if (string.IsNullOrWhiteSpace(username)) return false;

            FilterDefinition<User> query = Builders<User>.Filter.Eq(ElementNames.LowercaseUsername, username.ToLowerInvariant());
            DeleteResult result = Collection.DeleteOne(query);
            return result.IsAcknowledged;
        }

        /// <summary>
        ///     Gets a collection of membership users where the user name matches the specified string.
        /// </summary>
        /// <param name="usernameToMatch">
        ///     The user name to search for.
        ///     Match string may contain the standard SQL LIKE wildcard: %
        ///     "sm%"  -> StartsWith("sm")
        ///     "%ith" -> EndsWith("ith")
        ///     "%mit%" -> Contains("mit")
        /// </param>
        /// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex" /> is zero-based.</param>
        /// <param name="pageSize">The size of the page of results to return.</param>
        /// <param name="totalRecords">The total number of matched users.</param>
        /// <returns>
        ///     A <see cref="T:System.Web.Security.MembershipUserCollection" /> collection that contains a page of
        ///     <paramref name="pageSize" /><see cref="T:System.Web.Security.MembershipUser" /> objects beginning at the page
        ///     specified by <paramref name="pageIndex" />.
        /// </returns>
        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return FindUsersBy(ElementNames.LowercaseUsername, usernameToMatch, pageIndex, pageSize, out totalRecords);
        }

        /// <summary>
        ///     Gets a collection of membership users where the e-mail address matches the specified string.
        /// </summary>
        /// <param name="emailToMatch">
        ///     The e-mail address to search for.
        ///     Match string may contain the standard SQL LIKE wildcard: %
        ///     "sm%"  -> StartsWith("sm")
        ///     "%ith" -> EndsWith("ith")
        ///     "%mit%" -> Contains("mit")
        /// </param>
        /// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex" /> is zero-based.</param>
        /// <param name="pageSize">The size of the page of results to return.</param>
        /// <param name="totalRecords">The total number of matched users.</param>
        /// <returns>
        ///     A <see cref="T:System.Web.Security.MembershipUserCollection" /> collection that contains a page of
        ///     <paramref name="pageSize" /><see cref="T:System.Web.Security.MembershipUser" /> objects beginning at the page
        ///     specified by <paramref name="pageIndex" />.
        /// </returns>
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return FindUsersBy(ElementNames.LowercaseEmail, emailToMatch, pageIndex, pageSize, out totalRecords);
        }

        /// <summary>
        ///     Gets a collection of all the users in the data source in pages of data.
        /// </summary>
        /// <param name="pageIndex">The index of the page of results to return. <paramref name="pageIndex" /> is zero-based.</param>
        /// <param name="pageSize">The size of the page of results to return.</param>
        /// <param name="totalRecords">The total number of matched users.</param>
        /// <returns>
        ///     A <see cref="T:System.Web.Security.MembershipUserCollection" /> collection that contains a page of
        ///     <paramref name="pageSize" /><see cref="T:System.Web.Security.MembershipUser" /> objects beginning at the page
        ///     specified by <paramref name="pageIndex" />.
        /// </returns>
        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            var users = new MembershipUserCollection();
            List<User> matches = Collection.AsQueryable().Skip(pageIndex * pageSize)
                .Take(pageSize)
                .ToList();

            // execute second query to get total count
            totalRecords = (int)Collection.Count(Builders<User>.Filter.Empty);

            matches.ForEach(u => users.Add(ToMembershipUser(u)));

            return users;
        }

        /// <summary>
        ///     Gets the number of users currently accessing the application.
        /// </summary>
        /// <returns>
        ///     The number of users currently accessing the application.
        /// </returns>
        public override int GetNumberOfUsersOnline()
        {
            // http://msdn.microsoft.com/en-us/library/system.web.security.membership.userisonlinetimewindow.aspx

            var onlineSpan = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
            DateTime compareTime = DateTime.UtcNow.Subtract(onlineSpan);

            var count = 0;

            if (Collection != null)
            {
                count = Collection.AsQueryable().Count(u => u.LastActivityDate > compareTime);
            }

            return count;
        }

        /// <summary>
        ///     Gets the password for the specified user name from the data source.
        /// </summary>
        /// <param name="username">The user to retrieve the password for.</param>
        /// <param name="answer">The password answer for the user.</param>
        /// <returns>
        ///     The password for the specified user name.
        /// </returns>
        public override string GetPassword(string username, string answer)
        {
            if (!EnablePasswordRetrieval)
            {
                throw new ProviderException(Resources.Membership_PasswordRetrieval_not_supported);
            }

            User user = GetUserByName(username, "GetPassword");
            if (null == user)
            {
                throw new MembershipPasswordException(Resources.Membership_UserNotFound);
            }

            if (user.IsLockedOut)
            {
                throw new MembershipPasswordException(Resources.Membership_AccountLockOut);
            }

            if (RequiresQuestionAndAnswer && !ComparePasswords(answer, user.PasswordAnswer, user.PasswordSalt, user.PasswordFormat))
            {
                UpdateFailureCount(user, "passwordAnswer", false);

                throw new MembershipPasswordException(Resources.Membership_WrongAnswer);
            }

            string password = user.Password;
            if (user.PasswordFormat == MembershipPasswordFormat.Encrypted)
            {
                password = UnEncodePassword(password, user.PasswordFormat);
            }

            return password;
        }

        /// <summary>
        ///     Gets information from the data source for a user. Provides an option to update the last-activity date/time stamp
        ///     for the user.
        /// </summary>
        /// <param name="username">The name of the user to get information for.</param>
        /// <param name="userIsOnline">
        ///     true to update the last-activity date/time stamp for the user; false to return user
        ///     information without updating the last-activity date/time stamp for the user.
        /// </param>
        /// <returns>
        ///     A <see cref="T:System.Web.Security.MembershipUser" /> object populated with the specified user's information from
        ///     the data source.
        /// </returns>
        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            if (string.IsNullOrWhiteSpace(username)) return null;
            FilterDefinition<User> query = Builders<User>.Filter.Eq(ElementNames.LowercaseUsername, username.ToLowerInvariant());

            if (userIsOnline)
            {
                // update the last-activity date

                User result = UpdateLastActivityDate(query);
                return ToMembershipUser(result);
            }

            User user = Collection.FindSync(query).FirstOrDefault();
            return ToMembershipUser(user);
        }

        /// <summary>
        ///     Gets user information from the data source based on the unique identifier for the membership user. Provides an
        ///     option to update the last-activity date/time stamp for the user.
        /// </summary>
        /// <param name="providerUserKey">The unique identifier for the membership user to get information for.</param>
        /// <param name="userIsOnline">
        ///     true to update the last-activity date/time stamp for the user; false to return user
        ///     information without updating the last-activity date/time stamp for the user.
        /// </param>
        /// <returns>
        ///     A <see cref="T:System.Web.Security.MembershipUser" /> object populated with the specified user's information from
        ///     the data source.
        /// </returns>
        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            if (!(providerUserKey is Guid))
            {
                throw new ArgumentException(Resources.Membership_InvalidProviderUserKey, "providerUserKey");
            }

            FilterDefinition<User> query = Builders<User>.Filter.Eq("_id", (Guid)providerUserKey);
            if (userIsOnline)
            {
                // update the last-activity date
                User result = UpdateLastActivityDate(query);
                return ToMembershipUser(result);
            }

            User user = Collection.FindSync(query).First();
            return ToMembershipUser(user);
        }

        private User UpdateLastActivityDate(FilterDefinition<User> filter)
        {
            IMongoCollection<User> users = Collection;
            BsonClassMap map = BsonClassMap.LookupClassMap(typeof(User));
            UpdateDefinition<User> update = Builders<User>.Update.Set(ElementNames.LastActivityDate, DateTime.UtcNow);
            User result = users.FindOneAndUpdate(filter, update, new FindOneAndUpdateOptions<User> { ReturnDocument = ReturnDocument.After });
            if (result == null)
            {
                HandleDataExceptionAndThrow(new ProviderException("User is not found"), "GetUser");
            }

            return result;
        }

        /// <summary>
        ///     Gets the user name associated with the specified e-mail address.
        /// </summary>
        /// <param name="email">The e-mail address to search for.</param>
        /// <returns>
        ///     The user name associated with the specified e-mail address. If no match is found, return null.
        /// </returns>
        public override string GetUserNameByEmail(string email)
        {
            if (null == email)
                return null;

            string username = Collection.AsQueryable().Where(u => u.LowercaseEmail == email.ToLowerInvariant()).Select(u => u.Username).FirstOrDefault();
            return username;
        }

        /// <summary>
        ///     Resets a user's password to a new, automatically generated password.
        /// </summary>
        /// <param name="username">The user to reset the password for.</param>
        /// <param name="passwordAnswer">The password answer for the specified user.</param>
        /// <returns>The new password for the specified user.</returns>
        /// <exception cref="T:System.Configuration.Provider.ProviderException">
        ///     username is not found in the membership database.- or -The
        ///     change password action was canceled by a subscriber to the System.Web.Security.Membership.ValidatePassword
        ///     event and the <see cref="P:System.Web.Security.ValidatePasswordEventArgs.FailureInformation"></see> property was
        ///     null.- or -An
        ///     error occurred while retrieving the password from the database.
        /// </exception>
        /// <exception cref="T:System.NotSupportedException">
        ///     <see cref="P:System.Web.Security.SqlMembershipProvider.EnablePasswordReset"></see>
        ///     is set to false.
        /// </exception>
        /// <exception cref="T:System.ArgumentException">
        ///     username is an empty string (""), contains a comma, or is longer than 256 characters.
        ///     - or -passwordAnswer is an empty string or is longer than 128 characters and
        ///     <see cref="P:System.Web.Security.SqlMembershipProvider.RequiresQuestionAndAnswer"></see> is true.- or
        ///     -passwordAnswer is longer
        ///     than 128 characters after encoding.
        /// </exception>
        /// <exception cref="T:System.ArgumentNullException">
        ///     username is null.- or -passwordAnswer is null and
        ///     <see cref="P:System.Web.Security.SqlMembershipProvider.RequiresQuestionAndAnswer"></see> is true.
        /// </exception>
        /// <exception cref="T:System.Web.Security.MembershipPasswordException">
        ///     passwordAnswer is invalid. - or -The user account
        ///     is currently locked out.
        /// </exception>
        public override string ResetPassword(string username, string answer)
        {
            if (!EnablePasswordReset)
            {
                throw new NotSupportedException(Resources.Not_configured_to_support_password_resets);
            }

            User user = GetUserByName(username, "ResetPassword");
            if (null == user)
            {
                throw new ProviderException(Resources.Membership_UserNotFound);
            }
            if (user.IsLockedOut)
            {
                throw new ProviderException(Resources.Membership_AccountLockOut);
            }

            if (RequiresQuestionAndAnswer &&
                (null == answer || !ComparePasswords(answer, user.PasswordAnswer, user.PasswordSalt, user.PasswordFormat)))
            {
                UpdateFailureCount(user, "passwordAnswer", false);

                throw new MembershipPasswordException(Resources.Membership_InvalidAnswer);
            }

            string newPassword = Membership.GeneratePassword(NEW_PASSWORD_LENGTH, MinRequiredNonAlphanumericCharacters);

            var args =
                new ValidatePasswordEventArgs(username, newPassword, true);

            OnValidatingPassword(args);

            if (args.Cancel)
                if (args.FailureInformation != null)
                    throw args.FailureInformation;
                else
                    throw new MembershipPasswordException(Resources.Membership_Custom_Password_Validation_Failure);

            user.Password = EncodePassword(newPassword, user.PasswordFormat, user.PasswordSalt);
            user.LastPasswordChangedDate = DateTime.UtcNow;

            {
                string msg = string.Format("Error saving User '{0}' while resetting password", username);
                Save(user, msg, "ResetPassword");
            }

            return newPassword;
        }

        /// <summary>
        ///     Unlocks the user.
        /// </summary>
        /// <param name="username">The username.</param>
        /// <returns>Returns true if user was unlocked; otherwise returns false.</returns>
        public override bool UnlockUser(string username)
        {
            User user = GetUserByName(username, "UnlockUser");
            if (null == user)
            {
                return false;
            }

            user.IsLockedOut = false;
            user.LastLockedOutDate = DateTime.MinValue;
            user.FailedPasswordAnswerAttemptCount = 0;
            user.FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue;
            user.FailedPasswordAttemptCount = 0;
            user.FailedPasswordAttemptWindowStart = DateTime.MinValue;

            string msg = string.Format("Error saving User '{0}' while attempting to remove account lock", username);
            Save(user, msg, "UnlockUser");
            return true;
        }

        /// <summary>
        ///     Updates information about a user in the data source.
        /// </summary>
        /// <param name="user">
        ///     A <see cref="T:System.Web.Security.MembershipUser" /> object that represents the user to update and
        ///     the updated information for the user.
        /// </param>
        public override void UpdateUser(MembershipUser user)
        {
            User u = GetUserByName(user.UserName, "UpdateUser");
            if (null == user)
            {
                throw new ProviderException(Resources.Membership_UserNotFound);
            }

            u.Email = user.Email;
            u.Comment = user.Comment;
            u.IsApproved = user.IsApproved;
            u.LastLoginDate = user.LastLoginDate;
            u.LastActivityDate = user.LastActivityDate;

            {
                var msg = "Error saving user while attempting to update Email and IsApproved status";
                Save(u, msg, "UpdateUser");
            }
        }

        /// <summary>
        ///     Verifies that the specified user name and password exist in the data source.
        /// </summary>
        /// <param name="username">The name of the user to validate.</param>
        /// <param name="password">The password for the specified user.</param>
        /// <returns>
        ///     true if the specified username and password are valid; otherwise, false.
        /// </returns>
        public override bool ValidateUser(string username, string password)
        {
            if (!SecUtility.ValidateParameter(ref username, true, true, InvalidUsernameCharacters, MAX_USERNAME_LENGTH) || !SecUtility.ValidateParameter(ref password, true, true, null, MAX_PASSWORD_LENGTH))
            {
                return false;
            }

            User user = GetUserByName(username, "ValidateUser");
            if (null == user || user.IsLockedOut || !user.IsApproved)
            {
                return false;
            }

            bool passwordsMatch = ComparePasswords(password, user.Password, user.PasswordSalt, user.PasswordFormat);
            if (!passwordsMatch)
            {
                // update invalid try count
                UpdateFailureCount(user, "password", false);
                return false;
            }

            // User is authenticated. Update last activity and last login dates and failure counts.

            user.LastActivityDate = DateTime.UtcNow;
            user.LastLoginDate = DateTime.UtcNow;
            user.FailedPasswordAnswerAttemptCount = 0;
            user.FailedPasswordAttemptCount = 0;
            user.FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue;
            user.FailedPasswordAttemptWindowStart = DateTime.MinValue;

            string msg = string.Format("Error updating User '{0}'s last login date while validating", username);
            Save(user, msg, "ValidateUser");
            return true;
        }

        #endregion

        #region Protected Methods

        protected void ValidatePwdStrengthRegularExpression()
        {
            // Validate regular expression, if supplied.
            if (null == _passwordStrengthRegularExpression)
                _passwordStrengthRegularExpression = string.Empty;

            _passwordStrengthRegularExpression = _passwordStrengthRegularExpression.Trim();

            if (_passwordStrengthRegularExpression.Length <= 0)
                return;

            try
            {
                new Regex(_passwordStrengthRegularExpression);
            }
            catch (ArgumentException ex)
            {
                throw new ProviderException(ex.Message, ex);
            }
        }

        protected MembershipUser ToMembershipUser(User user)
        {
            if (null == user)
                return null;

            return new MembershipUser(
                Name,
                user.Username,
                user.Id,
                user.Email,
                user.PasswordQuestion,
                user.Comment,
                user.IsApproved,
                user.IsLockedOut,
                user.CreateDate,
                user.LastLoginDate,
                user.LastActivityDate,
                user.LastPasswordChangedDate,
                user.LastLockedOutDate
            );
        }

        protected static string GenerateSalt()
        {
            var data = new byte[0x10];
            new RNGCryptoServiceProvider().GetBytes(data);
            return Convert.ToBase64String(data);
        }

        /// <summary>
        ///     Convenience method that handles errors when retrieving a User
        /// </summary>
        /// <param name="username">The name of the user to retrieve</param>
        /// <param name="action">
        ///     The name of the action that attempted the retrieval. Used in case exceptions are raised and
        ///     written to EventLog
        /// </param>
        /// <returns></returns>
        protected User GetUserByName(string username, string action)
        {
            if (string.IsNullOrWhiteSpace(username))
            {
                return null;
            }

            User user = null;

            try
            {
                user = Collection.AsQueryable().SingleOrDefault(u => u.LowercaseUsername == username.ToLowerInvariant());
            }
            catch (Exception ex)
            {
                string msg = string.Format("Unable to retrieve User information for user '{0}'", username);
                HandleDataExceptionAndThrow(new ProviderException(msg, ex), action);
            }

            return user;
        }

        /// <summary>
        ///     Finds users that match the passed string.  Element name supports the use of % as a wildcard.
        /// </summary>
        /// <param name="elementName">The name of the element as it appears in the MongoDB collection</param>
        /// <param name="strToMatch">
        ///     The string to match.  Can start and/or end with a '%' to indicate endsWith or startsWith,
        ///     respectively.
        /// </param>
        /// <param name="pageIndex"></param>
        /// <param name="pageSize"></param>
        /// <param name="totalRecords"></param>
        /// <returns></returns>
        protected MembershipUserCollection FindUsersBy(string elementName, string strToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            var users = new MembershipUserCollection();
            if (string.IsNullOrWhiteSpace(strToMatch))
            {
                totalRecords = 0;
                return users;
            }

            IMongoQuery query = Helper.FindQuery(strToMatch, elementName);
            IFindFluent<User, User> cursor = Collection.Find(query.ToBsonDocument());
            cursor.Skip(pageIndex * pageSize);
            cursor.Limit(pageSize);

            foreach (User user in cursor.ToEnumerable())
            {
                users.Add(ToMembershipUser(user));
            }

            // execute second query to get total count
            totalRecords = (int)Collection.Find(query.ToBsonDocument()).Count();

            return users;
        }

        protected bool CheckPassword(User user, string password, bool failIfNotApproved)
        {
            if (null == user) return false;
            if (!user.IsApproved && failIfNotApproved) return false;

            string encodedPwdFromUser = EncodePassword(password, user.PasswordFormat, user.PasswordSalt);
            bool isAuthenticated = user.Password.Equals(encodedPwdFromUser);

            if (isAuthenticated && user.FailedPasswordAttemptCount == 0 && user.FailedPasswordAnswerAttemptCount == 0)
                return true;

            UpdateFailureCount(user, "password", isAuthenticated);

            return isAuthenticated;
        }

        /// <summary>
        ///     A helper method that performs the checks and updates associated User with password failure tracking
        /// </summary>
        /// <param name="username"></param>
        /// <param name="failureType"></param>
        /// <param name="isAuthenticated"></param>
        protected void UpdateFailureCount(User user, string failureType, bool isAuthenticated)
        {
            if (!(failureType == "password" || failureType == "passwordAnswer"))
            {
                throw new ArgumentException("Invalid value for failureType parameter. Must be 'password' or 'passwordAnswer'.", "failureType");
            }

            if (user.IsLockedOut)
                return; // Just exit without updating any fields if user is locked out

            if (isAuthenticated)
            {
                // User is valid, so make sure Attempt Counts and IsLockedOut fields have been reset
                if (user.FailedPasswordAttemptCount > 0 || user.FailedPasswordAnswerAttemptCount > 0)
                {
                    user.FailedPasswordAnswerAttemptCount = 0;
                    user.FailedPasswordAttemptCount = 0;
                    user.FailedPasswordAnswerAttemptWindowStart = DateTime.MinValue;
                    user.FailedPasswordAttemptWindowStart = DateTime.MinValue;
                    string msg = string.Format("Unable to reset Authenticated User's FailedPasswordAttemptCount property for user '{0}'", user.Username);
                    Save(user, msg, "UpdateFailureCount");
                }
                return;
            }

            // If we get here that means isAuthenticated = false, which means the user did not log on successfully.
            // Log the failure and possibly lock out the user if she exceeded the number of allowed attempts.

            DateTime windowStart = DateTime.MinValue;
            var failureCount = 0;

            switch (failureType)
            {
                case "password":
                    windowStart = user.FailedPasswordAttemptWindowStart;
                    failureCount = user.FailedPasswordAttemptCount;
                    break;
                case "passwordAnswer":
                    windowStart = user.FailedPasswordAnswerAttemptWindowStart;
                    failureCount = user.FailedPasswordAnswerAttemptCount;
                    break;
                default:
                    break;
            }

            DateTime windowEnd = windowStart.AddMinutes(PasswordAttemptWindow);

            if (failureCount == 0 || DateTime.UtcNow > windowEnd)
            {
                // First password failure or outside of PasswordAttemptWindow. 
                // Start a new password failure count from 1 and a new window starting now.

                switch (failureType)
                {
                    case "password":
                        user.FailedPasswordAttemptCount = 1;
                        user.FailedPasswordAttemptWindowStart = DateTime.UtcNow;
                        break;
                    case "passwordAnswer":
                        user.FailedPasswordAnswerAttemptCount = 1;
                        user.FailedPasswordAnswerAttemptWindowStart = DateTime.UtcNow;
                        break;
                }

                string msg = string.Format("Unable to update failure count and window start for user '{0}'", user.Username);
                Save(user, msg, "UpdateFailureCount");

                return;
            }

            // within PasswordAttemptWindow

            failureCount++;

            if (failureCount >= MaxInvalidPasswordAttempts)
            {
                // Password attempts have exceeded the failure threshold. Lock out the user.
                user.IsLockedOut = true;
                user.LastLockedOutDate = DateTime.UtcNow;
                user.FailedPasswordAttemptCount = failureCount;

                string msg = string.Format("Unable to lock out user '{0}'", user.Username);
                Save(user, msg, "UpdateFailureCount");

                return;
            }

            // Password attempts have not exceeded the failure threshold. Update
            // the failure counts. Leave the window the same.

            switch (failureType)
            {
                case "password":
                    user.FailedPasswordAttemptCount = failureCount;
                    break;
                case "passwordAnswer":
                    user.FailedPasswordAnswerAttemptCount = failureCount;
                    break;
            }

            {
                string msg = string.Format("Unable to update failure count for user '{0}'", user.Username);
                Save(user, msg, "UpdateFailureCount");
            }
        }

        protected bool ComparePasswords(string password, string dbpassword, string salt, MembershipPasswordFormat passwordFormat)
        {
            //   Compares password values based on the MembershipPasswordFormat.
            string pass1 = password;
            string pass2 = dbpassword;

            switch (passwordFormat)
            {
                case MembershipPasswordFormat.Encrypted:
                    pass2 = UnEncodePassword(dbpassword, passwordFormat);
                    break;
                case MembershipPasswordFormat.Hashed:
                    pass1 = EncodePassword(password, passwordFormat, salt);
                    break;
                default:
                    break;
            }

            return pass1 == pass2;
        }

        protected string EncodePassword(string password, MembershipPasswordFormat passwordFormat, string salt)
        {
            //   Encrypts, Hashes, or leaves the password clear based on the PasswordFormat.
            if (string.IsNullOrEmpty(password))
                return password;

            byte[] bytes = Encoding.Unicode.GetBytes(password);
            byte[] src = Convert.FromBase64String(salt);
            var dst = new byte[src.Length + bytes.Length];
            byte[] inArray;

            Buffer.BlockCopy(src, 0, dst, 0, src.Length);
            Buffer.BlockCopy(bytes, 0, dst, src.Length, bytes.Length);

            switch (passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    return password;
                case MembershipPasswordFormat.Encrypted:
                    inArray = EncryptPassword(dst);
                    break;
                case MembershipPasswordFormat.Hashed:
                    HashAlgorithm algorithm = HashAlgorithm.Create(Membership.HashAlgorithmType);
                    if (null == algorithm)
                    {
                        throw new ProviderException(
                            string.Format(
                                Resources.Provider_unrecognized_hash_algorithm,
                                Membership.HashAlgorithmType));
                    }
                    inArray = algorithm.ComputeHash(dst);

                    break;
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return Convert.ToBase64String(inArray);
        }

        protected string UnEncodePassword(string encodedPassword, MembershipPasswordFormat passwordFormat)
        {
            //   Decrypts or leaves the password clear based on the PasswordFormat.
            string password = encodedPassword;

            switch (passwordFormat)
            {
                case MembershipPasswordFormat.Clear:
                    break;
                case MembershipPasswordFormat.Encrypted:
                    byte[] bytes = DecryptPassword(Convert.FromBase64String(password));
                    password = null == bytes ? null : Encoding.Unicode.GetString(bytes, 0x10, bytes.Length - 0x10);
                    break;
                case MembershipPasswordFormat.Hashed:
                    throw new ProviderException(Resources.Provider_can_not_decode_hashed_password);
                default:
                    throw new ProviderException("Unsupported password format.");
            }

            return password;
        }

        protected void HandleDataExceptionAndThrow(Exception ex, string action)
        {
            if (WriteExceptionsToEventLog)
            {
                WriteToEventLog(ex, action);

                throw new ProviderException(_exceptionMessage);
            }

            throw ex;
        }

        /// <summary>
        ///     WriteToEventLog
        ///     A helper function that writes exception detail to the event log. Exceptions
        ///     are written to the event log as a security measure to avoid private database
        ///     details from being returned to the browser. If a method does not return a status
        ///     or boolean indicating the action succeeded or failed, a generic exception is also
        ///     thrown by the caller.
        /// </summary>
        /// <param name="ex"></param>
        /// <param name="action"></param>
        protected void WriteToEventLog(Exception ex, string action)
        {
            var log = new EventLog { Source = _eventSource, Log = _eventLog };

            var message = "An exception occurred communicating with the data source.\n\n";
            message += "Action: " + action + "\n\n";
            message += "Exception: " + ex;

            log.WriteEntry(message);
        }

        /// <summary>
        ///     Saves a User to persistent storage
        /// </summary>
        /// <param name="user">The User to save</param>
        /// <param name="failureMessage">A message that will be used if an exception is raised during save</param>
        /// <param name="action">
        ///     The name of the action which attempted the save (ex. "CreateUser"). Used in case exceptions are
        ///     written to EventLog.
        /// </param>
        protected void Save(User user, string failureMessage, string action)
        {
            ReplaceOneResult result = null;
            try
            {
                IMongoCollection<User> users = Collection;
                FilterDefinition<User> filter = Builders<User>.Filter.Eq(u => u.Id, user.Id);
                result = users.ReplaceOne(filter, user, new UpdateOptions { IsUpsert = true });
            }
            catch (Exception ex)
            {
                HandleDataExceptionAndThrow(new ProviderException(failureMessage, ex), action);
            }
            if (null == result)
            {
                HandleDataExceptionAndThrow(new ProviderException("Save to database did not return a status result"), action);
            }
        }

        #endregion
    }
}