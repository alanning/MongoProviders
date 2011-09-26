// Port to MongoDB of MySql Connector by Adrian Lanning <adrian@nimblejump.com>
// Copyright (c) 2011 Adrian Lanning <adrian@nimblejump.com>
//
// Copyright (c) 2004-2008 MySQL AB, 2008-2009 Sun Microsystems, Inc.
//
// MySQL Connector/NET is licensed under the terms of the GPLv2
// <http://www.gnu.org/licenses/old-licenses/gpl-2.0.html>, like most 
// MySQL Connectors. There are special exceptions to the terms and 
// conditions of the GPLv2 as it is applied to this software, see the 
// FLOSS License Exception
// <http://www.mysql.com/about/legal/licensing/foss-exception.html>.
//
// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published 
// by the Free Software Foundation; version 2 of the License.
//
// This program is distributed in the hope that it will be useful, but 
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
// or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License 
// for more details.
//
// You should have received a copy of the GNU General Public License along 
// with this program; if not, write to the Free Software Foundation, Inc., 
// 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA

//  This code was contributed by Sean Wright (srwright@alcor.concordia.ca) on 2007-01-12
//  The copyright was assigned and transferred under the terms of
//  the MySQL Contributor License Agreement (CLA)

using NUnit.Framework;
using System.Web.Security;
using System.Collections.Specialized;
using System;
using System.Linq;
using System.Configuration.Provider;
using MongoDB.Driver.Builders;
using MongoDB.Bson.Serialization;

namespace MongoProviders.UnitTests
{
    [TestFixture]
    public class MembershipProviderTest : BaseTest
    {
        protected MembershipProvider provider;

        [SetUp]
		public override void Setup()
		{
            base.Setup();
            provider = new MembershipProvider();
		}

        private void CreateUserWithFormat(MembershipPasswordFormat format)
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("applicationName", _applicationName);
            config.Add("passwordStrengthRegularExpression", "bar.*");
            config.Add("passwordFormat", format.ToString());
            provider.Initialize(null, config);

            // create the user
            MembershipCreateStatus status;
            provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
            Assert.AreEqual(MembershipCreateStatus.Success, status);

            // verify that the password format was saved
            var user = _db.GetCollection<User>(provider.CollectionName).FindOne(Query.EQ(provider.ElementNames.LowercaseUsername, "foo"));
            MembershipPasswordFormat rowFormat = user.PasswordFormat;
            Assert.AreEqual(format, rowFormat);

            //  then attempt to verify the user
            Assert.IsTrue(provider.ValidateUser("foo", "barbar!"));
        }

        [Test]
        public void CreateUserWithHashedPassword()
        {
            CreateUserWithFormat(MembershipPasswordFormat.Hashed);
        }

        [Test]
        public void CreateUserWithEncryptedPassword()
        {
            CreateUserWithFormat(MembershipPasswordFormat.Encrypted);
        }

        [Test]
        public void CreateUserWithClearPassword()
        {
            CreateUserWithFormat(MembershipPasswordFormat.Clear);
        }

        /// <summary>
        /// MySQL Bug #34792 New User/Changing Password Validation Not working. 
        /// </summary>
        [Test]
        public void ChangePassword()
        {
            CreateUserWithHashedPassword();
            try
            {
                provider.ChangePassword("foo", "barbar!", "bar2");
                Assert.Fail();
            }
            catch (ArgumentException ae1)
            {
                Assert.AreEqual("newPassword", ae1.ParamName);
                Assert.IsTrue(ae1.Message.Contains("length of parameter"));
            }

            try
            {
                provider.ChangePassword("foo", "barbar!", "barbar2");
                Assert.Fail();
            }
            catch (ArgumentException ae1)
            {
                Assert.AreEqual("newPassword", ae1.ParamName);
                Assert.IsTrue(ae1.Message.Contains("alpha numeric"));
            }

            try
            {
                // now test regex strength testing
                provider.ChangePassword("foo", "barbar!", "zzzxxx!");
                Assert.Fail();
            }
            catch (ArgumentException ae1)
            {
                Assert.AreEqual("newPassword", ae1.ParamName);
                Assert.IsTrue(ae1.Message.Contains("regular expression"));
            }

            // now do one that should work
            bool result = provider.ChangePassword("foo", "barbar!", "barfoo!");
            Assert.IsTrue(result);

            provider.ValidateUser("foo", "barfoo!");
        }

        /// <summary>
        /// MySQL Bug #34792 New User/Changing Password Validation Not working. 
        /// </summary>
        [Test]
        public void CreateUserWithErrors()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("applicationName", _applicationName);
            config.Add("passwordStrengthRegularExpression", "bar.*");
            config.Add("passwordFormat", "Hashed");
            provider.Initialize(null, config);

            // first try to create a user with a password not long enough
            MembershipCreateStatus status;
            MembershipUser user = provider.CreateUser("foo", "xyz", 
                "foo@bar.com", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidPassword, status);

            // now with not enough non-alphas
            user = provider.CreateUser("foo", "xyz1234",
                "foo@bar.com", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidPassword, status);

            // now one that doesn't pass the regex test
            user = provider.CreateUser("foo", "xyzxyz!",
                "foo@bar.com", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidPassword, status);

            // now one that works
            user = provider.CreateUser("foo", "barbar!",
                "foo@bar.com", null, null, true, null, out status);
            Assert.IsNotNull(user);
            Assert.AreEqual(MembershipCreateStatus.Success, status);
        }

        [Test]
        public void CreateUserWithDefaultInvalidCharacters()
        {
            // test default invalid characters

            // Username
            MembershipCreateStatus status;
            MembershipUser user = Membership.CreateUser("foo,","xyz",
                "foo@bar.com", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidUserName, status);

            user = Membership.CreateUser("foo%", "xyz",
                "foo@bar.com", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidUserName, status);


            // Email
            user = Membership.CreateUser("foo", "xyz",
                "foo,@bar.com", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidEmail, status);

            user = Membership.CreateUser("foo", "xyz",
                "foo%@bar.com", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidEmail, status);
        }

        [Test]
        public void CreateUserWithCustomInvalidCharacters()
        {
            var invalidUserChars = "()-#";
            var invalidEmailChars = "^/`";

            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("applicationName", _applicationName);
            config.Add("passwordStrengthRegularExpression", "bar.*");
            config.Add("passwordFormat", "Hashed");
            config.Add("invalidUsernameCharacters", invalidUserChars);
            config.Add("invalidEmailCharacters", invalidEmailChars);
            provider.Initialize(null, config);

            // Username
            MembershipCreateStatus status;
            var username = "foo{0}";
            foreach (var c in invalidUserChars.Split())
            {
                MembershipUser user = provider.CreateUser(
                    String.Format(username, c),
                    "xyz",
                    "foo@bar.com", null, null, true, null, out status);
                Assert.IsNull(user);
                Assert.AreEqual(MembershipCreateStatus.InvalidUserName, status);
            }

            // Email
            var email = "foo{0}@bar.com";
            foreach (var c in invalidEmailChars.Split())
            {
                MembershipUser user = provider.CreateUser(
                    "foo",
                    "xyz",
                    String.Format(email, c),
                    null, null, true, null, out status);
                Assert.IsNull(user);
                Assert.AreEqual(MembershipCreateStatus.InvalidEmail, status);
            }

        }

        [Test]
        public void DeleteUser()
        {
            CreateUserWithHashedPassword();
            Assert.IsTrue(provider.DeleteUser("foo", true));
            var count = _db.GetCollection<User>(provider.CollectionName).Count();
            Assert.AreEqual(0, count);

            provider = new MembershipProvider();
            CreateUserWithHashedPassword();

            // in Mongo, all associated data is stored in same document so 
            // passing true or false to DeleteUser will be the same.
            Assert.IsTrue(provider.DeleteUser("foo", deleteAllRelatedData: true));
            count = _db.GetCollection<User>(provider.CollectionName).Count();
            Assert.AreEqual(0, count);
            //Assert.IsTrue(Membership.DeleteUser("foo", false));
            //table = FillTable("SELECT * FROM my_aspnet_Membership");
            //Assert.AreEqual(0, table.Rows.Count);
            //table = FillTable("SELECT * FROM my_aspnet_Users");
            //Assert.AreEqual(1, table.Rows.Count);
        }

        [Test]
        public void FindUsersByName()
        {
            CreateUserWithHashedPassword();

            int records;
            MembershipUserCollection users = provider.FindUsersByName("F%", 0, 10, out records);
            Assert.AreEqual(1, records);
            Assert.AreEqual("foo", users["foo"].UserName);
        }

        [Test]
        public void FindUsersByEmail()
        {
            CreateUserWithHashedPassword();

            int records;
            MembershipUserCollection users = provider.FindUsersByEmail("foo@bar.com", 0, 10, out records);
            Assert.AreEqual(1, records);
            Assert.AreEqual("foo", users["foo"].UserName);
        }

        [Test]
        public void TestCreateUserOverrides()
        {
            try
            {
                MembershipCreateStatus status;
                Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);
                int records;
                MembershipUserCollection users = Membership.FindUsersByName("F%", 0, 10, out records);
                Assert.AreEqual(1, records);
                Assert.AreEqual("foo", users["foo"].UserName);

                Membership.CreateUser("test", "barbar!", "myemail@host.com", 
                    "question", "answer", true, out status);
                users = Membership.FindUsersByName("T%", 0, 10, out records);
                Assert.AreEqual(1, records);
                Assert.AreEqual("test", users["test"].UserName);
            }
            catch (Exception ex)
            {
                Assert.Fail(ex.Message);
            }
        }

        [Test]
        public void NumberOfUsersOnline()
        {
            int numOnline = Membership.GetNumberOfUsersOnline();
            Assert.AreEqual(0, numOnline);

            MembershipCreateStatus status;
            Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);
            Membership.CreateUser("foo2", "barbar!", "foo2@bar.com", "question", "answer", true, out status);

            numOnline = Membership.GetNumberOfUsersOnline();
            Assert.AreEqual(2, numOnline);
        }

        [Test]
        public void UnlockUser()
        {
            MembershipCreateStatus status;
            Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);
            Assert.IsFalse(Membership.ValidateUser("foo", "bar2"));
            Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));
            Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));
            Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));
            Assert.IsFalse(Membership.ValidateUser("foo", "bar3"));

            // the user should be locked now so the right password should fail
            Assert.IsFalse(Membership.ValidateUser("foo", "barbar!"));

            MembershipUser user = Membership.GetUser("foo");
            Assert.IsTrue(user.IsLockedOut);

            Assert.IsTrue(user.UnlockUser());
            user = Membership.GetUser("foo");
            Assert.IsFalse(user.IsLockedOut);

            Assert.IsTrue(Membership.ValidateUser("foo", "barbar!"));
        }

        [Test]
        public void GetUsernameByEmail()
        {
            MembershipCreateStatus status;
            Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, out status);
            string username = Membership.GetUserNameByEmail("foo@bar.com");
            Assert.AreEqual("foo", username);

            username = Membership.GetUserNameByEmail("foo@b.com");
            Assert.IsNull(username);

            username = Membership.GetUserNameByEmail("  foo@bar.com   ");
            Assert.AreEqual("foo", username);
        }

        [Test]
        public void UpdateUser()
        {
            MembershipCreateStatus status;
            Membership.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, out status);
            Assert.AreEqual(MembershipCreateStatus.Success, status);

            MembershipUser user = Membership.GetUser("foo");

            user.Comment = "my comment";
            user.Email = "my email";
            user.IsApproved = false;
            user.LastActivityDate = new DateTime(2008, 1, 1);
            user.LastLoginDate = new DateTime(2008, 2, 1);
            Membership.UpdateUser(user);

            MembershipUser newUser = Membership.GetUser("foo");
            Assert.AreEqual(user.Comment, newUser.Comment);
            Assert.AreEqual(user.Email, newUser.Email);
            Assert.AreEqual(user.IsApproved, newUser.IsApproved);
            Assert.AreEqual(user.LastActivityDate, newUser.LastActivityDate);
            Assert.AreEqual(user.LastLoginDate, newUser.LastLoginDate);
        }

        private void ChangePasswordQAHelper(MembershipUser user, string pw, string newQ, string newA)
        {
            try
            {
                user.ChangePasswordQuestionAndAnswer(pw, newQ, newA);
                Assert.Fail("This should not work.");
            }
            catch (ArgumentNullException ane)
            {
                Assert.AreEqual("password", ane.ParamName);
            }
            catch (ArgumentException)
            {
                Assert.IsNotNull(pw);
            }
        }

        [Test]
        public void ChangePasswordQuestionAndAnswer()
        {
            MembershipCreateStatus status;
            Membership.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, out status);
            Assert.AreEqual(MembershipCreateStatus.Success, status);

            MembershipUser user = Membership.GetUser("foo");
            ChangePasswordQAHelper(user, "", "newQ", "newA");
            ChangePasswordQAHelper(user, "barbar!", "", "newA");
            ChangePasswordQAHelper(user, "barbar!", "newQ", "");
            ChangePasswordQAHelper(user, null, "newQ", "newA");

            bool result = user.ChangePasswordQuestionAndAnswer("barbar!", "newQ", "newA");
            Assert.IsTrue(result);

            user = Membership.GetUser("foo");
            Assert.AreEqual("newQ", user.PasswordQuestion);
        }

        [Test]
        public void GetAllUsers()
        {
            MembershipCreateStatus status;
            // first create a bunch of users
            for (int i = 0; i < 100; i++)
            {
                var user = String.Format("foo{0}", i);
                Membership.CreateUser(user, "barbar!", user + "@bar.com",
                    "question", "answer", true, out status);
            }

            MembershipUserCollection users = Membership.GetAllUsers();
            Assert.AreEqual(100, users.Count);
            int index = 0;
            foreach (MembershipUser user in users)
                Assert.AreEqual(String.Format("foo{0}", index++), user.UserName);

            int total;
            users = Membership.GetAllUsers(2, 10, out total);
            Assert.AreEqual(10, users.Count);
            Assert.AreEqual(100, total);
            index = 0;
            foreach (MembershipUser user in users)
                Assert.AreEqual(String.Format("foo2{0}", index++), user.UserName);
        }

        private void GetPasswordHelper(bool requireQA, bool enablePasswordRetrieval, string answer)
        {
            MembershipCreateStatus status;
            provider = new MembershipProvider();
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("requiresQuestionAndAnswer", requireQA ? "true" : "false");
            config.Add("enablePasswordRetrieval", enablePasswordRetrieval ? "true" : "false");
            config.Add("passwordFormat", "clear");
            config.Add("applicationName", _applicationName);
            config.Add("writeExceptionsToEventLog", "false");
            provider.Initialize(null, config);

            provider.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, null, out status);

            try
            {
                string password = provider.GetPassword("foo", answer);
                if (!enablePasswordRetrieval)
                    Assert.Fail("This should have thrown an exception");
                Assert.AreEqual("barbar!", password);
            }
            catch (MembershipPasswordException)
            {
                if (requireQA && answer != null)
                    Assert.Fail("This should not have thrown an exception");
            }
            catch (ProviderException)
            {
                if (requireQA && answer != null)
                    Assert.Fail("This should not have thrown an exception");
            }
        }

        [Test]
        public void GetPassword()
        {
            GetPasswordHelper(false, false, null);
            GetPasswordHelper(false, true, null);
            GetPasswordHelper(true, true, null);
            GetPasswordHelper(true, true, "blue");
        }

        /// <summary>
        /// MySQL Bug #38939 MembershipUser.GetPassword(string answer) fails when incorrect answer is passed.
        /// </summary>
        [Test]
        public void GetPasswordWithWrongAnswer()
        {
            MembershipCreateStatus status;
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("requiresQuestionAndAnswer", "true");
            config.Add("enablePasswordRetrieval", "true");
            config.Add("passwordFormat", "Encrypted");
            config.Add("applicationName", _applicationName);
            provider.Initialize(null, config);
            provider.CreateUser("foo", "barbar!", "foo@bar.com", "color", "blue", true, null, out status);

            MongoProviders.MembershipProvider provider2 = new MongoProviders.MembershipProvider();
            NameValueCollection config2 = new NameValueCollection();
            config2.Add("connectionStringName", "local");
            config2.Add("requiresQuestionAndAnswer", "true");
            config2.Add("enablePasswordRetrieval", "true");
            config2.Add("passwordFormat", "Encrypted");
            config2.Add("applicationName", _applicationName);
            provider2.Initialize(null, config2);

            try
            {
                string pw = provider2.GetPassword("foo", "wrong");
                Assert.Fail("Should have  failed");
            }
            catch (MembershipPasswordException)
            {
            }
        }

        [Test]
        public void GetUser()
        {
            MembershipCreateStatus status;
            var guid = Guid.NewGuid();
            Membership.CreateUser("foo", "barbar!", "foo@bar.com", "question", "answer", true, guid, out status);
            MembershipUser user = Membership.GetUser(guid);
            Assert.AreEqual("foo", user.UserName);

            // now move the activity date back outside the login
            // window
            user.LastActivityDate = new DateTime(2008, 1, 1);
            Membership.UpdateUser(user);

            user = Membership.GetUser("foo");
            Assert.IsFalse(user.IsOnline);

            user = Membership.GetUser("foo", true);
            Assert.IsTrue(user.IsOnline);

            // now move the activity date back outside the login
            // window again so we can test with providerUserKey
            user.LastActivityDate = new DateTime(2008, 1, 1);
            Membership.UpdateUser(user);

            user = Membership.GetUser(guid);
            Assert.IsFalse(user.IsOnline);

            user = Membership.GetUser(guid, true);
            Assert.IsTrue(user.IsOnline);
        }

        [Test]
        public void FindUsers()
        {
            MembershipCreateStatus status;
            for (int i = 0; i < 100; i++)
            {
                var user = String.Format("boo{0}", i);
                Membership.CreateUser(user, "barbar!", user + "@bar.com",
                    "question", "answer", true, out status);
                Assert.AreEqual(MembershipCreateStatus.Success, status);
            }
            for (int i = 0; i < 100; i++)
            {
                var user = String.Format("foo{0}", i);
                Membership.CreateUser(user, "barbar!", user + "@bar.com",
                    "question", "answer", true, null, out status);
                Assert.AreEqual(MembershipCreateStatus.Success, status);
            }
            for (int i = 0; i < 100; i++)
            {
                var user = String.Format("schmoo{0}", i);
                Membership.CreateUser(user, "barbar!", user + "@bar.com",
                    "question", "answer", true, null, out status);
                Assert.AreEqual(MembershipCreateStatus.Success, status);
            }


            int total = 0;
            MembershipUserCollection users = Membership.FindUsersByName("fo%");
            Assert.AreEqual(100, users.Count);

            users = Membership.FindUsersByName("fo%", 2, 10, out total);
            Assert.AreEqual(10, users.Count);
            Assert.AreEqual(100, total);
            int index = 0;
            foreach (MembershipUser user in users)
                Assert.AreEqual(String.Format("foo2{0}", index++), user.UserName);

        }


        [Test]
        public void CreateUserWithNoQA()
        {
            MembershipCreateStatus status;
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("requiresQuestionAndAnswer", "true");
            config.Add("passwordFormat", "clear");
            config.Add("applicationName", _applicationName);
            provider.Initialize(null, config);

            provider.CreateUser("foo", "barbar!", "foo@bar.com", "color", null, true, null, out status);
            Assert.AreEqual(MembershipCreateStatus.InvalidAnswer, status);
            
            
            provider.CreateUser("foo", "barbar!", "foo@bar.com", "", "blue", true, null, out status);
            Assert.AreEqual(MembershipCreateStatus.InvalidQuestion, status);
        }

        [Test]
        public void MinRequiredAlpha()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("applicationName", _applicationName);
            config.Add("minRequiredNonalphanumericCharacters", "3");
            provider.Initialize(null, config);

            MembershipCreateStatus status;
            MembershipUser user = provider.CreateUser("foo", "pw!pass", "email", null, null, true, null, out status);
            Assert.IsNull(user);
            Assert.AreEqual(MembershipCreateStatus.InvalidPassword, status);

            user = provider.CreateUser("foo", "pw!pa!!", "email", null, null, true, null, out status);
            Assert.IsNotNull(user);
            Assert.AreEqual(MembershipCreateStatus.Success, status);
        }

        /// <summary>
        /// MySQL Bug #35332 GetPassword() don't working (when PasswordAnswer is NULL) 
        /// </summary>
        [Test]
        public void GetPasswordWithNullValues()
        {
            MembershipCreateStatus status;
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("requiresQuestionAndAnswer", "false");
            config.Add("enablePasswordRetrieval", "true");
            config.Add("passwordFormat", "clear");
            config.Add("applicationName", _applicationName);
            provider.Initialize(null, config);

            MembershipUser user = provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
            Assert.IsNotNull(user);

            string pw = provider.GetPassword("foo", null);
            Assert.AreEqual("barbar!", pw);
        }

        /// <summary>
        /// MySQL Bug #35336 GetPassword() return wrong password (when format is encrypted) 
        /// </summary>
        [Test]
        public void GetEncryptedPassword()
        {
            MembershipCreateStatus status;
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("requiresQuestionAndAnswer", "false");
            config.Add("enablePasswordRetrieval", "true");
            config.Add("passwordFormat", "encrypted");
            config.Add("applicationName", _applicationName);
            provider.Initialize(null, config);

            MembershipUser user = provider.CreateUser("foo", "barbar!", "foo@bar.com", null, null, true, null, out status);
            Assert.IsNotNull(user);

            string pw = provider.GetPassword("foo", null);
            Assert.AreEqual("barbar!", pw);
        }

        /// <summary>
        /// MySQL Bug #42574	ValidateUser does not use the application id, allowing cross application login
        /// </summary>
        [Test]
        public void CrossAppLogin()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("applicationName", _applicationName);
            config.Add("passwordStrengthRegularExpression", "bar.*");
            config.Add("passwordFormat", "Clear");
            provider.Initialize(null, config);
            MembershipCreateStatus status;
            provider.CreateUser("foo", "bar!bar", null, null, null, true, null, out status);

            MongoProviders.MembershipProvider provider2 = new MongoProviders.MembershipProvider();
            NameValueCollection config2 = new NameValueCollection();
            config2.Add("connectionStringName", "local");
            config2.Add("applicationName", _appName2);
            config2.Add("passwordStrengthRegularExpression", ".*");
            config2.Add("passwordFormat", "Clear");
            provider2.Initialize(null, config2);

            bool worked = provider2.ValidateUser("foo", "bar!bar");
            Assert.AreEqual(false, worked);

            _db.DropCollection(provider2.CollectionName);
        }

        /// <summary>
        /// MySQL Bug #41408	PasswordReset not possible when requiresQuestionAndAnswer="false"
        /// </summary>
        [Test]
        public void ResetPassword()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("applicationName", _applicationName);
            config.Add("passwordStrengthRegularExpression", "bar.*");
            config.Add("passwordFormat", "Clear");
            config.Add("requiresQuestionAndAnswer", "false");
            provider.Initialize(null, config);

            MembershipCreateStatus status;
            provider.CreateUser("foo", "bar!bar", "foo@bar.com", null, null, true, null, out status);

            MembershipUser u = provider.GetUser("foo", false);
            string newpw = provider.ResetPassword("foo", null);
        }

        /// <summary>
        /// MySQL Bug #59438	setting Membership.ApplicationName has no effect
        /// </summary>
        [Test]
        public void ChangeAppName()
        {
            NameValueCollection config = new NameValueCollection();
            config.Add("connectionStringName", "local");
            config.Add("applicationName", _applicationName);
            config.Add("requiresUniqueEmail", "false");
            config.Add("passwordStrengthRegularExpression", "bar.*");
            config.Add("passwordFormat", "Clear");
            provider.Initialize(null, config);
            MembershipCreateStatus status;
            provider.CreateUser("foo", "bar!bar", null, null, null, true, null, out status);
            Assert.AreEqual(MembershipCreateStatus.Success, status);

            MongoProviders.MembershipProvider provider2 = new MongoProviders.MembershipProvider();
            NameValueCollection config2 = new NameValueCollection();
            config2.Add("connectionStringName", "local");
            config2.Add("applicationName", _appName2);
            config2.Add("requiresUniqueEmail", "false");
            config2.Add("passwordStrengthRegularExpression", "foo.*");
            config2.Add("passwordFormat", "Clear");
            provider2.Initialize(null, config2);
            provider2.CreateUser("foo2", "foo!foo", null, null, null, true, null, out status);
            Assert.AreEqual(MembershipCreateStatus.Success, status);

            provider.ApplicationName = "/myapp";
            Assert.IsFalse(provider.ValidateUser("foo", "bar!bar"));
            Assert.IsTrue(provider.ValidateUser("foo2", "foo!foo"));
        }

        [Test]
        public void GetUserLooksForExactUsername()
        {
            MembershipCreateStatus status;
            Membership.CreateUser("code", "thecode!", "code@example.com", "question", "answer", true, out status);

            MembershipUser user = Membership.GetUser("code");
            Assert.AreEqual("code", user.UserName);

            user = Membership.GetUser("co_e");
            Assert.IsNull(user);
        }

        [Test]
        public void GetUserNameByEmailLooksForExactEmail()
        {
            MembershipCreateStatus status;
            Membership.CreateUser("code", "thecode!", "code@mysql.com", "question", "answer", true, out status);

            string username = Membership.GetUserNameByEmail("code@mysql.com");
            Assert.AreEqual("code", username);

            username = Membership.GetUserNameByEmail("co_e@mysql.com");
            Assert.IsNull(username);
        }

    }
}