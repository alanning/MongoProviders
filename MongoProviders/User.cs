using System;
using System.Web.Security;
using System.Collections.Generic;

namespace MongoProviders
{
    [Serializable]
    public class User {

		public Guid Id { get; set; }
		public string Username { get; set; }
		public string LowercaseUsername { get; set; }
		public string ApplicationName { get; set; }
		public string Email { get; set; }
		public string LowercaseEmail { get; set; }
        public string DisplayName { get; set; }
		public string Comment { get; set; }
		public string Password { get; set; }
		public MembershipPasswordFormat PasswordFormat { get; set; }
		public string PasswordSalt { get; set; }
		public string PasswordQuestion { get; set; }
		public string PasswordAnswer { get; set; }
		public bool IsApproved { get; set; }
		public DateTime LastActivityDate { get; set; }
		public DateTime LastLoginDate { get; set; }
		public DateTime LastPasswordChangedDate { get; set; }
		public DateTime CreateDate { get; set; }
		public bool IsLockedOut { get; set; }
		public DateTime LastLockedOutDate { get; set; }
		public int FailedPasswordAttemptCount { get; set; }
		public DateTime FailedPasswordAttemptWindowStart { get; set; }
		public int FailedPasswordAnswerAttemptCount { get; set; }
		public DateTime FailedPasswordAnswerAttemptWindowStart { get; set; }
        public List<string> Roles { get; set; }

        public User()
        {
            Roles = new List<string>();
            //Roles.Add("test");
        }

		public override string ToString()
		{
			return Username;
		}

    }
}
