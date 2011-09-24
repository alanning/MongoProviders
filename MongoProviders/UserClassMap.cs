using System;
using MongoDB.Bson.Serialization;

namespace MongoProviders
{
    public class UserClassMap
    {

        public static void Register()
        {
            if (!BsonClassMap.IsClassMapRegistered(typeof(User)))
            {
                // Initialize Mongo Mappings
                BsonClassMap.RegisterClassMap<User>(cm =>
                {
                    cm.AutoMap();
                    cm.SetIgnoreExtraElements(true);
                    cm.GetMemberMap(c => c.Username).SetElementName("uname");
                    cm.GetMemberMap(c => c.LowercaseUsername).SetElementName("lname");
                    cm.GetMemberMap(c => c.DisplayName).SetElementName("dname");
                    cm.GetMemberMap(c => c.ApplicationName).SetElementName("app");
                    cm.GetMemberMap(c => c.Comment).SetElementName("cmnt");
                    cm.GetMemberMap(c => c.CreateDate).SetElementName("create");
                    cm.GetMemberMap(c => c.Email).SetElementName("email");
                    cm.GetMemberMap(c => c.LowercaseEmail).SetElementName("lemail");
                    cm.GetMemberMap(c => c.FailedPasswordAnswerAttemptCount).SetElementName("anscount");
                    cm.GetMemberMap(c => c.FailedPasswordAttemptCount).SetElementName("passcount");
                    cm.GetMemberMap(c => c.FailedPasswordAnswerAttemptWindowStart).SetElementName("answindow");
                    cm.GetMemberMap(c => c.FailedPasswordAttemptWindowStart).SetElementName("passwindow");
                    cm.GetMemberMap(c => c.IsApproved).SetElementName("apprvd");
                    cm.GetMemberMap(c => c.IsLockedOut).SetElementName("lockd");
                    cm.GetMemberMap(c => c.LastActivityDate).SetElementName("actdate");
                    cm.GetMemberMap(c => c.LastLockedOutDate).SetElementName("lockdate");
                    cm.GetMemberMap(c => c.LastLoginDate).SetElementName("logindate");
                    cm.GetMemberMap(c => c.LastPasswordChangedDate).SetElementName("passdate");
                    cm.GetMemberMap(c => c.Password).SetElementName("pass");
                    cm.GetMemberMap(c => c.PasswordAnswer).SetElementName("ans");
                    cm.GetMemberMap(c => c.PasswordFormat).SetElementName("fmt");
                    cm.GetMemberMap(c => c.PasswordQuestion).SetElementName("qstion");
                    cm.GetMemberMap(c => c.PasswordSalt).SetElementName("salt");
                    cm.GetMemberMap(c => c.Roles).SetElementName("roles").SetIgnoreIfNull(true);
                });
            }
        }
    }
}
