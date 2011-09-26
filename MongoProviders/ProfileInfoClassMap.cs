using System;
using MongoDB.Bson.Serialization;
using System.Web.Profile;

namespace MongoProviders
{
    public class ProfileInfoClassMap
    {
        public static void Register()
        {
            if (!BsonClassMap.IsClassMapRegistered(typeof(ProfileInfo)))
            {
                // Initialize Mongo Mappings
                BsonClassMap.RegisterClassMap<ProfileInfo>(cm =>
                {
                    cm.SetIgnoreExtraElements(true);
                    //cm.MapIdMember("UserName").SetElementName("lname");
                    cm.MapMember(c => c.UserName).SetElementName("lname");   // matches User LowercaseUsername
                    cm.MapMember(c => c.LastActivityDate).SetElementName("actdate"); // matches User LastActivityDate
                    cm.MapMember(c => c.LastUpdatedDate).SetElementName("moddate");
                    cm.MapMember(c => c.IsAnonymous).SetElementName("anon");
                    cm.MapMember(c => c.Size).SetElementName("size");
                });
            }
        }
    }
}
