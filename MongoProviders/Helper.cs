using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using MongoDB.Driver.Builders;
using System.Text.RegularExpressions;
using MongoDB.Bson;
using System.Reflection;
using System.Linq.Expressions;
using MongoDB.Bson.Serialization;

namespace MongoProviders
{
    public class Helper
    {

        public static T GetConfigValue<T>(string configValue, T defaultValue)
        {
            if (String.IsNullOrEmpty(configValue))
                return defaultValue;

            return ((T)Convert.ChangeType(configValue, typeof(T)));
        }

        public static string GenerateCollectionName (string application, string collection)
        {
            if (String.IsNullOrWhiteSpace(application))
                return collection;

            if (application.EndsWith("/"))
                return application + collection;
            else
                return application + "/" + collection;
        }

        /// <summary>
        /// Reference:
        /// http://stackoverflow.com/questions/671968/retrieving-property-name-from-lambda-expression
        /// </summary>
        /// <typeparam name="TProperty"></typeparam>
        /// <param name="propertyLambda"></param>
        /// <returns></returns>
        public static string GetElementNameFor<TSource, TProperty>(Expression<Func<TSource, TProperty>> propertyLambda) {

            Type type = typeof(TSource);
        
            MemberExpression member = propertyLambda.Body as MemberExpression;
            if (member == null)
                throw new ArgumentException(string.Format(
                    "Expression '{0}' refers to a method, not a property.",
                    propertyLambda.ToString()));
        
            PropertyInfo propInfo = member.Member as PropertyInfo;
            if (propInfo == null)
                throw new ArgumentException(string.Format(
                    "Expression '{0}' refers to a field, not a property.",
                    propertyLambda.ToString()));
        
            if (type != propInfo.ReflectedType &&
                !type.IsSubclassOf(propInfo.ReflectedType))
                throw new ArgumentException(string.Format(
                    "Expresion '{0}' refers to a property that is not from type {1}.",
                    propertyLambda.ToString(),
                    type));
        
            var map = BsonClassMap.LookupClassMap(typeof(TSource));
            if (null == map)
            {
                throw new ArgumentException(string.Format(
                    "Missing BsonClassMap for type {0}",
                    type));
            }
            var memberMap = map.GetMemberMap(propInfo.Name);
            if (null == memberMap)
            {
                throw new ArgumentException(string.Format(
                    "BsonClassMap for type {0} does not contain a mapping for member {1}",
                    type, propInfo.Name));
            }

            return memberMap.ElementName;
        }
        public static string GetElementNameFor<TSource>(Expression<Func<TSource, object>> propertyLambda)
        {
            return GetElementNameFor<TSource, object>(propertyLambda);
        }

        public static QueryComplete FindQuery(string strToMatch, string elementName)
        {
            if (String.IsNullOrWhiteSpace(strToMatch))
                throw new ArgumentException("strToMatch can not be empty", "strToMatch");

            var startsWith = strToMatch.StartsWith("%");
            var endsWith = strToMatch.EndsWith("%");

            // check for "%" and "%%" cases
            if ((startsWith && 1 == strToMatch.Length) ||
                (startsWith && endsWith && 2 == strToMatch.Length)) {
                // no way to return a FindAll QueryComplete so use Exists instead...
                return Query.Exists(elementName, true);
            }

            // strip leading and trailing percent
            if (startsWith) {
                strToMatch = strToMatch.Substring(1);
            }
            if (endsWith) {
                strToMatch = strToMatch.Substring(0, strToMatch.Length - 1);
            }

            var value = Regex.Escape(strToMatch.ToLowerInvariant());
            
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


    }
}
