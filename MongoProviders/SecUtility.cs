using System;
using System.Linq;
using System.Globalization;

namespace MongoProviders
{
	/// <summary>
	/// Provides general purpose validation functionality.
	/// </summary>
	internal class SecUtility
	{
		/// <summary>
		/// Checks the parameter and throws an exception if one or more rules are violated.
		/// </summary>
		/// <param name="param">The parameter to check.</param>
		/// <param name="checkForNull">When <c>true</c>, verify <paramref name="param"/> is not null.</param>
		/// <param name="checkIfEmpty">When <c>true</c> verify <paramref name="param"/> is not an empty string.</param>
		/// <param name="invalidChars">When not null, verify <paramref name="param"/> does not contain any of the supplied characters.</param>
		/// <param name="maxSize">The maximum allowed length of <paramref name="param"/>.</param>
		/// <param name="paramName">Name of the parameter to check. This is passed to the exception if one is thrown.</param>
		/// <exception cref="ArgumentNullException">Thrown when <paramref name="param"/> is null and <paramref name="checkForNull"/> is true.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="param"/> does not satisfy one of the remaining requirements.</exception>
		/// <remarks>This method performs the same implementation as Microsoft's version at System.Web.Util.SecUtility.</remarks>
		internal static void CheckParameter(ref string param, bool checkForNull, bool checkIfEmpty, string invalidChars, int maxSize, string paramName)
		{
            if (null == param && checkForNull)
			{
                throw new ArgumentNullException(paramName);
			}
			else
			{
				param = param.Trim();
				if (checkIfEmpty && (param.Length < 1))
				{
					throw new ArgumentException(String.Format(Resources.Parameter_can_not_be_empty, paramName), paramName);
				}
				if ((maxSize > 0) && (param.Length > maxSize))
				{
					throw new ArgumentException(String.Format(Resources.Parameter_too_long, paramName, maxSize.ToString(CultureInfo.InvariantCulture)), paramName);
				}
				if (!String.IsNullOrWhiteSpace(invalidChars))
				{
                    var chars = invalidChars.ToCharArray();
                    for (int i = 0; i < chars.Length; i++)
                    {
                        if (param.Contains(chars[i]))
                        {
                            throw new ArgumentException(String.Format(Resources.Parameter_contains_invalid_characters, 
                                paramName, 
                                String.Join("','", invalidChars.Split())), 
                                paramName);
                        }
                    }
				}
			}
		}

		/// <summary>
		/// Verifies that <paramref name="param"/> conforms to all requirements.
		/// </summary>
		/// <param name="param">The parameter to check.</param>
		/// <param name="checkForNull">When <c>true</c>, verify <paramref name="param"/> is not null.</param>
		/// <param name="checkIfEmpty">When <c>true</c> verify <paramref name="param"/> is not an empty string.</param>
		/// <param name="invalidChars">When not null, verify <paramref name="param"/> does not contain any of the supplied characters.</param>
		/// <param name="maxSize">The maximum allowed length of <paramref name="param"/>.</param>
		/// <returns>Returns <c>true</c> if all requirements are met; otherwise returns <c>false</c>.</returns>
		internal static bool ValidateParameter(ref string param, bool checkForNull, bool checkIfEmpty, string invalidChars, int maxSize)
		{
            if (null == param)
			{
				return !checkForNull;
			}
			param = param.Trim();

            bool valid = (!checkIfEmpty || (param.Length >= 1)) &&
                ((maxSize <= 0) || (param.Length <= maxSize));

            if (valid && !String.IsNullOrWhiteSpace(invalidChars))
            {
                var chars = invalidChars.ToCharArray();
                var i = 0;
                while (valid && i < chars.Length) {
                    valid &= !param.Contains(chars[i]);
                    i++;
                }
            }

            return valid;
		}


		/// <summary>
		/// Checks each element in the parameter array and throws an exception if one or more rules are violated.
		/// </summary>
		/// <param name="param">The parameter array to check.</param>
		/// <param name="checkForNull">When <c>true</c>, verify <paramref name="param"/> is not null.</param>
		/// <param name="checkIfEmpty">When <c>true</c> verify <paramref name="param"/> is not an empty string.</param>
		/// <param name="invalidChars">When not null, verify <paramref name="param"/> does not contain any of the supplied characters.</param>
		/// <param name="maxSize">The maximum allowed length of <paramref name="param"/>.</param>
		/// <param name="paramName">Name of the parameter to check. This is passed to the exception if one is thrown.</param>
		/// <exception cref="ArgumentNullException">Thrown when <paramref name="param"/> is null and <paramref name="checkForNull"/> is true.</exception>
		/// <exception cref="ArgumentException">Thrown if <paramref name="param"/> does not satisfy one of the remaining requirements.</exception>
		/// <remarks>This method performs the same implementation as Microsoft's version at System.Web.Util.SecUtility.</remarks>
		internal static void CheckArrayParameter(ref string[] param, bool checkForNull, bool checkIfEmpty, string invalidChars, int maxSize, string paramName)
        {
            if (null == param)
			{
                throw new ArgumentNullException(paramName);
			}
            for (var i = 0; i < param.Length; i++ )
            {
                CheckParameter(ref param[i], checkForNull, checkIfEmpty, invalidChars, maxSize, paramName);
            }
        }
    }
}
