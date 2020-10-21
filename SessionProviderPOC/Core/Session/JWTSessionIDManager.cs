using SessionProviderPOC.Core.Extensions;
using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Configuration;
using System.Web.SessionState;
/// <summary>
/// [DISCLAIMER] ====================================================================================================================
/// 
///   This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
/// 
///   THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
/// 
///   INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
/// 
///   We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object
/// 
///   code form of the Sample Code, provided that You agree: (i)to not use Our name, logo, or trademarks to market Your software
/// 
///   product in which the Sample Code is embedded; (ii)to include a valid copyright notice on Your software product in which the
/// 
///   Sample Code is embedded; and(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or
/// 
///   lawsuits, including attorneys’ fees, that arise or result from the use or distribution of the Sample Code.
/// 
/// =================================================================================================================================
/// </summary>
namespace SessionProviderPOC.Core.Session
{
    public class JWTSessionIDManager : SessionIDManager, ISessionIDManager
    {
        internal static ConcurrentDictionary<string, SessionDetails> Sessions = new ConcurrentDictionary<string, SessionDetails>();

        public override string CreateSessionID(HttpContext context)
        {
            string token = ExtractAuthorizationToken(context);
            SessionDetails session = new SessionDetails(token);
            Sessions[session.Key] = session;
            return session.Key;
        }

        public override bool Validate(string id)
        {
            string token = ExtractAuthorizationToken(HttpContext.Current);
            if(Sessions.TryGetValue(token.Checksum(), out SessionDetails details))
                return id.Equals(details.Key, StringComparison.OrdinalIgnoreCase);

            return false;
        }

        private static string ExtractAuthorizationToken(HttpContext context)
        {
            string authorization = context.Request.Headers["Authorization"];
            if (string.IsNullOrWhiteSpace(authorization))
                throw new TypeInitializationException(typeof(JWTSessionIDManager).FullName, new InvalidCredentialException("Missing valid 'Authorization' header"));
            string token = authorization.Split(new[] { ' ' }, 2, StringSplitOptions.RemoveEmptyEntries).Skip(1).FirstOrDefault();
            if (string.IsNullOrWhiteSpace(token))
                throw new InvalidCredentialException("Missing valid 'Authorization' header");
            return token;
        }
    }
}