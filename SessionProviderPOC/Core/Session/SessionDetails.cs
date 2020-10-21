using Microsoft.IdentityModel.Tokens;
using SessionProviderPOC.Core.Extensions;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;

namespace SessionProviderPOC.Core.Session
{
    public class SessionDetails
    {
        public SessionDetails(string tokenString)
        {
            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            JwtSecurityToken token = handler.ReadToken(tokenString) as JwtSecurityToken;

            // If there is no valid `exp` claim then `ValidTo` returns DateTime.MinValue
            if (ValidTo == default(DateTime))
                throw new SecurityTokenInvalidLifetimeException("JWT token has invalid experation value - could not get 'exp' claim from token");

            ValidTo = token.ValidTo;
            ValidFrom = token.ValidFrom;
            Key = token.Subject;
            Checksum = tokenString.Checksum();
        }

        public string Token { get; private set; }
        public DateTime ValidFrom { get; private set; }

        public DateTime ValidTo { get; private set; }

        public string Key{ get; private set; }

        public string Checksum { get; private set; }

        public bool Expired => (ValidTo < DateTime.UtcNow);

        public override string ToString()
        {
            return $"Key: {Key}, ValidFrom: {ValidFrom}, ValidTo: {ValidTo}, Checksum: {Checksum}";
        }
    }
}