using System;
using System.Security.Cryptography;
using System.Text;

namespace SessionProviderPOC.Core.Extensions
{
    public static class StringExtensions
    {
        public static string Checksum(this string tokenString)
        {
            // MD5 is the simplest and fastest one - uniqeness is requested (rather than security)
            using (HashAlgorithm algorithm = MD5.Create())
                return BitConverter.ToString(algorithm.ComputeHash(Encoding.UTF8.GetBytes(tokenString)));
        }
    }
}