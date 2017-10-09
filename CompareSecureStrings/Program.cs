using System;
using System.Net;

namespace CompareSecureStrings
{
    class Program
    {
        static void Main(string[] args)
        {
            var s1 = new NetworkCredential("", "hello").SecurePassword;
            var s2 = new NetworkCredential("", "hello").SecurePassword;
            var s3 = new NetworkCredential("", "notequal").SecurePassword;

            Console.WriteLine(CompareWithStrcmp.IsEqual(s1, s2));
            Console.WriteLine(CompareWithXor.IsEqual(s1, s2));
            Console.WriteLine(CompareWithHmac.IsEqual(s1, s2));

            Console.WriteLine(CompareWithStrcmp.IsEqual(s1, s3));
            Console.WriteLine(CompareWithXor.IsEqual(s1, s3));
            Console.WriteLine(CompareWithHmac.IsEqual(s1, s3));
        }
    }
}