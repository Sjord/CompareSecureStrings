using System;
using System.Security;
using System.Runtime.InteropServices;

namespace CompareSecureStrings
{
    /// <summary>
    /// Compare two SecureString objects by using P/Invoke on lstrcmp.
    /// (C) Sjoerd Langkemper, 2017
    /// This example code is missing vital error handling functionality and should not be used in production.
    /// </summary>
    class CompareWithStrcmp
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        static extern int lstrcmp(IntPtr lpString1, IntPtr lpString2);

        public static bool IsEqual(SecureString ss1, SecureString ss2)
        {
            var bstr1 = Marshal.SecureStringToBSTR(ss1);
            var bstr2 = Marshal.SecureStringToBSTR(ss2);

            var result = IsEqual(bstr1, bstr2);

            Marshal.ZeroFreeBSTR(bstr2);
            Marshal.ZeroFreeBSTR(bstr1);

            return result;
        }

        private static bool IsEqual(IntPtr bstr1, IntPtr bstr2)
        {
            return lstrcmp(bstr1, bstr2) == 0;
        }
    }
}
