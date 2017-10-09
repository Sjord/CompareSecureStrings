using System;
using System.Security;
using System.Runtime.InteropServices;

namespace CompareSecureStrings
{
    class CompareWithXor
    {
        /// <summary>
        /// Compare two SecureString objects by XOR-ing all bytes.
        /// (C) Sjoerd Langkemper, 2017
        /// This example code is missing vital error handling functionality and should not be used in production.
        /// </summary>
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
            var length1 = Marshal.ReadInt32(bstr1, -4);
            var length2 = Marshal.ReadInt32(bstr2, -4);

            if (length1 != length2) return false;

            var equal = 0;
            for (var i = 0; i < length1; i++)
            {
                var c1 = Marshal.ReadByte(bstr1 + i);
                var c2 = Marshal.ReadByte(bstr2 + i);
                equal |= c1 ^ c2;
            }
            return equal == 0;
        }
    }
}
