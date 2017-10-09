using System;
using System.Security;
using System.Runtime.InteropServices;
using System.Linq;

namespace CompareSecureStrings
{
    /// <summary>
    /// Compare two SecureString objects by creating a random HMAC of both SecureStrings, and comparing that.
    /// (C) Sjoerd Langkemper, 2017
    /// This example code is missing vital error handling functionality and should not be used in production.
    /// </summary>
    class CompareWithHmac
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptGenKey(IntPtr hProv, uint Algid, uint dwFlags, ref IntPtr phKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptDestroyKey(IntPtr hKey);

        [DllImport("Advapi32.dll", EntryPoint = "CryptReleaseContext", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptReleaseContext(IntPtr hProv, Int32 dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptHashData(IntPtr hHash, IntPtr pbData, uint dataLen, uint flags);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CryptCreateHash(IntPtr hProv, uint algId, IntPtr hKey, uint dwFlags, ref IntPtr phHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptSetHashParam(IntPtr hHash, uint dwParam, ref _HMAC_Info pbData, Int32 dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptGetHashParam(IntPtr hHash, uint dwParam, byte[] pbData, ref uint dwDataLen, uint dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptDestroyHash(IntPtr hHash);

        const uint PROV_RSA_FULL = 1;
        const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        const uint CALG_RC2 = 0x00006602;
        const uint CALG_HMAC = 0x00008009;
        const uint CALG_SHA512 = 0x0000800e;
        const uint CRYPT_EXPORTABLE = 1;
        const uint HP_HASHVAL = 2;
        const uint HP_HMAC_INFO = 5;

        struct _HMAC_Info
        {
            public uint HashAlgid;
            public byte[] pbInnerString;
            public uint cbInnerString;
            public byte[] pbOuterString;
            public uint cbOuterString;
        }

        public static bool IsEqual(SecureString ss1, SecureString ss2)
        {
            IntPtr hProv = IntPtr.Zero;
            CryptAcquireContext(ref hProv, null, null, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

            IntPtr hKey = IntPtr.Zero;
            CryptGenKey(hProv, CALG_RC2, CRYPT_EXPORTABLE, ref hKey);

            var hmac1 = CreateHmacForSecureString(hProv, hKey, ss1);
            var hmac2 = CreateHmacForSecureString(hProv, hKey, ss2);

            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);

            return hmac1.SequenceEqual(hmac2);
        }

        private static byte[] CreateHmacForSecureString(IntPtr hProv, IntPtr hKey, SecureString ss)
        {
            IntPtr hHash = IntPtr.Zero;
            CryptCreateHash(hProv, CALG_HMAC, hKey, 0, ref hHash);

            var hmacInfo = new _HMAC_Info() { HashAlgid = CALG_SHA512 };
            CryptSetHashParam(hHash, HP_HMAC_INFO, ref hmacInfo, 0);

            var bstr = Marshal.SecureStringToBSTR(ss);
            var len = (uint)Marshal.ReadInt32(bstr, -4);
            CryptHashData(hHash, bstr, len, 0);
            Marshal.ZeroFreeBSTR(bstr);

            uint length = 64;
            byte[] pbData = new byte[64];
            CryptGetHashParam(hHash, HP_HASHVAL, pbData, ref length, 0);

            CryptDestroyHash(hHash);

            return pbData;
        }
    }
}
