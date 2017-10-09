using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace CompareSecureStrings
{
    class Program
    {
        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl)]
        static extern int wcscmp(IntPtr s1, IntPtr s2);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptCreateHash(IntPtr hProv, uint algId, IntPtr hKey, uint dwFlags, ref IntPtr phHash);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CryptAcquireContext(ref IntPtr hProv, string pszContainer, string pszProvider, uint dwProvType, uint dwFlags);

        [DllImport("Advapi32.dll", EntryPoint = "CryptReleaseContext", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CryptReleaseContext(IntPtr hProv, Int32 dwFlags);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptDestroyHash(IntPtr hHash);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptHashData(IntPtr hHash, IntPtr pbData, uint dataLen, uint flags);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool CryptGetHashParam(IntPtr hHash, uint dwParam, byte[] pbData, ref uint dwDataLen, uint dwFlags);

        [DllImport(@"advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CryptImportKey(IntPtr hProv, IntPtr pbKeyData, UInt32 dwDataLen, IntPtr hPubKey, UInt32 dwFlags, ref IntPtr hKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptSetHashParam(IntPtr hHash, uint dwParam, ref _HMAC_Info pbData, Int32 dwFlags);


        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptGenKey(IntPtr hProv, uint Algid, uint dwFlags, ref IntPtr phKey);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool CryptDestroyKey(IntPtr hKey);





        const uint CALG_SHA1 = 0x00008004;
        const uint CALG_SHA512 = 0x0000800e;
        const uint CALG_HMAC = 0x00008009;
        const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        const uint HP_HASHVAL = 2;
        const uint PROV_RSA_FULL = 1;
        const uint PROV_RSA_AES = 24;
        const uint HP_HMAC_INFO = 5;
        const uint CALG_RC2 = 0x00006602;
        const uint CRYPT_EXPORTABLE = 1;

        public struct _HMAC_Info
        {
            public uint HashAlgid;
            public byte[] pbInnerString;
            public uint cbInnerString;
            public byte[] pbOuterString;
            public uint cbOuterString;
        }

        static void Main(string[] args)
        {
            var s1 = new NetworkCredential("", "hello").SecurePassword;
            var s2 = new NetworkCredential("", "hello").SecurePassword;

            Console.WriteLine(CompareSecureStrings(s1, s2));
        }

        public static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }

        private static SecureString CreateRandomSecureString()
        {
            var rng = new RNGCryptoServiceProvider();
            var randomBytes = new byte[16];
            rng.GetBytes(randomBytes);
            SecureString sstring = new SecureString();
            foreach (var b in randomBytes)
            {
                sstring.AppendChar((char)b);
            }
            Array.Clear(randomBytes, 0, randomBytes.Length);
            return sstring;
        }

        private static bool CompareSecureStrings(SecureString ss1, SecureString ss2)
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
        

        /*
        private static byte[] CreateHashForSecureString(SecureString ss)
        {
            IntPtr hProv = IntPtr.Zero;
            CryptAcquireContext(ref hProv, null, null, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);

            IntPtr hHash = IntPtr.Zero;
            CryptCreateHash(hProv, CALG_SHA1, IntPtr.Zero, 0, ref hHash);

            var bstr = Marshal.SecureStringToBSTR(ss);
            var len = (uint)Marshal.ReadInt32(bstr, -4);
            CryptHashData(hHash, bstr, len, 0);
            Marshal.ZeroFreeBSTR(bstr);

            byte[] pbData = new byte[20];
            uint length = (uint)pbData.Length;
            CryptGetHashParam(hHash, HP_HASHVAL, pbData, ref length, 0);

            CryptDestroyHash(hHash);
            CryptReleaseContext(hProv, 0);

            return pbData;
        }
        */

    }
}
