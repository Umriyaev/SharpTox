using System;
using System.Text;

#if !IS_PORTABLE
using System.Security.Cryptography;
#endif

namespace SharpTox.Core
{
    public static class ToxTools
    {
        internal static string HexBinToString(byte[] b)
        {
            StringBuilder sb = new StringBuilder(2 * b.Length);

            for (int i = 0; i < b.Length; i++)
                sb.AppendFormat("{0:X2}", b[i]);

            return sb.ToString();
        }

        internal static byte[] StringToHexBin(string s)
        {
            byte[] bin = new byte[s.Length / 2];

            for (int i = 0; i < bin.Length; i++)
                bin[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);

            return bin;
        }

        internal static DateTime EpochToDateTime(ulong epoch)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0).AddSeconds(Convert.ToDouble(epoch));
        }

        public static byte[] Hash(byte[] data)
        {
            byte[] hash = new byte[ToxConstants.HashLength];
            ToxFunctions.Hash(hash, data, (uint)data.Length);
            return hash;
        }

        internal static string RemoveNull(string s)
        {
            if (s.Length != 0)
            {
                int index = s.IndexOf(Char.MinValue);
                if (!(index >= 0))
                    return s;
                else
                    return s.Substring(0, index);
            }

            return s;
        }

#if !IS_PORTABLE
        internal static byte[] ProtectBytes(byte[] bytesToProtect)
        {
            int diff = bytesToProtect.Length % 16;
            if (diff == 0)
            {
                ProtectedMemory.Protect(bytesToProtect, MemoryProtectionScope.SameProcess);
                return bytesToProtect;
            }
            else
            {
                byte[] newBytes = new byte[bytesToProtect.Length + diff];
                Array.Copy(bytesToProtect, 0, newBytes, 0, bytesToProtect.Length);

                for (int i = 0; i < bytesToProtect.Length; i++)
                    bytesToProtect[i] = 0;

                ProtectedMemory.Protect(newBytes, MemoryProtectionScope.SameProcess);
                return newBytes;
            }
        }

        internal static byte[] UnprotectBytes(byte[] protectedBytes)
        {
            ProtectedMemory.Unprotect(protectedBytes, MemoryProtectionScope.SameProcess);
            return protectedBytes;
        }
#endif
    }
}
