using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace SharpTox.Encryption
{
    public static class ToxEncryption
    {
        internal const int SaltLength = 32;
        internal const int KeyLength = 32;
        internal const int EncryptionExtraLength = 80;

        public static byte[] EncryptData(byte[] data, ToxEncryptionKey key, out ToxErrorEncryption error)
        {
            byte[] output = new byte[data.Length + EncryptionExtraLength];
            error = ToxErrorEncryption.Ok;

            bool success = key.Unprotect();
            var pass = key.ToPassKey();

            try
            {
                if (!ToxEncryptionFunctions.PassKeyEncrypt(data, (uint)data.Length, ref pass, output, ref error) || error != ToxErrorEncryption.Ok)
                    return null;
            }
            finally
            {
                if (success)
                    key.Protect();
            }

            return output;
        }

        public static byte[] EncryptData(byte[] data, ToxEncryptionKey key)
        {
            var error = ToxErrorEncryption.Ok;
            return EncryptData(data, key, out error);
        }

        public static byte[] DecryptData(byte[] data, ToxEncryptionKey key, out ToxErrorDecryption error)
        {
            byte[] output = new byte[data.Length - EncryptionExtraLength];
            error = ToxErrorDecryption.Ok;

            bool success = key.Unprotect();
            var pass = key.ToPassKey();

            try
            {
                if (!ToxEncryptionFunctions.PassKeyDecrypt(data, (uint)data.Length, ref pass, output, ref error) || error != ToxErrorDecryption.Ok)
                    return null;
            }
            finally
            {
                if (success)
                    key.Protect();
            }

            return output;
        }

        public static byte[] DecryptData(byte[] data, ToxEncryptionKey key)
        {
            var error = ToxErrorDecryption.Ok;
            return DecryptData(data, key, out error);
        }

        public static bool IsDataEncrypted(byte[] data)
        {
            return ToxEncryptionFunctions.IsDataEncrypted(data);
        }

        public static byte[] GetSalt(byte[] data)
        {
            byte[] salt = new byte[SaltLength];

            if (!ToxEncryptionFunctions.GetSalt(data, salt))
                return null;

            return salt;
        }

        internal static ToxPassKey? DeriveKey(string passphrase)
        {
            byte[] pp = Encoding.UTF8.GetBytes(passphrase);
            var error = ToxErrorKeyDerivation.Ok;
            var key = new ToxPassKey();

            if (!ToxEncryptionFunctions.DeriveKeyFromPass(pp, (uint)pp.Length, ref key, ref error) || error != ToxErrorKeyDerivation.Ok)
                return null;

            return key;
        }

#if !IS_PORTABLE
        internal static ToxPassKey? DeriveKey(SecureString passphrase)
        {
            var ptr = Marshal.SecureStringToGlobalAllocAnsi(passphrase);
            var error = ToxErrorKeyDerivation.Ok;
            var key = new ToxPassKey();

            try
            {
                if (!ToxEncryptionFunctions.DeriveKeyFromPass(ptr, (uint)passphrase.Length, ref key, ref error) || error != ToxErrorKeyDerivation.Ok)
                    return null;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocAnsi(ptr);
            }

            return key;
        }
#endif

        internal static ToxPassKey? DeriveKey(string passphrase, byte[] salt)
        {
            if (salt.Length < SaltLength)
                return null;

            byte[] pp = Encoding.UTF8.GetBytes(passphrase);
            var error = ToxErrorKeyDerivation.Ok;
            var key = new ToxPassKey();

            if (!ToxEncryptionFunctions.DeriveKeyWithSalt(pp, (uint)pp.Length, salt, ref key, ref error) || error != ToxErrorKeyDerivation.Ok)
                return null;

            return key;
        }

#if !IS_PORTABLE
        internal static ToxPassKey? DeriveKey(SecureString passphrase, byte[] salt)
        {
            if (salt.Length < SaltLength)
                return null;

            var ptr = Marshal.SecureStringToGlobalAllocAnsi(passphrase);
            var error = ToxErrorKeyDerivation.Ok;
            var key = new ToxPassKey();

            try
            {
                if (!ToxEncryptionFunctions.DeriveKeyWithSalt(ptr, (uint)passphrase.Length, salt, ref key, ref error) || error != ToxErrorKeyDerivation.Ok)
                    return null;
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocAnsi(ptr);
            }

            return key;
        }
#endif
    }
}
