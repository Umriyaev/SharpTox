using System;
using System.Runtime.InteropServices;
using System.Security;

#if !IS_PORTABLE
using System.Security.Cryptography;
#endif

namespace SharpTox.Encryption
{
    public class ToxEncryptionKey
    {
        private bool _protected;
        private byte[] _bytes;
        private byte[] _salt;

        public ToxEncryptionKey(string passphrase, bool protect, byte[] salt = null)
        {
            var key = salt == null ? ToxEncryption.DeriveKey(passphrase) : ToxEncryption.DeriveKey(passphrase, salt);
            if (key == null)
                throw new Exception("Could not derive key from passphrase");

#if !IS_PORTABLE
            if (protect)
            {
                _protected = true;
                ProtectedMemory.Protect(key.Value.Key, MemoryProtectionScope.SameProcess);
            }
#endif

            _bytes = key.Value.Key;
            _salt = key.Value.Salt;
        }

#if !IS_PORTABLE
        public ToxEncryptionKey(SecureString passphrase, bool protect, byte[] salt = null)
        {
            var key = salt == null ? ToxEncryption.DeriveKey(passphrase) : ToxEncryption.DeriveKey(passphrase, salt);
            if (key == null)
                throw new Exception("Could not derive key from passphrase");

            if (protect)
            {
                _protected = true;
                ProtectedMemory.Protect(key.Value.Key, MemoryProtectionScope.SameProcess);
            }

            _bytes = key.Value.Key;
            _salt = key.Value.Salt;
        }
#endif

        internal ToxPassKey ToPassKey()
        {
            return new ToxPassKey(_bytes, _salt);
        }

        internal bool Protect()
        {
#if !IS_PORTABLE
            if (!_protected)
            {
                ProtectedMemory.Protect(_bytes, MemoryProtectionScope.SameProcess);
                _protected = true;
                return true;
            }
#endif

            return false;
        }

        internal bool Unprotect()
        {
#if !IS_PORTABLE
            if (_protected)
            {
                ProtectedMemory.Unprotect(_bytes, MemoryProtectionScope.SameProcess);
                _protected = false;
                return true;
            }
#endif

            return false;
        }
    }
}
