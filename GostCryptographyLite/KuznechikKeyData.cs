using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    /// <summary>
    /// A class that storing Kuznechik keys
    /// </summary>
    internal class KuznechikKeyData
    {
        /// <summary>
        /// Scheduled masked keys
        /// </summary>
        private Vector128<byte>[] key = new Vector128<byte>[20];
        /// <summary>
        /// Key masks
        /// </summary>
        public Vector128<byte>[] Key { get => key; private set
            {
                if (value.Length != key.Length)
                    throw new ArgumentException("Sizes aren't match");
                for(int i = 0; i < key.Length; i++)
                    key[i] = value[i];
            } }

        /// <summary>
        /// Create instance by schedeled keys
        /// </summary>
        /// <param name="key">Input keys</param>
        /// <exception cref="ArgumentException">Incorrect input key length</exception>
        public KuznechikKeyData(Vector128<byte>[] key)
        {
            if (key.Length != 10)
                throw new ArgumentException("Incorrect input keys count");

            for(int i = 0; i  < 10; i++)
                Key[i] = key[i];

            for (int i = 10; i < 20; i++)
                Key[i] = Vector128.Create((byte)0);

            byte[] temp = new byte[16];

            Mask();
        }

        /// <summary>
        /// Masking of key
        /// </summary>
        /// <returns></returns>
        public void Mask()
        {
            Vector128<byte> xor;
            for(int i = 0; i < 10; i++)
            {
                xor = Vector128.Create(RandomNumberGenerator.GetBytes(16));
                key[i] ^= xor;
                key[i + 10] ^= xor;
            }
        }

        /// <summary>
        /// Clear key information
        /// </summary>
        public void Clear()
        {
            if (Key != null)
            {
                Array.Clear(Key);
                Key = null!;
            }
        }
    }
}
