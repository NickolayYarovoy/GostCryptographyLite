using System.Security.Cryptography;

namespace GostCryptographyLite
{
    /// <summary>
    /// A class that storing Magma keys
    /// </summary>
    internal class MagmaKeyData
    {
        /// <summary>
        /// Scheduled masked keys
        /// </summary>
        public UInt32[][] maskedKey;
        /// <summary>
        /// Key masks
        /// </summary>
        public UInt32[][] mask;

        /// <summary>
        /// Create instance by key
        /// </summary>
        /// <param name="key">Input keys</param>
        /// <exception cref="ArgumentException">Incorrect input key count</exception>
        public MagmaKeyData(UInt32[] key)
        {
            if (key.Length != 8)
                throw new ArgumentException("Incorrect input keys count");

            maskedKey = new UInt32[2][];

            maskedKey[0] = new UInt32[32];
            maskedKey[1] = new UInt32[32];

            mask = new UInt32[2][];

            mask[0] = new UInt32[32];
            mask[1] = new UInt32[32];

            for (int i = 0; i < 24; i++)
            {
                UInt32 maskNow = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
                maskedKey[0][i] = key[i & 7] + maskNow;
                mask[0][i] = maskNow;
                maskNow = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
                maskedKey[1][i] = ~key[i & 7] + maskNow;
                mask[1][i] = maskNow;
            }

            for (int i = 0; i < 8; i++)
            {
                UInt32 maskNow = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
                maskedKey[0][31 - i] = key[i] + maskNow;
                mask[0][31 - i] = maskNow;
                maskNow = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4));
                maskedKey[1][31 - i] = ~key[i] + maskNow;
                mask[1][31 - i] = maskNow;
            }
        }

        /// <summary>
        /// Clear key information
        /// </summary>
        public void Clear()
        {
            Array.Clear(maskedKey);
            Array.Clear(mask);
            mask = maskedKey = null!;
        }
    }
}
