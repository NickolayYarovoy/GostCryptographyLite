using System.Security.Cryptography;

namespace GostCryptographyLite
{
    internal class MagmaKeyData
    {
        public UInt32[][] maskedKey;
        public UInt32[][] mask;

        public MagmaKeyData(UInt32[] key)
        {
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

        public void Clear()
        {
            Array.Clear(maskedKey);
            Array.Clear(mask);
            mask = maskedKey = null!;
        }
    }
}
