using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    internal class KuznechikKeyData
    {
        private Vector128<byte>[] key = new Vector128<byte>[20];
        public Vector128<byte>[] Key { get => key; private set
            {
                if (value.Length != key.Length)
                    throw new ArgumentException("Размеры не совпадают");
                for(int i = 0; i < key.Length; i++)
                    key[i] = value[i];
            } }

        private uint icode;
        public uint ICode { get => icode; private set => icode = value; }

        public KuznechikKeyData(Vector128<byte>[] key)
        {
            if (key.Length != 10)
                throw new ArgumentException("Количество раундовых ключей должно быть равно 10");

            for(int i = 0; i  < 10; i++)
                Key[i] = key[i];

            for (int i = 10; i < 20; i++)
                Key[i] = Vector128.Create((byte)0);

            byte[] temp = new byte[16];

            Mask();
        }

        public bool Mask()
        {
            Vector128<byte> xor;
            for(int i = 0; i < 10; i++)
            {
                xor = Vector128.Create(RandomNumberGenerator.GetBytes(16));
                key[i] ^= xor;
                key[i + 10] ^= xor;
            }
            return true;
        }

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
