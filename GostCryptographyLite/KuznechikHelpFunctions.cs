using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    /// <summary>
    ///  Class with auxiliary functions for the Luznechik aglorythm
    /// </summary>
    internal static class KuznechikHelpFunctions
    {
        /// <summary>
        /// Standard linear feedback shift register with 16 iterations implementation
        /// </summary>
        /// <param name="w">Initial register padding</param>
        public static void LinearSteps(byte[] w)
        {
            int i = 0, j = 0;
            for (j = 0; j < 16; j++)
            {
                byte z = Gf256Muliply(w[0], register[0]);
                for (i = 1; i < 16; i++)
                {
                    w[i - 1] = w[i];
                    z ^= Gf256Muliply(w[i], register[i]);
                }
                w[15] = z;
            }
        }

        /// <summary>
        /// Reversing the byte order in an array if the system uses LittleEndian
        /// </summary>
        /// <param name="arr">Input and output array</param>
        public static void ReverceIsLittleEndian(ref byte[] arr)
        {
            if (BitConverter.IsLittleEndian)
                arr = arr.Reverse().ToArray();
        }

        /// <summary>
        /// Multiplication operation in Galois field 2^{256}
        /// </summary>
        /// <param name="x">First Galois field element</param>
        /// <param name="y">Second Galois field element</param>
        /// <returns>Multiplication of x and y</returns>
        public static byte Gf256Muliply(byte x, byte y)
        {
            byte z = 0;
            while (y != 0)
            {
                if ((y & 0x1) != 0) z ^= x;
                x = (byte)(((byte)(x << 1)) ^ ((x & 0x80) != 0 ? 0xC3 : 0x00));
                y >>= 1;
            }
            return z;
        }

        /// <summary>
        /// The operation of squaring a matrix 16*16
        /// </summary>
        /// <param name="a">Squaring matrix</param>
        /// <exception cref="ArgumentException">Matrix size is not 16*16</exception>
        private static void SquareMatrix(byte[,] a)
        {
            if (a.GetLength(0) != 16 || a.GetLength(1) != 16)
            {
                throw new ArgumentException("Size of matrix must be equals 16x16");
            }

            int i, j, k;
            byte[,] c = new byte[16, 16];

            for (i = 0; i < 16; i++)
                for (j = 0; j < 16; j++)
                {
                    c[i, j] = 0;
                    for (k = 0; k < 16; k++)
                        c[i, j] ^= Gf256Muliply(a[i, k], a[k, j]);
                }

            for (i = 0; i < 16; i++)
                for (j = 0; j < 16; j++) a[i, j] = c[i, j];
        }

        /// <summary>
        /// Filling the matrix responsible for moving 16 steps in a linear feedback shift register
        /// </summary>
        /// <param name="matrix">Filling matrix</param>
        /// <exception cref="ArgumentException">Register length is not 16 or matrix size is not 16*16</exception>
        public static void GenerateMatrix(byte[,] matrix)
        {
            if (register.Length != 16)
                throw new ArgumentException("Size of linear register must be equals 16");

            if (matrix.GetLength(0) != 16 || matrix.GetLength(1) != 16)
            {
                throw new ArgumentException("Size of matrix must be equals 16x16");
            }

            for (int i = 0; i < 15; i++)
                for (int j = 0; j < 16; j++)
                {
                    if (i + 1 == j)
                        matrix[i, j] = 1;
                    else
                        matrix[i, j] = 0;
                }

            for (int i = 0; i < 16; i++)
                matrix[15, i] = register[i];

            SquareMatrix(matrix);
            SquareMatrix(matrix);
            SquareMatrix(matrix);
            SquareMatrix(matrix);
        }

        /// <summary>
        /// Key schedule algorithm
        /// </summary>
        /// <param name="key">Input key</param>
        /// <returns>Round keys</returns>
        /// <exception cref="ArgumentNullException">Key is null</exception>
        /// <exception cref="ArgumentException">Key size is not 256 bites</exception>
        public static KuznechikKeyData ScheduleKeys(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException("The key must be initialized");

            if (key.Length != 32)
                throw new ArgumentException("The key size must be 256 bit");

            Vector128<byte>[] Key = new Vector128<byte>[10];

            Vector128<byte> iter_1, iter_2, iter_3, iter_4;

            Key[0] = iter_1 = Vector128.Create(key, 0);
            Key[1] = iter_2 = Vector128.Create(key, 16);

            for (int i = 0; i < 4; i++)
            {
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[0 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[1 + 8 * i]);
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[2 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[3 + 8 * i]);
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[4 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[5 + 8 * i]);
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[6 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[7 + 8 * i]);

                Key[2 * i + 2] = iter_1;
                Key[2 * i + 3] = iter_2;
            }

            return new(Key);
        }

        /// <summary>
        /// Key scheduling algorithm to use fast decryption
        /// </summary>
        /// <param name="key">Input key</param>
        /// <param name="openSslCompability">Is OpenSSL compatible mode used</param>
        /// <returns>Inverse round keys</returns>
        /// <exception cref="ArgumentNullException">Key is null</exception>
        /// <exception cref="ArgumentException">Key size is not 256 bites</exception>
        public static KuznechikKeyData ScheduleInverseKeys(byte[] key, bool openSslCompability)
        {
            if (key == null)
                throw new ArgumentNullException("Ключ должен быть инициализирован");

            if (key.Length != 32)
                throw new ArgumentException("Размер ключа должен быть равен 256 битам");

            Vector128<byte>[] Key = new Vector128<byte>[10];

            Vector128<byte> iter_1, iter_2, iter_3, iter_4;

            Key[0] = iter_1 = Vector128.Create(key.Reverse().ToArray(), 0);
            iter_2 = Vector128.Create(key.Reverse().ToArray(), 16);

            Vector128<byte> arr1;
            Vector128<byte> arr2 = iter_2;
            byte[] temp = new byte[16];
            arr2 = MatrixVectorMultiply(LMatrixInv, arr2);
            arr2.CopyTo(temp);
            Key[1] = Vector128.Create(temp.Reverse().ToArray());

            for (int i = 0; i < 4; i++)
            {
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[0 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[1 + 8 * i]);
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[2 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[3 + 8 * i]);
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[4 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[5 + 8 * i]);
                Kuznechik_F(iter_1, iter_2, out iter_3, out iter_4, iter_c[6 + 8 * i]);
                Kuznechik_F(iter_3, iter_4, out iter_1, out iter_2, iter_c[7 + 8 * i]);

                arr1 = iter_1;
                arr2 = iter_2;

                arr1 = MatrixVectorMultiply(LMatrixInv, arr1);
                arr2 = MatrixVectorMultiply(LMatrixInv, arr2);

                arr1.CopyTo(temp);
                Key[2 * i + 2] = Vector128.Create(temp.Reverse().ToArray());
                arr2.CopyTo(temp);
                Key[2 * i + 3] = Vector128.Create(temp.Reverse().ToArray());
            }

            return new(Key);
        }

        /// <summary>
        /// One round of the Feistel network for key scheduling
        /// </summary>
        /// <param name="inKey1">Left part</param>
        /// <param name="inKey2">Right part</param>
        /// <param name="outKey1">Left out part</param>
        /// <param name="outKey2">Right out part</param>
        /// <param name="iterConst">Iteration constant</param>
        private static void Kuznechik_F(Vector128<byte> inKey1, Vector128<byte> inKey2, out Vector128<byte> outKey1, out Vector128<byte> outKey2, Vector128<byte> iterConst)
        {
            outKey2 = inKey1;
            outKey1 = inKey1 ^ iterConst;
            byte[] data = new byte[16];
            outKey1.CopyTo(data);
            ReverceIsLittleEndian(ref data);
            data = Kuznechik_S(data);
            LinearSteps(data);
            ReverceIsLittleEndian(ref data);
            outKey1 = Vector128.Create(data, 0) ^ inKey2;
        }

        /// <summary>
        /// Substitution operation on a byte array
        /// </summary>
        /// <param name="input">Input byte array</param>
        /// <returns>Byte array after substitution</returns>
        private static byte[] Kuznechik_S(byte[] input)
        {
            byte[] res = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                res[i] = gostPi[input[i]];
            return res;
        }

        /// <summary>
        /// Matrix-vector multiplication operation
        /// </summary>
        /// <param name="D">Matrix</param>
        /// <param name="w">Vector</param>
        /// <returns>Matrix-vector multiplication</returns>
        /// <exception cref="ArgumentException">Invalid matrix size</exception>
        private static Vector128<byte> MatrixVectorMultiply(byte[,] D, Vector128<byte> w)
        {
            if (D.GetLength(0) != 16 || D.GetLength(1) != 16)
                throw new ArgumentException("Неверные размер матрицы");

            int i = 0, j = 0;
            byte[] x = new byte[16];
            for (i = 0; i < 16; i++)
            {
                    byte z = Gf256Muliply(D[i, 0], w[15]);
                    for (j = 1; j < 16; j++) z ^= Gf256Muliply(D[i, j], w[15 - j]);
                    x[i] = z;
            }

            return Vector128.Create(x);
        }

        /// <summary>
        /// Implementation of fast round transformation of cipher
        /// </summary>
        /// <param name="wIn">Input vector</param>
        /// <returns>Vector after round</returns>
        public static unsafe Vector128<byte> FastLinearSteps(Vector128<byte> wIn)
        {
            Vector128<byte> temp  = Vector128<byte>.Zero;
            byte* w = (byte*)&wIn;
            fixed (Vector128<byte>* table = EncExpandedTable)
            {
                temp ^= table[(0 * 256) + w[15]];
                temp ^= table[(1 * 256) + w[14]];
                temp ^= table[(2 * 256) + w[13]];
                temp ^= table[(3 * 256) + w[12]];
                temp ^= table[(4 * 256) + w[11]];
                temp ^= table[(5 * 256) + w[10]];
                temp ^= table[(6 * 256) + w[9]];
                temp ^= table[(7 * 256) + w[8]];
                temp ^= table[(8 * 256) + w[7]];
                temp ^= table[(9 * 256) + w[6]];
                temp ^= table[(10 * 256) + w[5]];
                temp ^= table[(11 * 256) + w[4]];
                temp ^= table[(12 * 256) + w[3]];
                temp ^= table[(13 * 256) + w[2]];
                temp ^= table[(14 * 256) + w[1]];
                temp ^= table[(15 * 256) + w[0]];
            }
            return temp;
        }

        /// <summary>
        /// GOST approved substitution
        /// </summary>
        public static readonly byte[] gostPi = [
                                    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
                                    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
                                    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
                                    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
                                    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
                                    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
                                    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
                                    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
                                    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
                                    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
                                    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
                                    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
                                    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
                                    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
                                    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
                                    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
                               ];

        /// <summary>
        /// LFSR coefficient values
        /// </summary>
        private static readonly byte[] register = [0x01, 0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB, 0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94];
        /// <summary>
        /// Array of constants for generating round keys
        /// </summary>
        private static readonly Vector128<byte>[] iter_c;
        /// <summary>
        /// Reverse 16 round LFSR Matrix
        /// </summary>
        public static readonly byte[,] LMatrixInv;
        /// <summary>
        /// Mast encrypting matrix
        /// </summary>
        public static readonly Vector128<byte>[] EncExpandedTable;
        /// <summary>
        /// Fast inverce byte order mask
        /// </summary>
        public static readonly Vector128<byte> mask = Vector128.Create((byte)15, (byte)14, (byte)13, (byte)12, (byte)11, (byte)10, (byte)9, (byte)8,
                                                (byte)7, (byte)6, (byte)5, (byte)4, (byte)3, (byte)2, (byte)1, (byte)0);

        static KuznechikHelpFunctions()
        {
            iter_c = new Vector128<byte>[32];
            byte[] iternum = new byte[16];
            for (byte i = 0; i < 32;)
            {
                iternum[0] = ++i;
                for (int j = 1; j < 16; j++)
                    iternum[j] = 0;

                LinearSteps(iternum);
                ReverceIsLittleEndian(ref iternum);

                iter_c[i - 1] = Vector128.Create(iternum, 0);
            }

            byte[,] LMatrix = new byte[16, 16];

            GenerateMatrix(LMatrix);

            LMatrixInv = new byte[16, 16];

            for (int i = 0; i < 16; i++)
                for (int j = 0; j < 16; j++)
                    LMatrixInv[i, j] = LMatrix[15 - i, 15 - j];


            

            EncExpandedTable = new Vector128<byte>[16*256];

            byte[] sumData = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 256; j++)
                {
                    Array.Clear(sumData);
                    for (int l = 0; l < 16; l++)
                    {
                        sumData[15 - l] = Gf256Muliply(LMatrix[l, i], gostPi[j]);
                    }
                    EncExpandedTable[i*256+j] = Vector128.Create(sumData);
                }
            }
        }
    }
}
