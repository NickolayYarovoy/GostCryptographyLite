using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    internal sealed class KuznechikDecryptor : ICryptoTransform
    {
        /// <summary>
        /// Размер блока в байтах
        /// </summary>
        private const int BlockSizeBytes = 16;

        private GostCipherMode GostCipherMode;
        private PaddingMode paddingMode;
        private KuznechikKeyData encKey = null!;
        private KuznechikKeyData decKey = null!;
        private byte[]? iv;
        private byte[]? startIv;
        private byte[] lastBlock;

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => BlockSizeBytes;

        public int OutputBlockSize => BlockSizeBytes;


        /// <summary>
        /// Матрица, используемая для быстрого шифрования блоков
        /// </summary>
        private Vector128<byte>[] DecExpandedTable { get; set; }
        private bool OpenSslCompability;
        private static readonly byte[] gostPiInv;
        private static readonly Vector128<byte> mask = Vector128.Create((byte)15, (byte)14, (byte)13, (byte)12, (byte)11, (byte)10, (byte)9, (byte)8,
                                                (byte)7, (byte)6, (byte)5, (byte)4, (byte)3, (byte)2, (byte)1, (byte)0);

        static KuznechikDecryptor()
        {
            gostPiInv = new byte[256];
            for (int i = 0; i < 256; i++)
                gostPiInv[KuzhnechicHelpFunctions.gostPi[i]] = (byte)i;
        }

        public KuznechikDecryptor(byte[] Key, byte[]? IV, GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslCompability)
        {
            if (Key == null)
                throw new ArgumentNullException("Ключ должен быть инициализирован");

            if (Key.Length != 32)
                throw new ArgumentException("Размер ключа должен быть равен 256 битам");

            if (GostCipherMode == GostCipherMode.CTS)
                throw new ArgumentException("Данный режим работы не поддерживается");

            if (paddingMode != PaddingMode.PKCS7)
                throw new ArgumentException("Данный режим заполнения не поддерживается");

            iv = null;

            if (GostCipherMode == GostCipherMode.CBC || GostCipherMode == GostCipherMode.CFB || GostCipherMode == GostCipherMode.OFB)
            {
                if (IV == null || IV.Length == 0)
                    throw new ArgumentNullException("При работе в режимах CTR, CBC, OFB и CFB необходим вектор инициализации");
                if (IV.Length % 16 != 0)
                    throw new ArgumentNullException("Размер вектора инициализации должен быть кратен 128 битам");

                if (openSslCompability)
                    iv = IV.ToArray();
                else
                {
                    iv = new byte[IV.Length];
                    for (int j = 0; j < IV.Length; j += 16)
                    {
                        for (int i = 0; i < 16; i++)
                            iv[j + i] = IV[j + 15 - i];
                    }
                }
            }
            if (GostCipherMode == GostCipherMode.CTR)
            {
                if (IV == null || IV.Length == 0)
                    throw new ArgumentNullException("При работе в режимах CTR, CBC, OFB и CFB необходим вектор инициализации");
                if (IV.Length != 8 && IV.Length != 16)
                    throw new ArgumentNullException("Размер вектора инициализации в режиме CTR должен составлять 64 бита");

                if (IV.Length == 16)
                    for (int i = 8; i < 16; i++)
                        if (IV[i] != 0)
                            throw new ArgumentNullException("Размер вектора инициализации в режиме CTR должен составлять 64 бита");

                iv = new byte[16];

                Array.Clear(iv!);

                if (openSslCompability)
                    Array.Copy(IV.Reverse().ToArray(), 0, iv!, 8, 8);
                else
                    Array.Copy(IV, 0, iv!, 8, 8);

                startIv = iv.ToArray();
            }

            startIv = iv?.ToArray();

            this.GostCipherMode = GostCipherMode;
            this.paddingMode = paddingMode;

            OpenSslCompability = openSslCompability;

            // Заполнение развернутой таблицы
            DecExpandedTable = new Vector128<byte>[16 * 256];
            byte[] sumData = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 256; j++)
                {
                    for (int l = 0; l < 16; l++)
                    {
                        sumData[l] = KuzhnechicHelpFunctions.Gf256Muliply(KuzhnechicHelpFunctions.LMatrixInv[15-l, i], gostPiInv[j]);
                    }
                    DecExpandedTable[i * 256 + j] = Vector128.Create(sumData);
                }
            }

            if (OpenSslCompability)
                decKey = KuzhnechicHelpFunctions.ScheduleInverseKeys(Key.Reverse().ToArray(), openSslCompability);
            else
                decKey = KuzhnechicHelpFunctions.ScheduleInverseKeys(Key, openSslCompability);

            if (OpenSslCompability)
                encKey = KuzhnechicHelpFunctions.ScheduleKeys(Key);
            else
                encKey = KuzhnechicHelpFunctions.ScheduleKeys(Key.Reverse().ToArray());
            lastBlock = new byte[BlockSizeBytes];
        }

        public void Dispose()
        {
        }

        public void Clear()
        {
            encKey.Clear();
            decKey.Clear();
            if (iv != null)
            {
                for (int i = 0; i < iv.Length; i++)
                {
                    iv[i] = 0;
                    startIv![i] = 0;
                }
            }
            for (int i = 0; i < lastBlock.Length; i++)
            {
                lastBlock[i] = 0;
            }
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (!(inputCount % BlockSizeBytes == 0))
                throw new ArgumentException("Некорректный размер блока.");
            Vector128<byte> block = Vector128.Create((byte)0);

            if (GostCipherMode == GostCipherMode.CTR)
            {
                Vector128<UInt64> plus = Vector128.Create([1ul, 0ul]);
                Vector128<UInt64> perenos = Vector128.Create([0ul, 1ul]);
                Vector128<byte> ctr = Vector128.Create(iv!);
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    block = EncryptBlock(Vector128.Shuffle(ctr, mask));

                    if(OpenSslCompability)
                        for (int j = 0; j < 16; j++)
                            outputBuffer[outputOffset + i + j] = (byte)(inputBuffer[inputOffset + i + j] ^ block[j]);
                    else
                        for (int j = 0; j < 16; j++)
                            outputBuffer[outputOffset + i + j] = (byte)(inputBuffer[inputOffset + i + j] ^ block[15 - j]);

                    var temp = ctr.AsUInt64() + plus;
                    if (temp[0] == 0)
                        temp += perenos;

                    ctr = temp.AsByte();
                }
                ctr.CopyTo(iv!);
            }
            else
            {
                byte[] bl = new byte[BlockSizeBytes];
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    if (GostCipherMode == GostCipherMode.CFB || GostCipherMode == GostCipherMode.OFB)
                    {
                        block = Vector128.Create(iv!);

                        block = EncryptBlock(block);

                        if (i != inputCount - 16)
                        {
                            if (OpenSslCompability)
                                block.CopyTo(outputBuffer, outputOffset + i);
                            else
                                for (int j = 0; j < 16; j++)
                                   Vector128.Shuffle(block, mask).CopyTo(outputBuffer, outputOffset + i);

                            for (int j = 0; j < 16; j++)
                                outputBuffer[outputOffset + i + j] ^= inputBuffer[i + j + inputOffset];
                        }
                        else
                        {
                            if (OpenSslCompability)
                                block.CopyTo(lastBlock, 0);
                            else
                                for (int j = 0; j < 16; j++)
                                    Vector128.Shuffle(block, mask).CopyTo(lastBlock, 0);

                            for (int j = 0; j < 16; j++)
                                lastBlock[j] ^= inputBuffer[i + j + inputOffset];
                        }

                        Array.Copy(iv!, 16, iv!, 0, iv!.Length - 16);

                        if (GostCipherMode == GostCipherMode.CFB)
                        {
                            if (OpenSslCompability)
                                Array.Copy(inputBuffer, inputOffset + i, iv!, iv!.Length - 16, 16);
                            else
                                for (int j = 1; j <= 16; j++)
                                    iv![iv!.Length - j] = inputBuffer[i + j + inputOffset - 1];
                        }
                        else
                            block.CopyTo(iv!, iv!.Length - 16);
                    }
                    else
                    {
                        block = Vector128.Create(inputBuffer, inputOffset + i);

                        if (OpenSslCompability)
                            block = DecryptBlock(block, bl);
                        else
                            block = Vector128.Shuffle(DecryptBlock(Vector128.Shuffle(block, mask), bl), mask);

                        if (i != inputCount - 16)
                        {
                            block.CopyTo(outputBuffer, outputOffset + i);

                            if (GostCipherMode == GostCipherMode.CBC)
                            {
                                for (int j = 0; j < 16; j++)
                                {
                                    if (OpenSslCompability || i >= 32)
                                        outputBuffer[outputOffset + i + j] ^= iv![j];
                                    else
                                        outputBuffer[outputOffset + i + j] ^= iv![15 - j];
                                }
                            }
                        }
                        else
                        {
                            block.CopyTo(lastBlock, 0);

                            if (GostCipherMode == GostCipherMode.CBC)
                            {
                                for (int j = 0; j < 16; j++)
                                {
                                    if (OpenSslCompability || i >= 32)
                                        lastBlock[j] ^= iv![j];
                                    else
                                        lastBlock[j] ^= iv![15 - j];
                                }
                            }
                        }

                        if (GostCipherMode == GostCipherMode.CBC)
                        {
                            Array.Copy(iv!, 16, iv!, 0, iv!.Length - 16);
                            for (int j = iv!.Length - 16, k = 0; j < iv!.Length; j++, k++)
                                iv[j] = inputBuffer[inputOffset + i + k];
                        }
                    }
                }
            }
            return inputCount - BlockSizeBytes;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] outputBuffer = new byte[BlockSizeBytes];
            Vector128<byte> block;
            byte[] res;
            if (inputCount == 0)
            {
                if(GostCipherMode == GostCipherMode.CTR)
                    return lastBlock;

                if (paddingMode == PaddingMode.PKCS7)
                {
                    if (lastBlock[15] <= 0 || lastBlock[15] > 16)
                        throw new CryptographicException("Неверная длина дополнения");

                    for (int i = 1; i < lastBlock[15]; i++)
                        if (lastBlock[15] != lastBlock[15 - i])
                            throw new CryptographicException("Неверное дополнение");

                    res = new byte[BlockSizeBytes - lastBlock[15]];
                    Array.Copy(lastBlock, res, BlockSizeBytes - lastBlock[15]);
                    if (iv != null)
                        Array.Copy(startIv!, iv, iv.Length);
                    return res;
                }
                throw new ArgumentException("Некорректный тип дополнения");
            }
            else
            {
                if (GostCipherMode == GostCipherMode.CTR)
                {
                    Vector128<byte> ctr = Vector128.Create(iv!);
                    block = EncryptBlock(Vector128.Shuffle(ctr, mask));

                    if (OpenSslCompability)
                        for (int j = 0; j < inputCount; j++)
                            outputBuffer[j] = (byte)(inputBuffer[inputOffset + j] ^ block[j]);
                    else
                        for (int j = 0; j < inputCount; j++)
                            outputBuffer[j] = (byte)(inputBuffer[inputOffset + j] ^ block[15 - j]);

                    startIv!.CopyTo(iv!, 0);
                    return outputBuffer;
                }
                else
                    throw new ArgumentException("Некорректный размер блока");
            }
        }

        /// <summary>
        /// Метод шифрования одного блока данных
        /// </summary>
        /// <param name="block">Шифруемый блок даннных</param>
        /// <returns></returns>
        private Vector128<byte> EncryptBlock(Vector128<byte> block)
        {
            Vector128<byte> num = block;

            for (int i = 0; i < 9; i++)
            {
                num ^= encKey.Key[i];
                num ^= encKey.Key[i + 10];
                num = KuzhnechicHelpFunctions.FastLinearSteps(num);
            }

            num ^= encKey.Key[9];
            num ^= encKey.Key[19];

            return num;
        }

        private unsafe Vector128<byte> DecryptBlock(Vector128<byte> block, byte[] bl)
        {
            block.CopyTo(bl, 0);
            for(int i = 0; i < 16; i++)
                bl[i] = KuzhnechicHelpFunctions.gostPi[bl[i]];

            Vector128<byte> b = Vector128.Create(bl), ts;
            byte* bPtr = (byte*)&b;

            fixed (Vector128<byte>* decTable = DecExpandedTable)
                for (int i = 9; i >= 1; i--)
                {
                    ts = Vector128<byte>.Zero;
                    ts ^= decTable[0 * 256 + bPtr[15]];
                    ts ^= decTable[1 * 256 + bPtr[14]];
                    ts ^= decTable[2 * 256 + bPtr[13]];
                    ts ^= decTable[3 * 256 + bPtr[12]];
                    ts ^= decTable[4 * 256 + bPtr[11]];
                    ts ^= decTable[5 * 256 + bPtr[10]];
                    ts ^= decTable[6 * 256 + bPtr[9]];
                    ts ^= decTable[7 * 256 + bPtr[8]];
                    ts ^= decTable[8 * 256 + bPtr[7]];
                    ts ^= decTable[9 * 256 + bPtr[6]];
                    ts ^= decTable[10 * 256 + bPtr[5]];
                    ts ^= decTable[11 * 256 + bPtr[4]];
                    ts ^= decTable[12 * 256 + bPtr[3]];
                    ts ^= decTable[13 * 256 + bPtr[2]];
                    ts ^= decTable[14 * 256 + bPtr[1]];
                    ts ^= decTable[15 * 256 + bPtr[0]];

                    b = ts;
                    b ^= decKey.Key[i];
                    b ^= decKey.Key[i + 10];
                }

            for (int i = 0; i < 16; i++)
                bl[i] = gostPiInv[bPtr[i]];

            b = Vector128.Create(bl);
            b ^= decKey.Key[0];
            b ^= decKey.Key[10];

            return b;
        }
    }
}
