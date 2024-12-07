using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    /// <summary>
    /// A class implementing Kuznechik decryptors
    /// </summary>
    internal sealed class KuznechikDecryptor : ICryptoTransform
    {
        /// <summary>
        /// Block size in bytes
        /// </summary>
        private const int BlockSizeBytes = 16;
        /// <summary>
        /// Cipher mode
        /// </summary>
        private GostCipherMode GostCipherMode;
        /// <summary>
        /// Padding mode
        /// </summary>
        private PaddingMode paddingMode;
        /// <summary>
        /// The sheduled masked keys used for encrypting the data block.
        /// </summary>
        private KuznechikKeyData encKey = null!;
        /// <summary>
        /// The sheduled masked keys used for decrypting the data block.
        /// </summary>
        private KuznechikKeyData decKey = null!;
        /// <summary>
        /// Current IV
        /// </summary>
        private byte[]? iv;
        /// <summary>
        /// IV of clear instance
        /// </summary>
        private byte[]? startIv;
        /// <summary>
        /// Last block decrypted with TransformBlock()
        /// </summary>
        private byte[] lastBlock;
        /// <summary>
        /// Is the current block the first in the queue
        /// </summary>
        private bool isFirstBlock;
        /// <summary>
        /// Total lenght of decrypted message
        /// </summary>
        private int totalLenght;

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => BlockSizeBytes;

        public int OutputBlockSize => BlockSizeBytes;


        /// <summary>
        /// A matrix used for fast decryption of the block.
        /// </summary>
        private static Vector128<byte>[] DecExpandedTable { get; set; }
        /// <summary>
        /// OpenSSL compability mode (true - OpenSSL compability, false - GOST compability)
        /// </summary>
        private bool OpenSslCompability;
        /// <summary>
        /// A substitution inverse to the one specified in the GOST
        /// </summary>
        private static readonly byte[] gostPiInv;
        
        static KuznechikDecryptor()
        {
            gostPiInv = new byte[256];
            for (int i = 0; i < 256; i++)
                gostPiInv[KuznechikHelpFunctions.gostPi[i]] = (byte)i;

            DecExpandedTable = new Vector128<byte>[16 * 256];
            byte[] sumData = new byte[16];

            for (int i = 0; i < 16; i++)
            {
                for (int j = 0; j < 256; j++)
                {
                    for (int l = 0; l < 16; l++)
                    {
                        sumData[l] = KuznechikHelpFunctions.Gf256Muliply(KuznechikHelpFunctions.LMatrixInv[15 - l, i], gostPiInv[j]);
                    }
                    DecExpandedTable[i * 256 + j] = Vector128.Create(sumData);
                }
            }
        }

        public KuznechikDecryptor(byte[] Key, byte[]? IV, GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslCompability)
        {
            if (Key == null)
                throw new ArgumentNullException("The key must be initialized");

            if (Key.Length != 32)
                throw new ArgumentException("The key size must be 256 bit");

            if (GostCipherMode == GostCipherMode.CTS)
                throw new ArgumentException("The selected algorithm does not support this cipher mode.");

            if (paddingMode != PaddingMode.PKCS7)
                throw new ArgumentException("The selected algorithm does not support this padding mode.");

            iv = null;

            if (GostCipherMode == GostCipherMode.CBC || GostCipherMode == GostCipherMode.CFB || GostCipherMode == GostCipherMode.OFB)
            {
                if (IV == null || IV.Length == 0)
                    throw new ArgumentNullException("An initialization vector is required when operating in CTR, CBC, OFB, and CFB modes");
                if (IV.Length % 16 != 0)
                    throw new ArgumentNullException("The IV size must be a multiple of 128");

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
                    throw new ArgumentNullException("An initialization vector is required when operating in CTR, CBC, OFB, and CFB modes");
                if (IV.Length != 8 && IV.Length != 16)
                    throw new ArgumentNullException("The IV size must be 64 bits");

                if (IV.Length == 16)
                    for (int i = 8; i < 16; i++)
                        if (IV[i] != 0)
                            throw new ArgumentNullException("The IV size must be 64 bits");

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

            if (OpenSslCompability)
                decKey = KuznechikHelpFunctions.ScheduleInverseKeys(Key.Reverse().ToArray(), openSslCompability);
            else
                decKey = KuznechikHelpFunctions.ScheduleInverseKeys(Key, openSslCompability);

            if (OpenSslCompability)
                encKey = KuznechikHelpFunctions.ScheduleKeys(Key);
            else
                encKey = KuznechikHelpFunctions.ScheduleKeys(Key.Reverse().ToArray());
            lastBlock = new byte[BlockSizeBytes];
            isFirstBlock = true;
            totalLenght = 0;
        }

        /// <summary>
        /// Empty, as unmanaged resources are not used.
        /// </summary>
        public void Dispose()
        {
        }

        /// <summary>
        /// Clearing of key information and information about decoded blocks.
        /// </summary>
        public void Clear()
        {
            encKey.Clear();
            decKey.Clear();
            encKey = decKey = null!;
            if (iv != null)
            {
                for (int i = 0; i < iv.Length; i++)
                {
                    iv[i] = 0;
                    startIv![i] = 0;
                }
                iv = startIv = null;
            }
            for (int i = 0; i < lastBlock.Length; i++)
            {
                lastBlock[i] = 0;
            }
            lastBlock = null!;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (!(inputCount % BlockSizeBytes == 0))
                throw new ArgumentException("Incorrect block size");

            if (!isFirstBlock && GostCipherMode != GostCipherMode.CTR)
            {
                lastBlock.CopyTo(outputBuffer, outputOffset);
                outputOffset += BlockSizeBytes;
            }

            Vector128<byte> block = Vector128.Create((byte)0);

            if (GostCipherMode == GostCipherMode.CTR)
            {
                Vector128<UInt64> plus = Vector128.Create([1ul, 0ul]);
                Vector128<UInt64> perenos = Vector128.Create([0ul, 1ul]);
                Vector128<byte> ctr = Vector128.Create(iv!);
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    block = EncryptBlock(Vector128.Shuffle(ctr, KuznechikHelpFunctions.mask));

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
                                Vector128.Shuffle(block, KuznechikHelpFunctions.mask).CopyTo(outputBuffer, outputOffset + i);

                            for (int j = 0; j < 16; j++)
                                outputBuffer[outputOffset + i + j] ^= inputBuffer[i + j + inputOffset];
                        }
                        else
                        {
                            if (OpenSslCompability)
                                block.CopyTo(lastBlock, 0);
                            else
                                for (int j = 0; j < 16; j++)
                                    Vector128.Shuffle(block, KuznechikHelpFunctions.mask).CopyTo(lastBlock, 0);

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
                            block = Vector128.Shuffle(DecryptBlock(Vector128.Shuffle(block, KuznechikHelpFunctions.mask), bl), KuznechikHelpFunctions.mask);

                        if (i != inputCount - 16)
                        {
                            block.CopyTo(outputBuffer, outputOffset + i);

                            if (GostCipherMode == GostCipherMode.CBC)
                            {
                                for (int j = 0; j < 16; j++)
                                {
                                    if (OpenSslCompability || i + totalLenght >= 32)
                                        outputBuffer[outputOffset + i + j] ^= iv![j];
                                    else
                                        outputBuffer[outputOffset + i + j] ^= iv![15-j];
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
                                    if (OpenSslCompability || i + totalLenght >= 32)
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

            totalLenght += inputCount;

            if (isFirstBlock && GostCipherMode != GostCipherMode.CTR)
            {
                totalLenght -= BlockSizeBytes;
                isFirstBlock = false;
                return inputCount - BlockSizeBytes;
            }
            else
                return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] outputBuffer = new byte[BlockSizeBytes];
            totalLenght = 0;
            isFirstBlock = true;
            Vector128<byte> block;
            byte[] res;
            if (inputCount == 0)
            {
                if (GostCipherMode == GostCipherMode.CTR)
                {
                    Array.Copy(startIv!, iv!, iv!.Length);
                    return lastBlock;
                }

                if (paddingMode == PaddingMode.PKCS7)
                {
                    if (lastBlock[15] <= 0 || lastBlock[15] > 16)
                        throw new CryptographicException("Incorrect padding size");

                    for (int i = 1; i < lastBlock[15]; i++)
                        if (lastBlock[15] != lastBlock[15 - i])
                            throw new CryptographicException("Incorrect padding");

                    res = new byte[BlockSizeBytes - lastBlock[15]];
                    Array.Copy(lastBlock, res, BlockSizeBytes - lastBlock[15]);
                    if (iv != null)
                        Array.Copy(startIv!, iv, iv.Length);
                    return res;
                }
                throw new ArgumentException("Incorrect padding type");
            }
            else
            {
                if (GostCipherMode == GostCipherMode.CTR)
                {
                    Vector128<byte> ctr = Vector128.Create(iv!);
                    block = EncryptBlock(Vector128.Shuffle(ctr, KuznechikHelpFunctions.mask));

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
                    throw new ArgumentException("incorrect block size");
            }
        }

        /// <summary>
        /// Method for encrypting a single block of data
        /// </summary>
        /// <param name="block">Encrypting block of data</param>
        /// <returns>Encrypted block</returns>
        private Vector128<byte> EncryptBlock(Vector128<byte> block)
        {
            Vector128<byte> num = block;

            for (int i = 0; i < 9; i++)
            {
                num ^= encKey.Key[i];
                num ^= encKey.Key[i + 10];
                num = KuznechikHelpFunctions.FastLinearSteps(num);
            }

            num ^= encKey.Key[9];
            num ^= encKey.Key[19];

            return num;
        }

        /// <summary>
        /// Method for decrypting a single block of data
        /// </summary>
        /// <param name="block">Decrypting block of data</param>
        /// <returns>Decrypdet block</returns>
        private unsafe Vector128<byte> DecryptBlock(Vector128<byte> block, byte[] bl)
        {
            block.CopyTo(bl, 0);
            for(int i = 0; i < 16; i++)
                bl[i] = KuznechikHelpFunctions.gostPi[bl[i]];

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
