using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace GostCryptographyLite
{
    /// <summary>
    /// A class implementing Magma decryptors
    /// </summary>
    internal class MagmaDecryptor : ICryptoTransform
    {
        /// <summary>
        /// Block size in bytes
        /// </summary>
        private const int BlockSizeBytes = 8;
        /// <summary>
        /// Cipher mode
        /// </summary>
        private GostCipherMode GostCipherMode;
        // <summary>
        /// Padding mode
        /// </summary>
        private PaddingMode paddingMode;
        /// <summary>
        /// The sheduled masked keys used for encrypting the data block.
        /// </summary>
        private MagmaKeyData key;
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
        /// OpenSSL compability mode (true - OpenSSL compability, false - GOST compability)
        /// </summary>
        private bool OpenSslCompability;

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => BlockSizeBytes;

        public int OutputBlockSize => BlockSizeBytes;

        public MagmaDecryptor(byte[] Key, byte[]? IV, GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslCompability)
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
                    throw new ArgumentNullException("The IV size must be a multiple of 64 bits");

                iv = new byte[IV.Length];
                IV.CopyTo(iv, 0);
            }
            if (GostCipherMode == GostCipherMode.CTR)
            {
                if (IV == null || IV.Length == 0)
                    throw new ArgumentNullException("An initialization vector is required when operating in CTR, CBC, OFB, and CFB modes");
                if (IV.Length != 4 && IV.Length != 8)
                    throw new ArgumentNullException("The IV size must be 32 bits");

                if (IV.Length == 8)
                    for (int i = 4; i < 8; i++)
                        if (IV[i] != 0)
                            throw new ArgumentNullException("The IV size must be 32 bits");

                iv = new byte[8];

                Array.Clear(iv!);

                if (openSslCompability)
                    Array.Copy(IV, iv, 4);
                else
                    for (int j = 0; j < 4; j++)
                        iv[j] = IV[3 - j];
            }

            OpenSslCompability = openSslCompability;

            uint[] startKeys = new uint[8];

            if (OpenSslCompability ^ !BitConverter.IsLittleEndian)
                Key = Key.Reverse().ToArray();

            for (int i = 0; i < 8; i++)
            {
                if (BitConverter.IsLittleEndian)
                    startKeys[i] = BitConverter.ToUInt32(Key, i << 2);
                else
                    startKeys[7 - i] = BitConverter.ToUInt32(Key, i << 2);
            }
            key = new(startKeys);

            startIv = iv?.ToArray();

            this.GostCipherMode = GostCipherMode;
            this.paddingMode = paddingMode;

            lastBlock = new byte[8];
            isFirstBlock = true;
        }

        /// <summary>
        /// Method for decrypting a single block of data
        /// </summary>
        /// <param name="block">Decrypting block of data</param>
        /// <returns>Decrypted block</returns>
        private byte[] DecryptBlock(byte[] data)
        {
            byte[] path = new byte[34];
            uint mv = unchecked((uint)path.GetHashCode());

            for (int i = 1; i <= 32; i++)
            {
                path[i] = (byte)(mv & 1);
                mv >>= 1;
            }

            path[0] = path[33] = 0;

            uint n3, n4, p = 0;

            if (BitConverter.IsLittleEndian ^ OpenSslCompability)
            {
                n3 = BitConverter.ToUInt32(data) ^ (0xFFFFFFFF * path[1]);
                n4 = BitConverter.ToUInt32(data, 4);
            }
            else
            {
                n4 = reverse(BitConverter.ToUInt32(data));
                n3 = reverse(BitConverter.ToUInt32(data, 4) ^ (0xFFFFFFFF * path[1]));
            }

            p = n3; p -= key.mask[path[1]][7]; p += key.maskedKey[path[1]][7] + path[1]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[2] ^ path[0], path[1]);
            p = n4; p -= key.mask[path[2]][6]; p += key.maskedKey[path[2]][6] + path[2]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[3] ^ path[1], path[2]);
            p = n3; p -= key.mask[path[3]][5]; p += key.maskedKey[path[3]][5] + path[3]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[4] ^ path[2], path[3]);
            p = n4; p -= key.mask[path[4]][4]; p += key.maskedKey[path[4]][4] + path[4]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[5] ^ path[3], path[4]);
            p = n3; p -= key.mask[path[5]][3]; p += key.maskedKey[path[5]][3] + path[5]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[6] ^ path[4], path[5]);
            p = n4; p -= key.mask[path[6]][2]; p += key.maskedKey[path[6]][2] + path[6]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[7] ^ path[5], path[6]);
            p = n3; p -= key.mask[path[7]][1]; p += key.maskedKey[path[7]][1] + path[7]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[8] ^ path[6], path[7]);
            p = n4; p -= key.mask[path[8]][0]; p += key.maskedKey[path[8]][0] + path[8]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[9] ^ path[7], path[8]);

            p = n3; p -= key.mask[path[9]][ 0]; p += key.maskedKey[path[9]][ 0] + path[9]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[10] ^ path[8], path[9]);
            p = n4; p -= key.mask[path[10]][1]; p += key.maskedKey[path[10]][1] + path[10]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[11] ^ path[9], path[10]);
            p = n3; p -= key.mask[path[11]][2]; p += key.maskedKey[path[11]][2] + path[11]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[12] ^ path[10], path[11]);
            p = n4; p -= key.mask[path[12]][3]; p += key.maskedKey[path[12]][3] + path[12]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[13] ^ path[11], path[12]);
            p = n3; p -= key.mask[path[13]][4]; p += key.maskedKey[path[13]][4] + path[13]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[14] ^ path[12], path[13]);
            p = n4; p -= key.mask[path[14]][5]; p += key.maskedKey[path[14]][5] + path[14]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[15] ^ path[13], path[14]);
            p = n3; p -= key.mask[path[15]][6]; p += key.maskedKey[path[15]][6] + path[15]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[16] ^ path[14], path[15]);
            p = n4; p -= key.mask[path[16]][7]; p += key.maskedKey[path[16]][7] + path[16]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[17] ^ path[15], path[16]);

            p = n3; p -= key.mask[path[17]][0]; p += key.maskedKey[path[17]][0] + path[17]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[18] ^ path[16], path[17]);
            p = n4; p -= key.mask[path[18]][1]; p += key.maskedKey[path[18]][1] + path[18]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[19] ^ path[17], path[18]);
            p = n3; p -= key.mask[path[19]][2]; p += key.maskedKey[path[19]][2] + path[19]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[20] ^ path[18], path[19]);
            p = n4; p -= key.mask[path[20]][3]; p += key.maskedKey[path[20]][3] + path[20]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[21] ^ path[19], path[20]);
            p = n3; p -= key.mask[path[21]][4]; p += key.maskedKey[path[21]][4] + path[21]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[22] ^ path[20], path[21]);
            p = n4; p -= key.mask[path[22]][5]; p += key.maskedKey[path[22]][5] + path[22]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[23] ^ path[21], path[22]);
            p = n3; p -= key.mask[path[23]][6]; p += key.maskedKey[path[23]][6] + path[23]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[24] ^ path[22], path[23]);
            p = n4; p -= key.mask[path[24]][7]; p += key.maskedKey[path[24]][7] + path[24]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[25] ^ path[23], path[24]);

            p = n3; p -= key.mask[path[25]][0]; p += key.maskedKey[path[25]][0] + path[25]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[26] ^ path[24], path[25]);
            p = n4; p -= key.mask[path[26]][1]; p += key.maskedKey[path[26]][1] + path[26]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[27] ^ path[25], path[26]);
            p = n3; p -= key.mask[path[27]][2]; p += key.maskedKey[path[27]][2] + path[27]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[28] ^ path[26], path[27]);
            p = n4; p -= key.mask[path[28]][3]; p += key.maskedKey[path[28]][3] + path[28]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[29] ^ path[27], path[28]);
            p = n3; p -= key.mask[path[29]][4]; p += key.maskedKey[path[29]][4] + path[29]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[30] ^ path[28], path[29]);
            p = n4; p -= key.mask[path[30]][5]; p += key.maskedKey[path[30]][5] + path[30]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[31] ^ path[29], path[30]);
            p = n3; p -= key.mask[path[31]][6]; p += key.maskedKey[path[31]][6] + path[31]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[32] ^ path[30], path[31]);
            p = n4; p -= key.mask[path[32]][7]; p += key.maskedKey[path[32]][7] + path[32]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[33] ^ path[31], path[32]);

            return FillArray(n3, n4, path[32]);
        }

        /// <summary>
        /// Fast filling output array
        /// </summary>
        /// <param name="n3">Right block</param>
        /// <param name="n4">Left block</param>
        /// <param name="path">Now path</param>
        /// <returns></returns>
        private unsafe byte[] FillArray(uint n3, uint n4, byte path)
        {
            byte[] res = new byte[8];
            fixed (byte* resBytePtr = res)
            {
                uint* resPtr = (uint*)resBytePtr;
                if (BitConverter.IsLittleEndian ^ OpenSslCompability)
                {
                    resPtr[0] = n4 ^ (path * 0xffffffff);
                    resPtr[1] = n3;
                }
                else
                {
                    resPtr[0] = reverse(n3);
                    resPtr[1] = reverse(n4 ^ (path * 0xffffffff));
                }
            }
            return res;
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (inputCount % 8 != 0)
                throw new ArgumentException("The input size must be a multiple of 64");

            if (!isFirstBlock && GostCipherMode != GostCipherMode.CTR)
            {
                lastBlock.CopyTo(outputBuffer, outputOffset);
                outputOffset += BlockSizeBytes;
            }

            byte[] block = new byte[BlockSizeBytes];
            if (GostCipherMode == GostCipherMode.ECB || GostCipherMode == GostCipherMode.CBC)
            {
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    Array.Copy(inputBuffer, inputOffset + i, block, 0, BlockSizeBytes);
                    block = DecryptBlock(block);

                    if (GostCipherMode == GostCipherMode.CBC)
                    {
                        for (int j = 0; j < 8; j++)
                            block[j] ^= iv![j];

                        Array.Copy(iv!, 8, iv!, 0, iv!.Length - 8);
                        Array.Copy(inputBuffer, inputOffset + i, iv!, iv!.Length - 8, block.Length);
                    }

                    if (i != inputCount - 8)
                    {
                        Array.Copy(block, 0, outputBuffer, outputOffset + i, block.Length);
                    }
                    else
                    {
                        block.CopyTo(lastBlock, 0);
                    }
                }
            }
            else if(GostCipherMode == GostCipherMode.OFB || GostCipherMode == GostCipherMode.CFB)
            {
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    Array.Copy(iv!, 0, block, 0, 8);

                    block = EncryptBlock(block);

                    Array.Copy(iv!, 8, iv!, 0, iv!.Length - 8);

                    if (GostCipherMode == GostCipherMode.OFB)
                        Array.Copy(block, 0, iv!, iv!.Length - 8, block.Length);

                    for (int j = 0; j < 8; j++)
                    {
                        block[j] ^= inputBuffer[inputOffset + i + j];
                    }
                    if (i < inputCount - 8)
                        Array.Copy(block, 0, outputBuffer, outputOffset + i, block.Length);
                    else
                        block.CopyTo(lastBlock, 0);

                    if (GostCipherMode == GostCipherMode.CFB)
                        Array.Copy(inputBuffer, inputOffset + i, iv!, iv.Length - 8, 8);
                }
            }
            else
            {
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    block = EncryptBlock(iv!);

                    for (int j = 0; j + i < inputCount && j < 8; j++)
                    {
                        outputBuffer[outputOffset + j + i] = (byte)(block[j] ^ inputBuffer[inputOffset + j + i]);
                    }

                    MagmaHelpFunctions.FastArrayIncrement(iv!);
                }
            }

            if (isFirstBlock && GostCipherMode != GostCipherMode.CTR)
            {
                isFirstBlock = false;
                return inputCount - BlockSizeBytes;
            }
            else
                return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {
            byte[] outputBuffer = new byte[BlockSizeBytes];
            isFirstBlock = true;
            byte[] res;
            if (inputCount == 0)
            {
                if (GostCipherMode == GostCipherMode.CTR)
                {
                    Array.Copy(startIv!, iv!, iv!.Length);
                    return [];
                }

                if (paddingMode == PaddingMode.PKCS7)
                {
                    if (lastBlock[7] <= 0 || lastBlock[7] > 8)
                        throw new CryptographicException("Incorrect padding");

                    for (int i = 1; i < lastBlock[7]; i++)
                        if (lastBlock[7] != lastBlock[7 - i])
                            throw new CryptographicException("Incorrect padding");

                    res = new byte[BlockSizeBytes - lastBlock[7]];
                    Array.Copy(lastBlock, res, BlockSizeBytes - lastBlock[7]);
                    if (iv != null)
                        Array.Copy(startIv!, iv, iv.Length);
                    return res;
                }
                throw new ArgumentException("Incorrect padding mode");
            }
            else if(GostCipherMode == GostCipherMode.CTR)
            {
                byte[] block = new byte[8];
                block = EncryptBlock(iv!);
                outputBuffer = new byte[inputCount];

                for (int j = 0; j < inputCount && j < 8; j++)
                {
                    outputBuffer[j] = (byte)(block[j] ^ inputBuffer[inputOffset + j]);
                }
                return outputBuffer;
            }

            return outputBuffer;
        }

        /// <summary>
        /// Empty, as unmanaged resources are not used.
        /// </summary>
        public void Dispose()
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Clearing of key information and information about decoded blocks.
        /// </summary>
        public void Clear()
        {
            key.Clear();
            key = null!;
            if (iv != null)
            {
                Array.Clear(iv);
                Array.Clear(startIv!);
                iv = null;
                startIv = null;
            }
        }

        /// <summary>
        /// Reversing uint byte order
        /// </summary>
        /// <param name="x">Input data</param>
        /// <returns>uint with inversed byte order</returns>
        private static uint reverse(uint x)
        {
            x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
            x = ((x >> 16) & 0xffffu) | ((x & 0xffffu) << 16);
            return x;
        }

        /// <summary>
        /// Method for encrypting a single block of data
        /// </summary>
        /// <param name="block">Encrypting block of data</param>
        /// <returns>Encrypted block</returns>
        private byte[] EncryptBlock(byte[] data)
        {
            byte[] path = new byte[34];
            uint mv = unchecked((uint)path.GetHashCode());

            for (int i = 1; i <= 32; i++)
            {
                path[i] = (byte)(mv & 1);
                mv >>= 1;
            }

            path[0] = path[33] = 0;

            uint n3, n4, p = 0;

            if (BitConverter.IsLittleEndian ^ (OpenSslCompability ||  GostCipherMode == GostCipherMode.CTR))
            {
                n3 = BitConverter.ToUInt32(data) ^ (0xFFFFFFFF * path[1]);
                n4 = BitConverter.ToUInt32(data, 4);
            }
            else
            {
                n4 = reverse(BitConverter.ToUInt32(data));
                n3 = reverse(BitConverter.ToUInt32(data, 4)) ^ (0xFFFFFFFF * path[1]);
            }

            p = n3; p -= key.mask[path[1]][7]; p += key.maskedKey[path[1]][7] + path[1]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[2] ^ path[0], path[1]);
            p = n4; p -= key.mask[path[2]][6]; p += key.maskedKey[path[2]][6] + path[2]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[3] ^ path[1], path[2]);
            p = n3; p -= key.mask[path[3]][5]; p += key.maskedKey[path[3]][5] + path[3]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[4] ^ path[2], path[3]);
            p = n4; p -= key.mask[path[4]][4]; p += key.maskedKey[path[4]][4] + path[4]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[5] ^ path[3], path[4]);
            p = n3; p -= key.mask[path[5]][3]; p += key.maskedKey[path[5]][3] + path[5]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[6] ^ path[4], path[5]);
            p = n4; p -= key.mask[path[6]][2]; p += key.maskedKey[path[6]][2] + path[6]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[7] ^ path[5], path[6]);
            p = n3; p -= key.mask[path[7]][1]; p += key.maskedKey[path[7]][1] + path[7]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[8] ^ path[6], path[7]);
            p = n4; p -= key.mask[path[8]][0]; p += key.maskedKey[path[8]][0] + path[8]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[9] ^ path[7], path[8]);

            p = n3; p -= key.mask[path[9]][7]; p += key.maskedKey[path[9]][7] + path[9]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[10] ^ path[8], path[9]);
            p = n4; p -= key.mask[path[10]][6]; p += key.maskedKey[path[10]][6] + path[10]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[11] ^ path[9], path[10]);
            p = n3; p -= key.mask[path[11]][5]; p += key.maskedKey[path[11]][5] + path[11]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[12] ^ path[10], path[11]);
            p = n4; p -= key.mask[path[12]][4]; p += key.maskedKey[path[12]][4] + path[12]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[13] ^ path[11], path[12]);
            p = n3; p -= key.mask[path[13]][3]; p += key.maskedKey[path[13]][3] + path[13]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[14] ^ path[12], path[13]);
            p = n4; p -= key.mask[path[14]][2]; p += key.maskedKey[path[14]][2] + path[14]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[15] ^ path[13], path[14]);
            p = n3; p -= key.mask[path[15]][1]; p += key.maskedKey[path[15]][1] + path[15]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[16] ^ path[14], path[15]);
            p = n4; p -= key.mask[path[16]][0]; p += key.maskedKey[path[16]][0] + path[16]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[17] ^ path[15], path[16]);

            p = n3; p -= key.mask[path[17]][7]; p += key.maskedKey[path[17]][7] + path[17]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[18] ^ path[16], path[17]);
            p = n4; p -= key.mask[path[18]][6]; p += key.maskedKey[path[18]][6] + path[18]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[19] ^ path[17], path[18]);
            p = n3; p -= key.mask[path[19]][5]; p += key.maskedKey[path[19]][5] + path[19]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[20] ^ path[18], path[19]);
            p = n4; p -= key.mask[path[20]][4]; p += key.maskedKey[path[20]][4] + path[20]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[21] ^ path[19], path[20]);
            p = n3; p -= key.mask[path[21]][3]; p += key.maskedKey[path[21]][3] + path[21]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[22] ^ path[20], path[21]);
            p = n4; p -= key.mask[path[22]][2]; p += key.maskedKey[path[22]][2] + path[22]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[23] ^ path[21], path[22]);
            p = n3; p -= key.mask[path[23]][1]; p += key.maskedKey[path[23]][1] + path[23]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[24] ^ path[22], path[23]);
            p = n4; p -= key.mask[path[24]][0]; p += key.maskedKey[path[24]][0] + path[24]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[25] ^ path[23], path[24]);

            p = n3; p -= key.mask[path[25]][0]; p += key.maskedKey[path[25]][0] + path[25]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[26] ^ path[24], path[25]);
            p = n4; p -= key.mask[path[26]][1]; p += key.maskedKey[path[26]][1] + path[26]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[27] ^ path[25], path[26]);
            p = n3; p -= key.mask[path[27]][2]; p += key.maskedKey[path[27]][2] + path[27]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[28] ^ path[26], path[27]);
            p = n4; p -= key.mask[path[28]][3]; p += key.maskedKey[path[28]][3] + path[28]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[29] ^ path[27], path[28]);
            p = n3; p -= key.mask[path[29]][4]; p += key.maskedKey[path[29]][4] + path[29]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[30] ^ path[28], path[29]);
            p = n4; p -= key.mask[path[30]][5]; p += key.maskedKey[path[30]][5] + path[30]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[31] ^ path[29], path[30]);
            p = n3; p -= key.mask[path[31]][6]; p += key.maskedKey[path[31]][6] + path[31]; n4 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[32] ^ path[30], path[31]);
            p = n4; p -= key.mask[path[32]][7]; p += key.maskedKey[path[32]][7] + path[32]; n3 ^= MagmaHelpFunctions.MagmaGostFBoxes(p, path[33] ^ path[31], path[32]);

            byte[] res = new byte[8];

            if (BitConverter.IsLittleEndian ^ OpenSslCompability)
            {
                BitConverter.GetBytes(n4 ^ (path[32] * 0xffffffff)).CopyTo(res, 0);
                BitConverter.GetBytes(n3).CopyTo(res, 4);
            }
            else
            {
                BitConverter.GetBytes(reverse(n3)).CopyTo(res, 0);
                BitConverter.GetBytes(reverse(n4 ^ (path[32] * 0xffffffff))).CopyTo(res, 4);
            }
            return res;
        }
    }
}
