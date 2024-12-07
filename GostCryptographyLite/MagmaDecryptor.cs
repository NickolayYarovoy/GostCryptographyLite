using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace GostCryptographyLite
{
    internal class MagmaDecryptor : ICryptoTransform
    {
        private const int BlockSizeBytes = 8;

        private GostCipherMode GostCipherMode;
        private PaddingMode paddingMode;
        private MagmaKeyData key;
        private byte[]? iv;
        private byte[]? startIv;
        private byte[] lastBlock;
        private bool isFirstBlock;
        private int totalLenght;

        private bool OpenSslCompability;

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => BlockSizeBytes;

        public int OutputBlockSize => BlockSizeBytes;

        public MagmaDecryptor(byte[] Key, byte[]? IV, GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslCompability)
        {
            if (Key == null)
                throw new ArgumentNullException("Ключ должен быть инициализирован");

            if (Key.Length != 32)
                throw new ArgumentException("Размер ключа должен быть равен 256 битам");

            if (GostCipherMode == GostCipherMode.CTS)
                throw new ArgumentException("Данный режим работы не поддерживается");

            if (paddingMode != PaddingMode.PKCS7 && paddingMode != PaddingMode.ANSIX923)
                throw new ArgumentException("Данный режим заполнения не поддерживается");

            iv = null;

            if (GostCipherMode == GostCipherMode.CBC || GostCipherMode == GostCipherMode.CFB || GostCipherMode == GostCipherMode.OFB)
            {
                if (IV == null || IV.Length == 0)
                    throw new ArgumentNullException("При работе в режимах CTR, CBC, OFB и CFB необходим вектор инициализации");
                if (IV.Length % 8 != 0)
                    throw new ArgumentNullException("Размер вектора инициализации должен быть кратен 64 битам");

                iv = new byte[IV.Length];
                IV.CopyTo(iv, 0);
            }
            if (GostCipherMode == GostCipherMode.CTR)
            {
                if (IV == null || IV.Length == 0)
                    throw new ArgumentNullException("При работе в режимах CTR, CBC, OFB и CFB необходим вектор инициализации");
                if (IV.Length != 4 && IV.Length != 8)
                    throw new ArgumentNullException("Размер вектора инициализации в режиме CTR должен составлять 32 бита");

                if (IV.Length == 8)
                    for (int i = 4; i < 8; i++)
                        if (IV[i] != 0)
                            throw new ArgumentNullException("Размер вектора инициализации в режиме CTR должен составлять 32 бита");

                iv = new byte[8];

                Array.Clear(iv!);

                for (int i = 0; i < 4; i++)
                    iv![i] = IV[i];
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
            totalLenght = 0;
        }

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
                throw new ArgumentException("Длина шифруемого блока должна быть кратна 64 битам");

            if (!isFirstBlock && GostCipherMode != GostCipherMode.CTR)
            {
                lastBlock.CopyTo(outputBuffer, outputOffset);
                outputOffset += BlockSizeBytes;
            }

            if (GostCipherMode == GostCipherMode.ECB || GostCipherMode == GostCipherMode.CBC)
            {
                byte[] block = new byte[BlockSizeBytes];
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
                    if (lastBlock[7] <= 0 || lastBlock[7] > 8)
                        throw new CryptographicException("Неверная длина дополнения");

                    for (int i = 1; i < lastBlock[7]; i++)
                        if (lastBlock[7] != lastBlock[7 - i])
                            throw new CryptographicException("Неверное дополнение");

                    res = new byte[BlockSizeBytes - lastBlock[7]];
                    Array.Copy(lastBlock, res, BlockSizeBytes - lastBlock[7]);
                    if (iv != null)
                        Array.Copy(startIv!, iv, iv.Length);
                    return res;
                }
                throw new ArgumentException("Некорректный тип дополнения");
            }

            return outputBuffer;
        }

        public void Dispose()
        {
            throw new NotImplementedException();
        }

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

        private static uint reverse(uint x)
        {
            x = ((x >> 8) & 0x00ff00ffu) | ((x & 0x00ff00ffu) << 8);
            x = ((x >> 16) & 0xffffu) | ((x & 0xffffu) << 16);
            return x;
        }
    }
}
