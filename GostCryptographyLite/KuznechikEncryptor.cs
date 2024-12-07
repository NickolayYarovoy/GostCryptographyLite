using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    /// <summary>
    /// A class implementing Kuznechik encryptors
    /// </summary>
    internal sealed class KuznechikEncryptor : ICryptoTransform
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
        private KuznechikKeyData key;
        /// <summary>
        /// Current IV
        /// </summary>
        private byte[]? iv;
        /// <summary>
        /// IV of clear instance
        /// </summary>
        private byte[]? startIv;

        public bool CanReuseTransform => true;

        public bool CanTransformMultipleBlocks => true;

        public int InputBlockSize => BlockSizeBytes;

        public int OutputBlockSize => BlockSizeBytes;


        /// <summary>
        /// 16 round LFSR Matrix
        /// </summary>
        private byte[,] LMatrix { get; set; }
        /// <summary>
        /// OpenSSL compability mode (true - OpenSSL compability, false - GOST compability)
        /// </summary>
        private bool OpenSslCompability;



        public KuznechikEncryptor(byte[] Key, byte[]? IV, GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslCompability)
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
            if(GostCipherMode == GostCipherMode.CTR)
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

            LMatrix = new byte[BlockSizeBytes, BlockSizeBytes];

            KuznechikHelpFunctions.GenerateMatrix(LMatrix);

            
            if (OpenSslCompability)
                key = KuznechikHelpFunctions.ScheduleKeys(Key);
            else
                key = KuznechikHelpFunctions.ScheduleKeys(Key.Reverse().ToArray());
        }

        public void Dispose()
        {
        }

        public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
        {
            if (!(inputCount % BlockSizeBytes == 0))
                throw new ArgumentException("Incorrect block size");
            Vector128<byte> block;
            Vector128<byte> temp;
            if (GostCipherMode == GostCipherMode.CTR)
            {
                Vector128<byte> ctr = Vector128.Create(iv!);
                Vector128<UInt64> ctrBig;
                Vector128<UInt64> add = Vector128.Create([1ul, 0ul]);
                Vector128<UInt64> per = Vector128.Create([0ul, 1ul]);
                byte[] byteBlock = new byte[16];
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    block = EncryptBlock(ctr);
                    block.CopyTo(byteBlock);
                    for(int j = 0; j < 16; j++)
                        outputBuffer[outputOffset + i + j] = (byte)(inputBuffer[inputOffset + i + j] ^ byteBlock[j]);

                    ctrBig = ctr.AsUInt64() + add;
                    if (ctrBig[0] == 0)
                        ctrBig += per;
                    ctr = ctrBig.AsByte();
                }
                ctr.CopyTo(iv!);
            }
            else
            {
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    if (GostCipherMode == GostCipherMode.CFB || GostCipherMode == GostCipherMode.OFB)
                    {
                            if (OpenSslCompability)
                                block = Vector128.Create(iv!);
                            else
                                block = Vector128.Shuffle(Vector128.Create(iv!), KuznechikHelpFunctions.mask);

                        block = EncryptBlock(block);


                        if (GostCipherMode == GostCipherMode.CFB)
                        {
                            temp = Vector128.Create(inputBuffer, i + inputOffset);
                            block ^= temp;
                        }

                        block.CopyTo(outputBuffer, outputOffset + i);

                        if (GostCipherMode == GostCipherMode.OFB)
                            for (int j = 0; j < 16; j++)
                                outputBuffer[outputOffset + i + j] ^= inputBuffer[i + j + inputOffset];

                        Array.Copy(iv!, 16, iv!, 0, iv!.Length - 16);
                        if (OpenSslCompability)
                            block.CopyTo(iv!, iv!.Length - 16);
                        else
                             Vector128.Shuffle(block, KuznechikHelpFunctions.mask).CopyTo(iv!, iv!.Length - 16);
                    }
                    else
                    {
                        block = Vector128.Create(inputBuffer, inputOffset + i);

                        if (GostCipherMode == GostCipherMode.CBC)
                        {
                            if (OpenSslCompability)
                                temp = Vector128.Create(iv!);
                            else
                                temp = Vector128.Shuffle(Vector128.Create(iv!), KuznechikHelpFunctions.mask);

                            block ^= temp;
                        }

                        block = EncryptBlock(block);

                        if (GostCipherMode == GostCipherMode.CBC)
                        {
                            Array.Copy(iv!, 16, iv!, 0, iv!.Length - 16);
                            if (OpenSslCompability)
                                block.CopyTo(iv!, iv!.Length - 16);
                            else
                                Vector128.Shuffle(block, KuznechikHelpFunctions.mask).CopyTo(iv!, iv!.Length - 16);
                        }

                        block.CopyTo(outputBuffer, outputOffset + i);
                    }
                }
            }

            return inputCount;
        }

        public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
        {

            if (GostCipherMode == GostCipherMode.CTR)
            {
                if (inputCount == 0)
                {
                    startIv!.CopyTo(iv!, 0);
                    return [];
                }

                Vector128<byte> block;
                byte[] outputBuffer = new byte[inputCount];
                Vector128<byte> ctr = Vector128.Create(iv!);
                byte[] byteBlock = new byte[16];
                for (int i = 0; i < inputCount; i += BlockSizeBytes)
                {
                    block = EncryptBlock(ctr);
                    block.CopyTo(byteBlock);
                    for (int j = 0; j < 16; j++)
                        outputBuffer[0 + i + j] = (byte)(inputBuffer[inputOffset + i + j] ^ byteBlock[j]);
                }
                startIv!.CopyTo(iv!, 0);
                return outputBuffer;
            }
            else
            {
                byte[] res = new byte[16];
                byte[] input = new byte[16];
                Array.Copy(inputBuffer, inputOffset, input, 0, inputCount);
                if (paddingMode == PaddingMode.PKCS7)
                {
                    byte pad = (byte)(16 - inputCount);
                    for (int i = inputCount; i < 16; i++)
                    {
                        input[i] = pad;
                    }
                }
                TransformBlock(input, 0, 16, res, 0);

                iv = startIv?.ToArray();

                return res;
            }
        }

        /// <summary>
        /// Method for encrypting a single block of data
        /// </summary>
        /// <param name="block">Encrypting block of data</param>
        /// <returns>Encrypted block</returns>
        private Vector128<byte> EncryptBlock(Vector128<byte> block)
        {
            Vector128<byte> num;
            if (GostCipherMode != GostCipherMode.CTR)
            {
                if (OpenSslCompability)
                    num = block;
                else
                {
                    num = Vector128.Shuffle(block, KuznechikHelpFunctions.mask);
                }
            }
            else
            {
                num = Vector128.Shuffle(block, KuznechikHelpFunctions.mask);
            }

            for (int i = 0; i < 9; i++)
            {
                num ^= key.Key[i];
                num ^= key.Key[i + 10];
                num = KuznechikHelpFunctions.FastLinearSteps(num);
            }

            num ^= key.Key[9];
            num ^= key.Key[19];

            if (OpenSslCompability)
                return num;
            else
            {
                return Vector128.Shuffle(num, KuznechikHelpFunctions.mask);
            }
        }

        public void Clear()
        {
            key.Clear();
            if (iv != null)
            {
                Array.Clear(iv);
                Array.Clear(startIv!);
                iv = null;
                startIv = null;
            }
        }
    }
}
