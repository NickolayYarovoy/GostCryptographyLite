using System.Security.Cryptography;

namespace GostCryptographyLite
{
    /// <summary>
    /// A class implementing the creation of decryptors and encryptors
    /// </summary>
    public sealed class Kuznechik : SymmetricAlgorithm
    {
        /// <summary>
        /// Legal key sizes
        /// </summary>
        private static readonly KeySizes[] legalKeySizes = [new(256, 256, 0)];
        public override KeySizes[] LegalKeySizes => legalKeySizes;

        /// <summary>
        /// Legal block sizes
        /// </summary>
        private static readonly KeySizes[] legalBlockSizes = [new(128, 128, 0)];
        public override KeySizes[] LegalBlockSizes => legalBlockSizes;

        /// <summary>
        /// OpenSSL compability mode (true - OpenSSL compability, false - GOST compability)
        /// </summary>
        private readonly bool OpenSslCompability;

        private new GostCipherMode ModeValue;
        public new GostCipherMode Mode
        {
            get
            {
                return ModeValue;
            }

            set
            {
                if (value == GostCipherMode.CTS)
                    throw new CryptographicException("The selected algorithm does not support this cipher mode");

                ModeValue = value;
            }
        }

        /// <summary>
        /// Creation of a standard class implementation of the GOST 34.12-2018 "Kuznechik" cipher (CBC, PKCS7)
        /// </summary>
        public Kuznechik(bool openSslComp = true)
        {
            KeySize = 256;
            BlockSize = 128;
            Mode = GostCipherMode.CBC;
            Padding = PaddingMode.PKCS7;
            OpenSslCompability = openSslComp;
        }

        /// <summary>
        /// Creation of a class implementation of the GOST 34.12-2018 "Kuznechik" cipher with the required mode of operation and padding scheme.
        /// </summary>
        /// <param name="GostCipherMode">Cipher mode</param>
        /// <param name="paddingMode">Padding scheme</param>
        public Kuznechik(GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslComp = true)
        {
            if (GostCipherMode == GostCipherMode.CTS)
                throw new ArgumentException("The selected algorithm does not support this cipher mode.");

            if (paddingMode != PaddingMode.PKCS7)
                throw new ArgumentException("The selected algorithm does not support this padding mode.");

            KeySize = 256;
            BlockSize = 128;
            Mode = GostCipherMode;
            Padding = paddingMode;
            OpenSslCompability = openSslComp;
        }

        /// <summary>
        /// Creation of a decryptor with parameters defined by the instance
        /// </summary>
        /// <returns>Instance of decryptor</returns>
        public override ICryptoTransform CreateDecryptor()
        {
            return new KuznechikDecryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Creation of a decryptor with parameters defined by the instance with inputed key and IV
        /// </summary>
        /// <param name="rgbKey">Decryptor key</param>
        /// <param name="rgbIV">Decryptor IV</param>
        /// <returns>Instance of decryptor</returns>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new KuznechikDecryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Creation of a encryptor with parameters defined by the instance
        /// </summary>
        /// <returns>Instance of encryptor</returns>
        public override ICryptoTransform CreateEncryptor()
        {
            return new KuznechikEncryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Creation of a encryptor with parameters defined by the instance with inputed key and IV
        /// </summary>
        /// <param name="rgbKey">Encryptor key</param>
        /// <param name="rgbIV">Encryptor IV</param>
        /// <returns>Instance of encryptor</returns>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new KuznechikEncryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Filling the instance initialization vector
        /// </summary>
        public override void GenerateIV()
        {
            IV = RandomNumberGenerator.GetBytes(16);

            if (Mode == GostCipherMode.CTR)
                for (int i = 8; i < 16; i++)
                    IV[i] = 0;
        }

        /// <summary>
        /// Filling the instance key
        /// </summary>
        public override void GenerateKey()
        {
            Key = RandomNumberGenerator.GetBytes(32);
        }
    }
}
