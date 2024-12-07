using GostCryptographyLite;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    public sealed class Magma : SymmetricAlgorithm
    {
        /// <summary>
        /// Legal key sizes
        /// </summary>
        private static readonly KeySizes[] legalKeySizes = [new(256, 256, 0)];
        public override KeySizes[] LegalKeySizes => legalKeySizes;
        /// <summary>
        /// Legal block sizes
        /// </summary>
        private static readonly KeySizes[] legalBlockSizes = [new(64, 64, 0)];
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
        /// Creation of a standard class implementation of the GOST 34.12-2018 "Magma" cipher (CBC, PKCS7)
        /// </summary>
        public Magma(bool openSslComp = true)
        {
            KeySize = 256;
            BlockSize = 64;
            Mode = GostCipherMode.CBC;
            Padding = PaddingMode.PKCS7;
            OpenSslCompability = openSslComp;
        }

        /// <summary>
        /// Creation of a class implementation of the GOST 34.12-2018 "Magma" cipher with the required mode of operation and padding scheme.
        /// </summary>
        /// <param name="GostCipherMode">Cipher mode</param>
        /// <param name="paddingMode">Padding scheme</param>
        public Magma(GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslComp = true)
        {
            if (GostCipherMode == GostCipherMode.CTS)
                throw new ArgumentException("The selected algorithm does not support this cipher mode");

            if (paddingMode != PaddingMode.PKCS7)
                throw new ArgumentException("The selected algorithm does not support this padding mode");

            KeySize = 256;
            BlockSize = 64;
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
            return new MagmaDecryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Creation of a decryptor with parameters defined by the instance with inputed key and IV
        /// </summary>
        /// <param name="rgbKey">Decryptor key</param>
        /// <param name="rgbIV">Decryptor IV</param>
        /// <returns>Instance of decryptor</returns>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new MagmaDecryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Creation of a encryptor with parameters defined by the instance
        /// </summary>
        /// <returns>Instance of encryptor</returns>
        public override ICryptoTransform CreateEncryptor()
        {
            return new MagmaEncryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Creation of a encryptor with parameters defined by the instance with inputed key and IV
        /// </summary>
        /// <param name="rgbKey">Encryptor key</param>
        /// <param name="rgbIV">Encryptor IV</param>
        /// <returns>Instance of encryptor</returns>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new MagmaEncryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        /// <summary>
        /// Filling the instance initialization vector
        /// </summary>
        public override void GenerateIV()
        {
            IV = RandomNumberGenerator.GetBytes(8);

            if (Mode == GostCipherMode.CTR)
                for (int i = 4; i < 8; i++)
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
