using System.Security.Cryptography;

namespace GostCryptographyLite
{
    public sealed class Kuznechik : SymmetricAlgorithm
    {
        private static readonly KeySizes[] legalKeySizes = [new(256, 256, 0)];
        public override KeySizes[] LegalKeySizes => legalKeySizes;
        private static readonly KeySizes[] legalBlockSizes = [new(128, 128, 0)];
        public override KeySizes[] LegalBlockSizes => legalBlockSizes;
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
                    throw new CryptographicException("Выбранный алгоритм не поддерживает данный режим шифрования");

                ModeValue = value;
            }
        }

        /// <summary>
        /// Создание стандартного класса реализации шифра ГОСТ 34.12-2018 "Кузнечик" (CBC, PKCS7)
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
        /// Создание класса реализации шифра ГОСТ 34.12-2018 "Кузнечик" с требуемым режимом работы и режимом заполнения
        /// </summary>
        /// <param name="GostCipherMode"></param>
        /// <param name="paddingMode"></param>
        public Kuznechik(GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslComp = true)
        {
            if (GostCipherMode == GostCipherMode.CTS)
                throw new ArgumentException("Данный режим работы не поддерживается");

            if (paddingMode != PaddingMode.PKCS7)
                throw new ArgumentException("Данный режим заполнения не поддерживается");

            KeySize = 256;
            BlockSize = 128;
            Mode = GostCipherMode;
            Padding = paddingMode;
            OpenSslCompability = openSslComp;
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return new KuznechikDecryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new KuznechikDecryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return new KuznechikEncryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new KuznechikEncryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        public override void GenerateIV()
        {
            IV = RandomNumberGenerator.GetBytes(16);

            if (Mode == GostCipherMode.CTR)
                for (int i = 8; i < 16; i++)
                    IV[i] = 0;
        }

        public override void GenerateKey()
        {
            Key = RandomNumberGenerator.GetBytes(32);
        }
    }
}
