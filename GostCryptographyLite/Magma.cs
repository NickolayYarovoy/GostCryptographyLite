﻿using GostCryptographyLite;
using System.Security.Cryptography;

namespace GostCryptographyLite
{
    public sealed class Magma : SymmetricAlgorithm
    {
        private static readonly KeySizes[] legalKeySizes = [new(256, 256, 0)];
        public override KeySizes[] LegalKeySizes => legalKeySizes;
        private static readonly KeySizes[] legalBlockSizes = [new(64, 64, 0)];
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
        public Magma(bool openSslComp = true)
        {
            KeySize = 256;
            BlockSize = 64;
            Mode = GostCipherMode.CBC;
            Padding = PaddingMode.PKCS7;
            OpenSslCompability = openSslComp;
        }

        /// <summary>
        /// Создание класса реализации шифра ГОСТ 34.12-2018 "Кузнечик" с требуемым режимом работы и режимом заполнения
        /// </summary>
        /// <param name="GostCipherMode"></param>
        /// <param name="paddingMode"></param>
        public Magma(GostCipherMode GostCipherMode, PaddingMode paddingMode, bool openSslComp = true)
        {
            if (GostCipherMode == GostCipherMode.CTS)
                throw new ArgumentException("Данный режим работы не поддерживается");

            if (paddingMode != PaddingMode.PKCS7)
                throw new ArgumentException("Данный режим заполнения не поддерживается");

            KeySize = 256;
            BlockSize = 64;
            Mode = GostCipherMode;
            Padding = paddingMode;
            OpenSslCompability = openSslComp;
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return new MagmaDecryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new MagmaDecryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return new MagmaEncryptor(Key, IV, Mode, Padding, OpenSslCompability);
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[]? rgbIV)
        {
            return new MagmaEncryptor(rgbKey, rgbIV, Mode, Padding, OpenSslCompability);
        }

        public override void GenerateIV()
        {
            IV = new byte[BlockSize / 8];
            RandomNumberGenerator.Fill(IV);

            if (Mode == GostCipherMode.CTR)
                for (int i = 8; i < 16; i++)
                    IV[i] = 0;
        }

        public override void GenerateKey()
        {
            Key = new byte[KeySize / 8];
            RandomNumberGenerator.Fill(Key);
        }
    }
}
