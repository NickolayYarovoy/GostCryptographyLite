using GostCryptographyLite;
using System.Security.Cryptography;

namespace GostTest
{
    [TestClass]
    public sealed class MagmaTest
    {
        public static IEnumerable<object?[]> AdditionData
        {
            get
            {
                return new[]
                {
                    new object?[] {GostCipherMode.ECB, PaddingMode.PKCS7, false,
                        new byte[] { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
                                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, null,
                        new byte[] {
                                0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
                                0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
                                0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
                                0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
                        },  new byte[] {
                                0xa0, 0x72, 0xf3, 0x94, 0x04, 0x3f, 0x07, 0x2b,
                                0x48, 0x6e, 0x55, 0xd3, 0x15, 0xe7, 0x70, 0xde,
                                0x1e, 0xbc, 0xcf, 0xea, 0xe9, 0xd9, 0xd8, 0x11,
                                0xfb, 0x7e, 0xc6, 0x96, 0x09, 0x26, 0x68, 0x7c
                        }
                    },new object?[] {GostCipherMode.ECB, PaddingMode.PKCS7, true,
                        new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
                                     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff}, null,
                        new byte[] {
                                0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
                                0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
                                0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
                                0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41
                        },  new byte[] {
                                0x2b, 0x07, 0x3f, 0x04, 0x94, 0xf3, 0x72, 0xa0,
                                0xde, 0x70, 0xe7, 0x15, 0xd3, 0x55, 0x6e, 0x48,
                                0x11, 0xd8, 0xd9, 0xe9, 0xea, 0xcf, 0xbc, 0x1e,
                                0x7c, 0x68, 0x26, 0x09, 0x96, 0xc6, 0x7e, 0xfb
                        }
                    },
                };
            }
        }



        [TestMethod]
        [DynamicData(nameof(AdditionData))]
        public void TestEncryption(GostCipherMode mode, PaddingMode padding, bool isOpenSsl, byte[] key, byte[] iv, byte[] plain, byte[] cipher)
        {
            using (Magma kuzya = new(mode, padding, isOpenSsl))
            {
                var encryptor = kuzya.CreateEncryptor(key, iv);
                byte[] output = new byte[32];

                encryptor.TransformBlock(plain, 0, 32, output, 0);
                //byte[] last = encryptor.TransformFinalBlock(plain, 0, 0);

                //byte[] res = [.. output, .. last];
                CollectionAssert.AreEqual(cipher, output);
            }
        }

        [TestMethod]
        [DynamicData(nameof(AdditionData))]
        public void TestDecryption(GostCipherMode mode, PaddingMode padding, bool isOpenSsl, byte[] key, byte[] iv, byte[] plain, byte[] cipher)
        {
            using (Magma kuzya = new(mode, padding, isOpenSsl))
            {
                var decryptor = kuzya.CreateDecryptor(key, iv);
                byte[] output = new byte[32];

                decryptor.TransformBlock(cipher, 0, 32, output, 0);
                //byte[] last = decryptor.TransformFinalBlock(cipher, 0, 0);

                CollectionAssert.AreEqual(output, plain);
            }
        }
    }
}
