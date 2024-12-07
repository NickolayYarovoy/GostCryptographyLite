﻿using GostCryptographyLite;
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
                                0xfb, 0x7e, 0xc6, 0x96, 0x09, 0x26, 0x68, 0x7c,
                                0x2d, 0xad, 0x28, 0xd1, 0x2b, 0xbb, 0x85, 0x7f
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
                                0x7c, 0x68, 0x26, 0x09, 0x96, 0xc6, 0x7e, 0xfb,
                                0x7f, 0x85, 0xbb, 0x2b, 0xd1, 0x28, 0xad, 0x2d
                        }
                    },
                    new object?[] {GostCipherMode.CBC, PaddingMode.PKCS7, false,
                        new byte[] { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
                                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                        new byte[]{ 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
                                    0xf1, 0xde, 0xbc, 0x0a, 0x89, 0x67, 0x45, 0x23,
                                    0x12, 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34 },
                        new byte[] {
                                0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
                                0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
                                0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
                                0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
                        },  new byte[] {
                                0x19, 0x39, 0x68, 0xea, 0x5e, 0xb0, 0xd1, 0x96,
                                0xb9, 0x37, 0xb9, 0xab, 0x29, 0x61, 0xf7, 0xaf,
                                0x19, 0x00, 0xbc, 0xc4, 0xa1, 0xb4, 0x58, 0x50,
                                0x67, 0xe6, 0xd7, 0x7c, 0x1a, 0x8b, 0xb7, 0x20,
                                0x7e, 0xc3, 0xfa, 0xdd, 0x08, 0x30, 0xaf, 0xd7
                        }
                    },
                    new object?[] {GostCipherMode.CBC, PaddingMode.PKCS7, true,
                        new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
                                     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff},
                        new byte[] {
                                    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                                    0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1,
                                    0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12
                                   },
                        new byte[] {
                                0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
                                0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
                                0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
                                0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41
                        },  new byte[] {
                                0x96, 0xd1, 0xb0, 0x5e, 0xea, 0x68, 0x39, 0x19,
                                0xaf, 0xf7, 0x61, 0x29, 0xab, 0xb9, 0x37, 0xb9,
                                0x50, 0x58, 0xb4, 0xa1, 0xc4, 0xbc, 0x00, 0x19,
                                0x20, 0xb7, 0x8b, 0x1a, 0x7c, 0xd7, 0xe6, 0x67,
                                0xd7, 0xaf, 0x30, 0x08, 0xdd, 0xfa, 0xc3, 0x7e
                        }
                    },
                    new object?[] {GostCipherMode.CFB, PaddingMode.PKCS7, false,
                        new byte[] { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
                                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                        new byte[]{ 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
                                    0xf1, 0xde, 0xbc, 0x0a, 0x89, 0x67, 0x45, 0x23 },
                        new byte[] {
                                0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
                                0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
                                0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
                                0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
                        },  new byte[] {
                                0x83, 0x3c, 0x90, 0x66, 0xe2, 0xe0, 0x37, 0xdb,
                                0x9c, 0x08, 0x9a, 0x1f, 0x4c, 0x64, 0x46, 0x0d,
                                0x8b, 0xd3, 0x15, 0x53, 0x03, 0xd2, 0xbd, 0x24,
                                0x05, 0x55, 0x07, 0x21, 0x14, 0x32, 0xc0, 0xbc,
                                0xed, 0xaa, 0x47, 0xa8, 0x04, 0x42, 0x69, 0xa8
                        }
                    },
                    new object?[] {GostCipherMode.CFB, PaddingMode.PKCS7, true,
                        new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
                                     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff},
                        new byte[] {
                                    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                                    0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1
                                   },
                        new byte[] {
                                0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
                                0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
                                0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
                                0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41
                        },  new byte[] {
                                0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83,
                                0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
                                0x24, 0xbd, 0xd2, 0x03, 0x53, 0x15, 0xd3, 0x8b,
                                0xbc, 0xc0, 0x32, 0x14, 0x21, 0x07, 0x55, 0x05,
                                0xa8, 0x69, 0x42, 0x04, 0xa8, 0x47, 0xaa, 0xed
                        }
                    },
                    new object?[] {GostCipherMode.OFB, PaddingMode.PKCS7, false,
                        new byte[] { 0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
                                     0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
                        new byte[]{ 0xef, 0xcd, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
                                    0xf1, 0xde, 0xbc, 0x0a, 0x89, 0x67, 0x45, 0x23 },
                        new byte[] {
                                0x59, 0x0a, 0x13, 0x3c, 0x6b, 0xf0, 0xde, 0x92,
                                0x20, 0x9d, 0x18, 0xf8, 0x04, 0xc7, 0x54, 0xdb,
                                0x4c, 0x02, 0xa8, 0x67, 0x2e, 0xfb, 0x98, 0x4a,
                                0x41, 0x7e, 0xb5, 0x17, 0x9b, 0x40, 0x12, 0x89
                        },  new byte[] {
                                0x83, 0x3c, 0x90, 0x66, 0xe2, 0xe0, 0x37, 0xdb,
                                0x9c, 0x08, 0x9a, 0x1f, 0x4c, 0x64, 0x46, 0x0d,
                                0x7e, 0x32, 0x0e, 0x43, 0x62, 0x30, 0xf8, 0xa0,
                                0x05, 0xdb, 0x4f, 0xbd, 0xb8, 0xef, 0x24, 0xc8,
                                0x68, 0x63, 0xf5, 0x0b, 0x52, 0x0b, 0x03, 0x33
                        }
                    },
                    new object?[] {GostCipherMode.OFB, PaddingMode.PKCS7, true,
                        new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
                                     0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff},
                        new byte[] {
                                    0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                                    0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1
                                   },
                        new byte[] {
                                0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
                                0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
                                0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
                                0x89, 0x12, 0x40, 0x9b, 0x17, 0xb5, 0x7e, 0x41
                        },  new byte[] {
                                0xdb, 0x37, 0xe0, 0xe2, 0x66, 0x90, 0x3c, 0x83,
                                0x0d, 0x46, 0x64, 0x4c, 0x1f, 0x9a, 0x08, 0x9c,
                                0xa0, 0xf8, 0x30, 0x62, 0x43, 0x0e, 0x32, 0x7e,
                                0xc8, 0x24, 0xef, 0xb8, 0xbd, 0x4f, 0xdb, 0x05,
                                0x33, 0x03, 0x0b, 0x52, 0x0b, 0xf5, 0x63, 0x68
                        }
                    },
                };
            }
        }



        [TestMethod]
        [DynamicData(nameof(AdditionData))]
        public void TestEncryption(GostCipherMode mode, PaddingMode padding, bool isOpenSsl, byte[] key, byte[] iv, byte[] plain, byte[] cipher)
        {
            using (Magma magma = new(mode, padding, isOpenSsl))
            {
                var encryptor = magma.CreateEncryptor(key, iv);
                byte[] output = new byte[32];

                encryptor.TransformBlock(plain, 0, 16, output, 0);
                encryptor.TransformBlock(plain, 16, 16, output, 16);
                byte[] last = encryptor.TransformFinalBlock(plain, 0, 0);
                byte[] res = [.. output, ..last];

                CollectionAssert.AreEqual(cipher, res);

                encryptor.TransformBlock(plain, 0, 32, output, 0);
                last = encryptor.TransformFinalBlock(plain, 0, 0);

                res = [.. output, .. last];
                CollectionAssert.AreEqual(cipher, res);
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

                int outLen = decryptor.TransformBlock(cipher, 0, cipher.Length - 16, output, 0);
                decryptor.TransformBlock(cipher, cipher.Length - 16, 16, output, outLen);
                byte[] last = decryptor.TransformFinalBlock(cipher, 0, 0);
                byte[] res = [.. output, .. last];

                CollectionAssert.AreEqual(res, plain);

                decryptor.TransformBlock(cipher, 0, 40, output, 0);
                last = decryptor.TransformFinalBlock(cipher, 0, 0);
                res = [.. output, .. last];
                CollectionAssert.AreEqual(res, plain);
            }
        }
    }
}
