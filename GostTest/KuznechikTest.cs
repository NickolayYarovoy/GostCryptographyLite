﻿using GostCryptographyLite;
using System.Security.Cryptography;

namespace GostTest
{
    [TestClass]
    public sealed class KuznechikTest
    {
        public static IEnumerable<object?[]> AdditionData
        {
            get
            {
                return new[]
                {
                    new object?[] {GostCipherMode.ECB, PaddingMode.PKCS7, false, new byte[] { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88}, null,
                    new byte[] {
                        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
                        0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x11,0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,
                    },  new byte[] {
                        0xcd,0xed,0xd4,0xb9,0x42,0x8d,0x46,0x5a,0x30,0x24,0xbc,0xbe,0x90,0x9d,0x67,0x7f,
                        0x8b,0xd0,0x18,0x67,0xd7,0x52,0x54,0x28,0xf9,0x32,0x00,0x6e,0x2c,0x91,0x29,0xb4,
                        0x57,0xb1,0xd4,0x3b,0x31,0xa5,0xf5,0xf3,0xee,0x7c,0x24,0x9d,0x54,0x33,0xca,0xf0,
                        0x98,0xda,0x8a,0xaa,0xc5,0xc4,0x02,0x3a,0xeb,0xb9,0x30,0xe8,0xcd,0x9c,0xb0,0xd0,
                        0x78,0xae,0xe5,0x5a,0xc2,0xb4,0x5a,0x91,0x75,0x16,0x19,0x31,0x2a,0xda,0xb6,0xb3
                    }
                    },
                    new object?[] {GostCipherMode.ECB, PaddingMode.PKCS7, true, new byte[] { 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}, null,
                    new byte[] {
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
                        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
                        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11
                    },  new byte[] {
                        0x7f,0x67,0x9d,0x90,0xbe,0xbc,0x24,0x30,0x5a,0x46,0x8d,0x42,0xb9,0xd4,0xed,0xcd,
                        0xb4,0x29,0x91,0x2c,0x6e,0x00,0x32,0xf9,0x28,0x54,0x52,0xd7,0x67,0x18,0xd0,0x8b,
                        0xf0,0xca,0x33,0x54,0x9d,0x24,0x7c,0xee,0xf3,0xf5,0xa5,0x31,0x3b,0xd4,0xb1,0x57,
                        0xd0,0xb0,0x9c,0xcd,0xe8,0x30,0xb9,0xeb,0x3a,0x02,0xc4,0xc5,0xaa,0x8a,0xda,0x98,
                        0xb3,0xb6,0xda,0x2a,0x31,0x19,0x16,0x75,0x91,0x5a,0xb4,0xc2,0x5a,0xe5,0xae,0x78
                    }
                    },
                    new object?[] {GostCipherMode.CBC, PaddingMode.PKCS7, false, new byte[] { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
                    new byte[] {
                        0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
                        0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
                    },
                    new byte[] {
                        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
                        0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x11,0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22
                    },  new byte[] {
                        0x27, 0xcc, 0x7d, 0x6d, 0x3d, 0x2e, 0xe5, 0x90, 0x4d, 0xfa, 0x85, 0xa0, 0xd4, 0x72, 0x99, 0x68,
                        0xac, 0xa5, 0x5e, 0x8d, 0x44, 0x8e, 0x1e, 0xaf, 0xa6, 0xec, 0x78, 0xb4, 0x61, 0xe6, 0x26, 0x28,
                        0xd0, 0x90, 0x9d, 0xf4, 0xb0, 0xe8, 0x40, 0x56, 0xe8, 0x99, 0x19, 0xe9, 0xf1, 0xab, 0x7b, 0xfe,
                        0x70, 0x39, 0xb6, 0x60, 0x15, 0x9a, 0x2d, 0x1a, 0x63, 0x5c, 0x89, 0x5a, 0x06, 0x88, 0x76, 0x16,
                        0x17, 0x9b, 0x72, 0x70, 0x32, 0xd4, 0xb1, 0x37, 0xd1, 0xfa, 0xa9, 0x9e, 0x06, 0xa8, 0x65, 0x5f
                    }
                    },
                    new object?[] {GostCipherMode.CBC, PaddingMode.PKCS7, true, new byte[] { 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
                    new byte[] {
                        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
                        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
                    },
                    new byte[] {
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
                        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
                        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11
                    },  new byte[] {
                        0x68, 0x99, 0x72, 0xd4, 0xa0, 0x85, 0xfa, 0x4d, 0x90, 0xe5, 0x2e, 0x3d, 0x6d, 0x7d, 0xcc, 0x27,
                        0x28, 0x26, 0xe6, 0x61, 0xb4, 0x78, 0xec, 0xa6, 0xaf, 0x1e, 0x8e, 0x44, 0x8d, 0x5e, 0xa5, 0xac,
                        0xfe, 0x7b, 0xab, 0xf1, 0xe9, 0x19, 0x99, 0xe8, 0x56, 0x40, 0xe8, 0xb0, 0xf4, 0x9d, 0x90, 0xd0,
                        0x16, 0x76, 0x88, 0x06, 0x5a, 0x89, 0x5c, 0x63, 0x1a, 0x2d, 0x9a, 0x15, 0x60, 0xb6, 0x39, 0x70,
                        0x5f, 0x65, 0xa8, 0x06, 0x9e, 0xa9, 0xfa, 0xd1, 0x37, 0xb1, 0xd4, 0x32, 0x70, 0x72, 0x9b, 0x17
                    }
                    },
                    new object?[] {GostCipherMode.OFB, PaddingMode.PKCS7, false, new byte[] { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
                    new byte[] {
                        0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
                        0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
                    },
                    new byte[] {
                        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
                        0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x11,0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22
                    },  new byte[] {
                        0x95, 0xbd, 0x7a, 0x89, 0x5e, 0x79, 0x1f, 0xff, 0x24, 0x2b, 0x84, 0xb1, 0x59, 0x0a, 0x80, 0x81,
                        0xbf, 0x26, 0x93, 0x9d, 0x36, 0x21, 0xb5, 0x8f, 0xb4, 0xfa, 0x8c, 0x04, 0xa7, 0x47, 0x5b, 0xed,
                        0x13, 0x8a, 0x28, 0x10, 0xfc, 0xe7, 0x0f, 0xc8, 0xb1, 0xb8, 0xa0, 0x3c, 0xac, 0x57, 0xa2, 0x66,
                        0x50, 0x31, 0x90, 0xf6, 0x43, 0x22, 0x29, 0xa0, 0x60, 0x86, 0x13, 0x66, 0xc0, 0xbb, 0x3e, 0x20,
                        0xb3, 0xf4, 0x63, 0x5b, 0xea, 0xeb, 0x48, 0xcc, 0x9d, 0xe0, 0x6b, 0x01, 0x03, 0xbd, 0x0e, 0xe8
                    }
                    },
                    new object?[] {GostCipherMode.OFB, PaddingMode.PKCS7, true, new byte[] { 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
                    new byte[] {
                        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
                        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
                    },
                    new byte[] {
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
                        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
                        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11
                    },  new byte[] {
                        0x81, 0x80, 0x0a, 0x59, 0xb1, 0x84, 0x2b, 0x24, 0xff, 0x1f, 0x79, 0x5e, 0x89, 0x7a, 0xbd, 0x95,
                        0xed, 0x5b, 0x47, 0xa7, 0x04, 0x8c, 0xfa, 0xb4, 0x8f, 0xb5, 0x21, 0x36, 0x9d, 0x93, 0x26, 0xbf,
                        0x66, 0xa2, 0x57, 0xac, 0x3c, 0xa0, 0xb8, 0xb1, 0xc8, 0x0f, 0xe7, 0xfc, 0x10, 0x28, 0x8a, 0x13,
                        0x20, 0x3e, 0xbb, 0xc0, 0x66, 0x13, 0x86, 0x60, 0xa0, 0x29, 0x22, 0x43, 0xf6, 0x90, 0x31, 0x50,
                        0xe8, 0x0e, 0xbd, 0x03, 0x01, 0x6b, 0xe0, 0x9d, 0xcc, 0x48, 0xeb, 0xea, 0x5b, 0x63, 0xf4, 0xb3
                    }
                    },
                    new object?[] {GostCipherMode.CFB, PaddingMode.PKCS7, false, new byte[] { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
                    new byte[] {
                        0x12, 0x01, 0xf0, 0xe5, 0xd4, 0xc3, 0xb2, 0xa1, 0xf0, 0xce, 0xab, 0x90, 0x78, 0x56, 0x34, 0x12,
                        0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x90, 0x89, 0x78, 0x67, 0x56, 0x45, 0x34, 0x23
                    },
                    new byte[] {
                        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
                        0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x11,0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22
                    },  new byte[] {
                        0x95, 0xbd, 0x7a, 0x89, 0x5e, 0x79, 0x1f, 0xff, 0x24, 0x2b, 0x84, 0xb1, 0x59, 0x0a, 0x80, 0x81,
                        0xbf, 0x26, 0x93, 0x9d, 0x36, 0x21, 0xb5, 0x8f, 0xb4, 0xfa, 0x8c, 0x04, 0xa7, 0x47, 0x5b, 0xed,
                        0xb5, 0x38, 0xa2, 0x97, 0x4e, 0x26, 0x2d, 0x84, 0x38, 0x8d, 0xc6, 0x5c, 0xeb, 0xa8, 0xf2, 0x79,
                        0xd1, 0xf4, 0xfb, 0x44, 0xdd, 0xd9, 0x5b, 0xc7, 0xe6, 0x2d, 0x92, 0x4e, 0xcd, 0xbe, 0xfe, 0x4f,
                        0x86, 0x27, 0xaf, 0x4e, 0x4d, 0x75, 0x84, 0xd7, 0xb8, 0x57, 0x6e, 0x83, 0xd6, 0xd4, 0x72, 0x9b
                    }
                    },
                    new object?[] {GostCipherMode.CFB, PaddingMode.PKCS7, true, new byte[] { 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
                    new byte[] {
                        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xce, 0xf0, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf0, 0x01, 0x12,
                        0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x90, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
                    },
                    new byte[] {
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
                        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
                        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11
                    },  new byte[] {
                        0x81,0x80,0x0a,0x59,0xb1,0x84,0x2b,0x24,0xff,0x1f,0x79,0x5e,0x89,0x7a,0xbd,0x95,
                        0xed,0x5b,0x47,0xa7,0x04,0x8c,0xfa,0xb4,0x8f,0xb5,0x21,0x36,0x9d,0x93,0x26,0xbf,
                        0x79,0xf2,0xa8,0xeb,0x5c,0xc6,0x8d,0x38,0x84,0x2d,0x26,0x4e,0x97,0xa2,0x38,0xb5,
                        0x4f,0xfe,0xbe,0xcd,0x4e,0x92,0x2d,0xe6,0xc7,0x5b,0xd9,0xdd,0x44,0xfb,0xf4,0xd1,
                        0x9b,0x72,0xd4,0xd6,0x83,0x6e,0x57,0xb8,0xd7,0x84,0x75,0x4d,0x4e,0xaf,0x27,0x86
                    }
                    },
                    new object?[] {GostCipherMode.CTR, PaddingMode.PKCS7, true, new byte[] { 0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77, 0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef},
                    new byte[] {
                        0x12,0x34,0x56,0x78,0x90,0xab,0xce,0xf0
                    },
                    new byte[] {
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x00,0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
                        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,
                        0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,
                        0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xee,0xff,0x0a,0x00,0x11
                    },  new byte[] {
                        0xf1,0x95,0xd8,0xbe,0xc1,0x0e,0xd1,0xdb,0xd5,0x7b,0x5f,0xa2,0x40,0xbd,0xa1,0xb8,
                        0x85,0xee,0xe7,0x33,0xf6,0xa1,0x3e,0x5d,0xf3,0x3c,0xe4,0xb3,0x3c,0x45,0xde,0xe4,
                        0xa5,0xea,0xe8,0x8b,0xe6,0x35,0x6e,0xd3,0xd5,0xe8,0x77,0xf1,0x35,0x64,0xa3,0xa5,
                        0xcb,0x91,0xfa,0xb1,0xf2,0x0c,0xba,0xb6,0xd1,0xc6,0xd1,0x58,0x20,0xbd,0xba,0x73,
                    }
                    },
                    new object?[] {GostCipherMode.CTR, PaddingMode.PKCS7, false, new byte[] { 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01, 0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88},
                    new byte[] {
                        0xf0,0xce,0xab,0x90,0x78,0x56,0x34,0x12
                    },
                    new byte[] {
                        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff,0x00,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
                        0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,
                        0x11,0x00,0x0a,0xff,0xee,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22
                    },  new byte[] {
                        0xb8,0xa1,0xbd,0x40,0xa2,0x5f,0x7b,0xd5,0xdb,0xd1,0x0e,0xc1,0xbe,0xd8,0x95,0xf1,
                        0xe4,0xde,0x45,0x3c,0xb3,0xe4,0x3c,0xf3,0x5d,0x3e,0xa1,0xf6,0x33,0xe7,0xee,0x85,
                        0xa5,0xa3,0x64,0x35,0xf1,0x77,0xe8,0xd5,0xd3,0x6e,0x35,0xe6,0x8b,0xe8,0xea,0xa5,
                        0x73,0xba,0xbd,0x20,0x58,0xd1,0xc6,0xd1,0xb6,0xba,0x0c,0xf2,0xb1,0xfa,0x91,0xcb
                    }
                    },
                };
            }
        }



        [TestMethod]
        [DynamicData(nameof(AdditionData))]
        public void TestEncryption(GostCipherMode mode, PaddingMode padding, bool isOpenSsl, byte[] key, byte[] iv, byte[] plain, byte[] cipher)
        {
            using (Kuznechik kuzya = new(mode, padding, isOpenSsl))
            {
                var encryptor = kuzya.CreateEncryptor(key, iv);
                byte[] output = new byte[64];

                encryptor.TransformBlock(plain, 0, 32, output, 0);
                encryptor.TransformBlock(plain, 32, 32, output, 32);
                byte[] last = encryptor.TransformFinalBlock(plain, 0, 0);

                byte[] res = [.. output, .. last];
                CollectionAssert.AreEqual(cipher, res);

                encryptor.TransformBlock(plain, 0, 64, output, 0);
                last = encryptor.TransformFinalBlock(plain, 0, 0);

                res = [.. output, .. last];
                CollectionAssert.AreEqual(cipher, res);
            }
        }

        [TestMethod]
        [DynamicData(nameof(AdditionData))]
        public void TestDecryption(GostCipherMode mode, PaddingMode padding, bool isOpenSsl, byte[] key, byte[] iv, byte[] plain, byte[] cipher)
        {
            using (Kuznechik kuzya = new(mode, padding, isOpenSsl))
            {
                var decryptor = kuzya.CreateDecryptor(key, iv);
                byte[] output = new byte[64];

                int outLen = decryptor.TransformBlock(cipher, 0, cipher.Length - 32, output, 0);
                decryptor.TransformBlock(cipher, cipher.Length - 32, 32, output, outLen);
                byte[] last = decryptor.TransformFinalBlock(cipher, 0, 0);

                CollectionAssert.AreEqual(output, plain);

                output = new byte[64];

                decryptor.TransformBlock(cipher, 0, cipher.Length, output, 0);
                last = decryptor.TransformFinalBlock(cipher, 0, 0);

                CollectionAssert.AreEqual(output, plain);
            }
        }
    }
}
