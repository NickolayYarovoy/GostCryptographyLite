﻿namespace GostCryptographyLite
{
    /// <summary>
    ///  Class with auxiliary functions for the Magma aglorythm
    /// </summary>
    internal static class MagmaHelpFunctions
    {
        /// <summary>
        /// Permutation blocks used to avoid side-channel attacks
        /// </summary>
        private static readonly byte[] magma_boxes;

        static MagmaHelpFunctions()
        {
            byte[][][][] temp =
        [
            [
                [
                    [
                        0x6C, 0x64, 0x66, 0x62, 0x6A, 0x65, 0x6B, 0x69, 0x6E, 0x68, 0x6D, 0x67, 0x60, 0x63, 0x6F, 0x61,
                        0x8C, 0x84, 0x86, 0x82, 0x8A, 0x85, 0x8B, 0x89, 0x8E, 0x88, 0x8D, 0x87, 0x80, 0x83, 0x8F, 0x81,
                        0x2C, 0x24, 0x26, 0x22, 0x2A, 0x25, 0x2B, 0x29, 0x2E, 0x28, 0x2D, 0x27, 0x20, 0x23, 0x2F, 0x21,
                        0x3C, 0x34, 0x36, 0x32, 0x3A, 0x35, 0x3B, 0x39, 0x3E, 0x38, 0x3D, 0x37, 0x30, 0x33, 0x3F, 0x31,
                        0x9C, 0x94, 0x96, 0x92, 0x9A, 0x95, 0x9B, 0x99, 0x9E, 0x98, 0x9D, 0x97, 0x90, 0x93, 0x9F, 0x91,
                        0xAC, 0xA4, 0xA6, 0xA2, 0xAA, 0xA5, 0xAB, 0xA9, 0xAE, 0xA8, 0xAD, 0xA7, 0xA0, 0xA3, 0xAF, 0xA1,
                        0x5C, 0x54, 0x56, 0x52, 0x5A, 0x55, 0x5B, 0x59, 0x5E, 0x58, 0x5D, 0x57, 0x50, 0x53, 0x5F, 0x51,
                        0xCC, 0xC4, 0xC6, 0xC2, 0xCA, 0xC5, 0xCB, 0xC9, 0xCE, 0xC8, 0xCD, 0xC7, 0xC0, 0xC3, 0xCF, 0xC1,
                        0x1C, 0x14, 0x16, 0x12, 0x1A, 0x15, 0x1B, 0x19, 0x1E, 0x18, 0x1D, 0x17, 0x10, 0x13, 0x1F, 0x11,
                        0xEC, 0xE4, 0xE6, 0xE2, 0xEA, 0xE5, 0xEB, 0xE9, 0xEE, 0xE8, 0xED, 0xE7, 0xE0, 0xE3, 0xEF, 0xE1,
                        0x4C, 0x44, 0x46, 0x42, 0x4A, 0x45, 0x4B, 0x49, 0x4E, 0x48, 0x4D, 0x47, 0x40, 0x43, 0x4F, 0x41,
                        0x7C, 0x74, 0x76, 0x72, 0x7A, 0x75, 0x7B, 0x79, 0x7E, 0x78, 0x7D, 0x77, 0x70, 0x73, 0x7F, 0x71,
                        0xBC, 0xB4, 0xB6, 0xB2, 0xBA, 0xB5, 0xBB, 0xB9, 0xBE, 0xB8, 0xBD, 0xB7, 0xB0, 0xB3, 0xBF, 0xB1,
                        0xDC, 0xD4, 0xD6, 0xD2, 0xDA, 0xD5, 0xDB, 0xD9, 0xDE, 0xD8, 0xDD, 0xD7, 0xD0, 0xD3, 0xDF, 0xD1,
                        0x0C, 0x04, 0x06, 0x02, 0x0A, 0x05, 0x0B, 0x09, 0x0E, 0x08, 0x0D, 0x07, 0x00, 0x03, 0x0F, 0x01,
                        0xFC, 0xF4, 0xF6, 0xF2, 0xFA, 0xF5, 0xFB, 0xF9, 0xFE, 0xF8, 0xFD, 0xF7, 0xF0, 0xF3, 0xFF, 0xF1,
                    ],
                    [
                        0xCB, 0xC3, 0xC5, 0xC8, 0xC2, 0xCF, 0xCA, 0xCD, 0xCE, 0xC1, 0xC7, 0xC4, 0xCC, 0xC9, 0xC6, 0xC0,
                        0x8B, 0x83, 0x85, 0x88, 0x82, 0x8F, 0x8A, 0x8D, 0x8E, 0x81, 0x87, 0x84, 0x8C, 0x89, 0x86, 0x80,
                        0x2B, 0x23, 0x25, 0x28, 0x22, 0x2F, 0x2A, 0x2D, 0x2E, 0x21, 0x27, 0x24, 0x2C, 0x29, 0x26, 0x20,
                        0x1B, 0x13, 0x15, 0x18, 0x12, 0x1F, 0x1A, 0x1D, 0x1E, 0x11, 0x17, 0x14, 0x1C, 0x19, 0x16, 0x10,
                        0xDB, 0xD3, 0xD5, 0xD8, 0xD2, 0xDF, 0xDA, 0xDD, 0xDE, 0xD1, 0xD7, 0xD4, 0xDC, 0xD9, 0xD6, 0xD0,
                        0x4B, 0x43, 0x45, 0x48, 0x42, 0x4F, 0x4A, 0x4D, 0x4E, 0x41, 0x47, 0x44, 0x4C, 0x49, 0x46, 0x40,
                        0xFB, 0xF3, 0xF5, 0xF8, 0xF2, 0xFF, 0xFA, 0xFD, 0xFE, 0xF1, 0xF7, 0xF4, 0xFC, 0xF9, 0xF6, 0xF0,
                        0x6B, 0x63, 0x65, 0x68, 0x62, 0x6F, 0x6A, 0x6D, 0x6E, 0x61, 0x67, 0x64, 0x6C, 0x69, 0x66, 0x60,
                        0x7B, 0x73, 0x75, 0x78, 0x72, 0x7F, 0x7A, 0x7D, 0x7E, 0x71, 0x77, 0x74, 0x7C, 0x79, 0x76, 0x70,
                        0x0B, 0x03, 0x05, 0x08, 0x02, 0x0F, 0x0A, 0x0D, 0x0E, 0x01, 0x07, 0x04, 0x0C, 0x09, 0x06, 0x00,
                        0xAB, 0xA3, 0xA5, 0xA8, 0xA2, 0xAF, 0xAA, 0xAD, 0xAE, 0xA1, 0xA7, 0xA4, 0xAC, 0xA9, 0xA6, 0xA0,
                        0x5B, 0x53, 0x55, 0x58, 0x52, 0x5F, 0x5A, 0x5D, 0x5E, 0x51, 0x57, 0x54, 0x5C, 0x59, 0x56, 0x50,
                        0x3B, 0x33, 0x35, 0x38, 0x32, 0x3F, 0x3A, 0x3D, 0x3E, 0x31, 0x37, 0x34, 0x3C, 0x39, 0x36, 0x30,
                        0xEB, 0xE3, 0xE5, 0xE8, 0xE2, 0xEF, 0xEA, 0xED, 0xEE, 0xE1, 0xE7, 0xE4, 0xEC, 0xE9, 0xE6, 0xE0,
                        0x9B, 0x93, 0x95, 0x98, 0x92, 0x9F, 0x9A, 0x9D, 0x9E, 0x91, 0x97, 0x94, 0x9C, 0x99, 0x96, 0x90,
                        0xBB, 0xB3, 0xB5, 0xB8, 0xB2, 0xBF, 0xBA, 0xBD, 0xBE, 0xB1, 0xB7, 0xB4, 0xBC, 0xB9, 0xB6, 0xB0,
                    ],
                    [
                        0x57, 0x5F, 0x55, 0x5A, 0x58, 0x51, 0x56, 0x5D, 0x50, 0x59, 0x53, 0x5E, 0x5B, 0x54, 0x52, 0x5C,
                        0xD7, 0xDF, 0xD5, 0xDA, 0xD8, 0xD1, 0xD6, 0xDD, 0xD0, 0xD9, 0xD3, 0xDE, 0xDB, 0xD4, 0xD2, 0xDC,
                        0xF7, 0xFF, 0xF5, 0xFA, 0xF8, 0xF1, 0xF6, 0xFD, 0xF0, 0xF9, 0xF3, 0xFE, 0xFB, 0xF4, 0xF2, 0xFC,
                        0x67, 0x6F, 0x65, 0x6A, 0x68, 0x61, 0x66, 0x6D, 0x60, 0x69, 0x63, 0x6E, 0x6B, 0x64, 0x62, 0x6C,
                        0x97, 0x9F, 0x95, 0x9A, 0x98, 0x91, 0x96, 0x9D, 0x90, 0x99, 0x93, 0x9E, 0x9B, 0x94, 0x92, 0x9C,
                        0x27, 0x2F, 0x25, 0x2A, 0x28, 0x21, 0x26, 0x2D, 0x20, 0x29, 0x23, 0x2E, 0x2B, 0x24, 0x22, 0x2C,
                        0xC7, 0xCF, 0xC5, 0xCA, 0xC8, 0xC1, 0xC6, 0xCD, 0xC0, 0xC9, 0xC3, 0xCE, 0xCB, 0xC4, 0xC2, 0xCC,
                        0xA7, 0xAF, 0xA5, 0xAA, 0xA8, 0xA1, 0xA6, 0xAD, 0xA0, 0xA9, 0xA3, 0xAE, 0xAB, 0xA4, 0xA2, 0xAC,
                        0xB7, 0xBF, 0xB5, 0xBA, 0xB8, 0xB1, 0xB6, 0xBD, 0xB0, 0xB9, 0xB3, 0xBE, 0xBB, 0xB4, 0xB2, 0xBC,
                        0x77, 0x7F, 0x75, 0x7A, 0x78, 0x71, 0x76, 0x7D, 0x70, 0x79, 0x73, 0x7E, 0x7B, 0x74, 0x72, 0x7C,
                        0x87, 0x8F, 0x85, 0x8A, 0x88, 0x81, 0x86, 0x8D, 0x80, 0x89, 0x83, 0x8E, 0x8B, 0x84, 0x82, 0x8C,
                        0x17, 0x1F, 0x15, 0x1A, 0x18, 0x11, 0x16, 0x1D, 0x10, 0x19, 0x13, 0x1E, 0x1B, 0x14, 0x12, 0x1C,
                        0x47, 0x4F, 0x45, 0x4A, 0x48, 0x41, 0x46, 0x4D, 0x40, 0x49, 0x43, 0x4E, 0x4B, 0x44, 0x42, 0x4C,
                        0x37, 0x3F, 0x35, 0x3A, 0x38, 0x31, 0x36, 0x3D, 0x30, 0x39, 0x33, 0x3E, 0x3B, 0x34, 0x32, 0x3C,
                        0xE7, 0xEF, 0xE5, 0xEA, 0xE8, 0xE1, 0xE6, 0xED, 0xE0, 0xE9, 0xE3, 0xEE, 0xEB, 0xE4, 0xE2, 0xEC,
                        0x07, 0x0F, 0x05, 0x0A, 0x08, 0x01, 0x06, 0x0D, 0x00, 0x09, 0x03, 0x0E, 0x0B, 0x04, 0x02, 0x0C,
                    ],
                    [
                        0x18, 0x1E, 0x12, 0x15, 0x16, 0x19, 0x11, 0x1C, 0x1F, 0x14, 0x1B, 0x10, 0x1D, 0x1A, 0x13, 0x17,
                        0x78, 0x7E, 0x72, 0x75, 0x76, 0x79, 0x71, 0x7C, 0x7F, 0x74, 0x7B, 0x70, 0x7D, 0x7A, 0x73, 0x77,
                        0xE8, 0xEE, 0xE2, 0xE5, 0xE6, 0xE9, 0xE1, 0xEC, 0xEF, 0xE4, 0xEB, 0xE0, 0xED, 0xEA, 0xE3, 0xE7,
                        0xD8, 0xDE, 0xD2, 0xD5, 0xD6, 0xD9, 0xD1, 0xDC, 0xDF, 0xD4, 0xDB, 0xD0, 0xDD, 0xDA, 0xD3, 0xD7,
                        0x08, 0x0E, 0x02, 0x05, 0x06, 0x09, 0x01, 0x0C, 0x0F, 0x04, 0x0B, 0x00, 0x0D, 0x0A, 0x03, 0x07,
                        0x58, 0x5E, 0x52, 0x55, 0x56, 0x59, 0x51, 0x5C, 0x5F, 0x54, 0x5B, 0x50, 0x5D, 0x5A, 0x53, 0x57,
                        0x88, 0x8E, 0x82, 0x85, 0x86, 0x89, 0x81, 0x8C, 0x8F, 0x84, 0x8B, 0x80, 0x8D, 0x8A, 0x83, 0x87,
                        0x38, 0x3E, 0x32, 0x35, 0x36, 0x39, 0x31, 0x3C, 0x3F, 0x34, 0x3B, 0x30, 0x3D, 0x3A, 0x33, 0x37,
                        0x48, 0x4E, 0x42, 0x45, 0x46, 0x49, 0x41, 0x4C, 0x4F, 0x44, 0x4B, 0x40, 0x4D, 0x4A, 0x43, 0x47,
                        0xF8, 0xFE, 0xF2, 0xF5, 0xF6, 0xF9, 0xF1, 0xFC, 0xFF, 0xF4, 0xFB, 0xF0, 0xFD, 0xFA, 0xF3, 0xF7,
                        0xA8, 0xAE, 0xA2, 0xA5, 0xA6, 0xA9, 0xA1, 0xAC, 0xAF, 0xA4, 0xAB, 0xA0, 0xAD, 0xAA, 0xA3, 0xA7,
                        0x68, 0x6E, 0x62, 0x65, 0x66, 0x69, 0x61, 0x6C, 0x6F, 0x64, 0x6B, 0x60, 0x6D, 0x6A, 0x63, 0x67,
                        0x98, 0x9E, 0x92, 0x95, 0x96, 0x99, 0x91, 0x9C, 0x9F, 0x94, 0x9B, 0x90, 0x9D, 0x9A, 0x93, 0x97,
                        0xC8, 0xCE, 0xC2, 0xC5, 0xC6, 0xC9, 0xC1, 0xCC, 0xCF, 0xC4, 0xCB, 0xC0, 0xCD, 0xCA, 0xC3, 0xC7,
                        0xB8, 0xBE, 0xB2, 0xB5, 0xB6, 0xB9, 0xB1, 0xBC, 0xBF, 0xB4, 0xBB, 0xB0, 0xBD, 0xBA, 0xB3, 0xB7,
                        0x28, 0x2E, 0x22, 0x25, 0x26, 0x29, 0x21, 0x2C, 0x2F, 0x24, 0x2B, 0x20, 0x2D, 0x2A, 0x23, 0x27,
                    ],
                ],
                [
                    [
                        0x93, 0x9B, 0x99, 0x9D, 0x95, 0x9A, 0x94, 0x96, 0x91, 0x97, 0x92, 0x98, 0x9F, 0x9C, 0x90, 0x9E,
                        0x73, 0x7B, 0x79, 0x7D, 0x75, 0x7A, 0x74, 0x76, 0x71, 0x77, 0x72, 0x78, 0x7F, 0x7C, 0x70, 0x7E,
                        0xD3, 0xDB, 0xD9, 0xDD, 0xD5, 0xDA, 0xD4, 0xD6, 0xD1, 0xD7, 0xD2, 0xD8, 0xDF, 0xDC, 0xD0, 0xDE,
                        0xC3, 0xCB, 0xC9, 0xCD, 0xC5, 0xCA, 0xC4, 0xC6, 0xC1, 0xC7, 0xC2, 0xC8, 0xCF, 0xCC, 0xC0, 0xCE,
                        0x63, 0x6B, 0x69, 0x6D, 0x65, 0x6A, 0x64, 0x66, 0x61, 0x67, 0x62, 0x68, 0x6F, 0x6C, 0x60, 0x6E,
                        0x53, 0x5B, 0x59, 0x5D, 0x55, 0x5A, 0x54, 0x56, 0x51, 0x57, 0x52, 0x58, 0x5F, 0x5C, 0x50, 0x5E,
                        0xA3, 0xAB, 0xA9, 0xAD, 0xA5, 0xAA, 0xA4, 0xA6, 0xA1, 0xA7, 0xA2, 0xA8, 0xAF, 0xAC, 0xA0, 0xAE,
                        0x33, 0x3B, 0x39, 0x3D, 0x35, 0x3A, 0x34, 0x36, 0x31, 0x37, 0x32, 0x38, 0x3F, 0x3C, 0x30, 0x3E,
                        0xE3, 0xEB, 0xE9, 0xED, 0xE5, 0xEA, 0xE4, 0xE6, 0xE1, 0xE7, 0xE2, 0xE8, 0xEF, 0xEC, 0xE0, 0xEE,
                        0x13, 0x1B, 0x19, 0x1D, 0x15, 0x1A, 0x14, 0x16, 0x11, 0x17, 0x12, 0x18, 0x1F, 0x1C, 0x10, 0x1E,
                        0xB3, 0xBB, 0xB9, 0xBD, 0xB5, 0xBA, 0xB4, 0xB6, 0xB1, 0xB7, 0xB2, 0xB8, 0xBF, 0xBC, 0xB0, 0xBE,
                        0x83, 0x8B, 0x89, 0x8D, 0x85, 0x8A, 0x84, 0x86, 0x81, 0x87, 0x82, 0x88, 0x8F, 0x8C, 0x80, 0x8E,
                        0x43, 0x4B, 0x49, 0x4D, 0x45, 0x4A, 0x44, 0x46, 0x41, 0x47, 0x42, 0x48, 0x4F, 0x4C, 0x40, 0x4E,
                        0x23, 0x2B, 0x29, 0x2D, 0x25, 0x2A, 0x24, 0x26, 0x21, 0x27, 0x22, 0x28, 0x2F, 0x2C, 0x20, 0x2E,
                        0xF3, 0xFB, 0xF9, 0xFD, 0xF5, 0xFA, 0xF4, 0xF6, 0xF1, 0xF7, 0xF2, 0xF8, 0xFF, 0xFC, 0xF0, 0xFE,
                        0x03, 0x0B, 0x09, 0x0D, 0x05, 0x0A, 0x04, 0x06, 0x01, 0x07, 0x02, 0x08, 0x0F, 0x0C, 0x00, 0x0E,
                    ],
                    [
                        0x34, 0x3C, 0x3A, 0x37, 0x3D, 0x30, 0x35, 0x32, 0x31, 0x3E, 0x38, 0x3B, 0x33, 0x36, 0x39, 0x3F,
                        0x74, 0x7C, 0x7A, 0x77, 0x7D, 0x70, 0x75, 0x72, 0x71, 0x7E, 0x78, 0x7B, 0x73, 0x76, 0x79, 0x7F,
                        0xD4, 0xDC, 0xDA, 0xD7, 0xDD, 0xD0, 0xD5, 0xD2, 0xD1, 0xDE, 0xD8, 0xDB, 0xD3, 0xD6, 0xD9, 0xDF,
                        0xE4, 0xEC, 0xEA, 0xE7, 0xED, 0xE0, 0xE5, 0xE2, 0xE1, 0xEE, 0xE8, 0xEB, 0xE3, 0xE6, 0xE9, 0xEF,
                        0x24, 0x2C, 0x2A, 0x27, 0x2D, 0x20, 0x25, 0x22, 0x21, 0x2E, 0x28, 0x2B, 0x23, 0x26, 0x29, 0x2F,
                        0xB4, 0xBC, 0xBA, 0xB7, 0xBD, 0xB0, 0xB5, 0xB2, 0xB1, 0xBE, 0xB8, 0xBB, 0xB3, 0xB6, 0xB9, 0xBF,
                        0x04, 0x0C, 0x0A, 0x07, 0x0D, 0x00, 0x05, 0x02, 0x01, 0x0E, 0x08, 0x0B, 0x03, 0x06, 0x09, 0x0F,
                        0x94, 0x9C, 0x9A, 0x97, 0x9D, 0x90, 0x95, 0x92, 0x91, 0x9E, 0x98, 0x9B, 0x93, 0x96, 0x99, 0x9F,
                        0x84, 0x8C, 0x8A, 0x87, 0x8D, 0x80, 0x85, 0x82, 0x81, 0x8E, 0x88, 0x8B, 0x83, 0x86, 0x89, 0x8F,
                        0xF4, 0xFC, 0xFA, 0xF7, 0xFD, 0xF0, 0xF5, 0xF2, 0xF1, 0xFE, 0xF8, 0xFB, 0xF3, 0xF6, 0xF9, 0xFF,
                        0x54, 0x5C, 0x5A, 0x57, 0x5D, 0x50, 0x55, 0x52, 0x51, 0x5E, 0x58, 0x5B, 0x53, 0x56, 0x59, 0x5F,
                        0xA4, 0xAC, 0xAA, 0xA7, 0xAD, 0xA0, 0xA5, 0xA2, 0xA1, 0xAE, 0xA8, 0xAB, 0xA3, 0xA6, 0xA9, 0xAF,
                        0xC4, 0xCC, 0xCA, 0xC7, 0xCD, 0xC0, 0xC5, 0xC2, 0xC1, 0xCE, 0xC8, 0xCB, 0xC3, 0xC6, 0xC9, 0xCF,
                        0x14, 0x1C, 0x1A, 0x17, 0x1D, 0x10, 0x15, 0x12, 0x11, 0x1E, 0x18, 0x1B, 0x13, 0x16, 0x19, 0x1F,
                        0x64, 0x6C, 0x6A, 0x67, 0x6D, 0x60, 0x65, 0x62, 0x61, 0x6E, 0x68, 0x6B, 0x63, 0x66, 0x69, 0x6F,
                        0x44, 0x4C, 0x4A, 0x47, 0x4D, 0x40, 0x45, 0x42, 0x41, 0x4E, 0x48, 0x4B, 0x43, 0x46, 0x49, 0x4F,
                    ],
                    [
                        0xA8, 0xA0, 0xAA, 0xA5, 0xA7, 0xAE, 0xA9, 0xA2, 0xAF, 0xA6, 0xAC, 0xA1, 0xA4, 0xAB, 0xAD, 0xA3,
                        0x28, 0x20, 0x2A, 0x25, 0x27, 0x2E, 0x29, 0x22, 0x2F, 0x26, 0x2C, 0x21, 0x24, 0x2B, 0x2D, 0x23,
                        0x08, 0x00, 0x0A, 0x05, 0x07, 0x0E, 0x09, 0x02, 0x0F, 0x06, 0x0C, 0x01, 0x04, 0x0B, 0x0D, 0x03,
                        0x98, 0x90, 0x9A, 0x95, 0x97, 0x9E, 0x99, 0x92, 0x9F, 0x96, 0x9C, 0x91, 0x94, 0x9B, 0x9D, 0x93,
                        0x68, 0x60, 0x6A, 0x65, 0x67, 0x6E, 0x69, 0x62, 0x6F, 0x66, 0x6C, 0x61, 0x64, 0x6B, 0x6D, 0x63,
                        0xD8, 0xD0, 0xDA, 0xD5, 0xD7, 0xDE, 0xD9, 0xD2, 0xDF, 0xD6, 0xDC, 0xD1, 0xD4, 0xDB, 0xDD, 0xD3,
                        0x38, 0x30, 0x3A, 0x35, 0x37, 0x3E, 0x39, 0x32, 0x3F, 0x36, 0x3C, 0x31, 0x34, 0x3B, 0x3D, 0x33,
                        0x58, 0x50, 0x5A, 0x55, 0x57, 0x5E, 0x59, 0x52, 0x5F, 0x56, 0x5C, 0x51, 0x54, 0x5B, 0x5D, 0x53,
                        0x48, 0x40, 0x4A, 0x45, 0x47, 0x4E, 0x49, 0x42, 0x4F, 0x46, 0x4C, 0x41, 0x44, 0x4B, 0x4D, 0x43,
                        0x88, 0x80, 0x8A, 0x85, 0x87, 0x8E, 0x89, 0x82, 0x8F, 0x86, 0x8C, 0x81, 0x84, 0x8B, 0x8D, 0x83,
                        0x78, 0x70, 0x7A, 0x75, 0x77, 0x7E, 0x79, 0x72, 0x7F, 0x76, 0x7C, 0x71, 0x74, 0x7B, 0x7D, 0x73,
                        0xE8, 0xE0, 0xEA, 0xE5, 0xE7, 0xEE, 0xE9, 0xE2, 0xEF, 0xE6, 0xEC, 0xE1, 0xE4, 0xEB, 0xED, 0xE3,
                        0xB8, 0xB0, 0xBA, 0xB5, 0xB7, 0xBE, 0xB9, 0xB2, 0xBF, 0xB6, 0xBC, 0xB1, 0xB4, 0xBB, 0xBD, 0xB3,
                        0xC8, 0xC0, 0xCA, 0xC5, 0xC7, 0xCE, 0xC9, 0xC2, 0xCF, 0xC6, 0xCC, 0xC1, 0xC4, 0xCB, 0xCD, 0xC3,
                        0x18, 0x10, 0x1A, 0x15, 0x17, 0x1E, 0x19, 0x12, 0x1F, 0x16, 0x1C, 0x11, 0x14, 0x1B, 0x1D, 0x13,
                        0xF8, 0xF0, 0xFA, 0xF5, 0xF7, 0xFE, 0xF9, 0xF2, 0xFF, 0xF6, 0xFC, 0xF1, 0xF4, 0xFB, 0xFD, 0xF3,
                    ],
                    [
                        0xE7, 0xE1, 0xED, 0xEA, 0xE9, 0xE6, 0xEE, 0xE3, 0xE0, 0xEB, 0xE4, 0xEF, 0xE2, 0xE5, 0xEC, 0xE8,
                        0x87, 0x81, 0x8D, 0x8A, 0x89, 0x86, 0x8E, 0x83, 0x80, 0x8B, 0x84, 0x8F, 0x82, 0x85, 0x8C, 0x88,
                        0x17, 0x11, 0x1D, 0x1A, 0x19, 0x16, 0x1E, 0x13, 0x10, 0x1B, 0x14, 0x1F, 0x12, 0x15, 0x1C, 0x18,
                        0x27, 0x21, 0x2D, 0x2A, 0x29, 0x26, 0x2E, 0x23, 0x20, 0x2B, 0x24, 0x2F, 0x22, 0x25, 0x2C, 0x28,
                        0xF7, 0xF1, 0xFD, 0xFA, 0xF9, 0xF6, 0xFE, 0xF3, 0xF0, 0xFB, 0xF4, 0xFF, 0xF2, 0xF5, 0xFC, 0xF8,
                        0xA7, 0xA1, 0xAD, 0xAA, 0xA9, 0xA6, 0xAE, 0xA3, 0xA0, 0xAB, 0xA4, 0xAF, 0xA2, 0xA5, 0xAC, 0xA8,
                        0x77, 0x71, 0x7D, 0x7A, 0x79, 0x76, 0x7E, 0x73, 0x70, 0x7B, 0x74, 0x7F, 0x72, 0x75, 0x7C, 0x78,
                        0xC7, 0xC1, 0xCD, 0xCA, 0xC9, 0xC6, 0xCE, 0xC3, 0xC0, 0xCB, 0xC4, 0xCF, 0xC2, 0xC5, 0xCC, 0xC8,
                        0xB7, 0xB1, 0xBD, 0xBA, 0xB9, 0xB6, 0xBE, 0xB3, 0xB0, 0xBB, 0xB4, 0xBF, 0xB2, 0xB5, 0xBC, 0xB8,
                        0x07, 0x01, 0x0D, 0x0A, 0x09, 0x06, 0x0E, 0x03, 0x00, 0x0B, 0x04, 0x0F, 0x02, 0x05, 0x0C, 0x08,
                        0x57, 0x51, 0x5D, 0x5A, 0x59, 0x56, 0x5E, 0x53, 0x50, 0x5B, 0x54, 0x5F, 0x52, 0x55, 0x5C, 0x58,
                        0x97, 0x91, 0x9D, 0x9A, 0x99, 0x96, 0x9E, 0x93, 0x90, 0x9B, 0x94, 0x9F, 0x92, 0x95, 0x9C, 0x98,
                        0x67, 0x61, 0x6D, 0x6A, 0x69, 0x66, 0x6E, 0x63, 0x60, 0x6B, 0x64, 0x6F, 0x62, 0x65, 0x6C, 0x68,
                        0x37, 0x31, 0x3D, 0x3A, 0x39, 0x36, 0x3E, 0x33, 0x30, 0x3B, 0x34, 0x3F, 0x32, 0x35, 0x3C, 0x38,
                        0x47, 0x41, 0x4D, 0x4A, 0x49, 0x46, 0x4E, 0x43, 0x40, 0x4B, 0x44, 0x4F, 0x42, 0x45, 0x4C, 0x48,
                        0xD7, 0xD1, 0xDD, 0xDA, 0xD9, 0xD6, 0xDE, 0xD3, 0xD0, 0xDB, 0xD4, 0xDF, 0xD2, 0xD5, 0xDC, 0xD8,
                    ]
                ]
            ],
            [
                [
                    [
                        0xF1, 0xFF, 0xF3, 0xF0, 0xF7, 0xFD, 0xF8, 0xFE, 0xF9, 0xFB, 0xF5, 0xFA, 0xF2, 0xF6, 0xF4, 0xFC,
                        0x01, 0x0F, 0x03, 0x00, 0x07, 0x0D, 0x08, 0x0E, 0x09, 0x0B, 0x05, 0x0A, 0x02, 0x06, 0x04, 0x0C,
                        0xD1, 0xDF, 0xD3, 0xD0, 0xD7, 0xDD, 0xD8, 0xDE, 0xD9, 0xDB, 0xD5, 0xDA, 0xD2, 0xD6, 0xD4, 0xDC,
                        0xB1, 0xBF, 0xB3, 0xB0, 0xB7, 0xBD, 0xB8, 0xBE, 0xB9, 0xBB, 0xB5, 0xBA, 0xB2, 0xB6, 0xB4, 0xBC,
                        0x71, 0x7F, 0x73, 0x70, 0x77, 0x7D, 0x78, 0x7E, 0x79, 0x7B, 0x75, 0x7A, 0x72, 0x76, 0x74, 0x7C,
                        0x41, 0x4F, 0x43, 0x40, 0x47, 0x4D, 0x48, 0x4E, 0x49, 0x4B, 0x45, 0x4A, 0x42, 0x46, 0x44, 0x4C,
                        0xE1, 0xEF, 0xE3, 0xE0, 0xE7, 0xED, 0xE8, 0xEE, 0xE9, 0xEB, 0xE5, 0xEA, 0xE2, 0xE6, 0xE4, 0xEC,
                        0x11, 0x1F, 0x13, 0x10, 0x17, 0x1D, 0x18, 0x1E, 0x19, 0x1B, 0x15, 0x1A, 0x12, 0x16, 0x14, 0x1C,
                        0xC1, 0xCF, 0xC3, 0xC0, 0xC7, 0xCD, 0xC8, 0xCE, 0xC9, 0xCB, 0xC5, 0xCA, 0xC2, 0xC6, 0xC4, 0xCC,
                        0x51, 0x5F, 0x53, 0x50, 0x57, 0x5D, 0x58, 0x5E, 0x59, 0x5B, 0x55, 0x5A, 0x52, 0x56, 0x54, 0x5C,
                        0xA1, 0xAF, 0xA3, 0xA0, 0xA7, 0xAD, 0xA8, 0xAE, 0xA9, 0xAB, 0xA5, 0xAA, 0xA2, 0xA6, 0xA4, 0xAC,
                        0x91, 0x9F, 0x93, 0x90, 0x97, 0x9D, 0x98, 0x9E, 0x99, 0x9B, 0x95, 0x9A, 0x92, 0x96, 0x94, 0x9C,
                        0x31, 0x3F, 0x33, 0x30, 0x37, 0x3D, 0x38, 0x3E, 0x39, 0x3B, 0x35, 0x3A, 0x32, 0x36, 0x34, 0x3C,
                        0x21, 0x2F, 0x23, 0x20, 0x27, 0x2D, 0x28, 0x2E, 0x29, 0x2B, 0x25, 0x2A, 0x22, 0x26, 0x24, 0x2C,
                        0x81, 0x8F, 0x83, 0x80, 0x87, 0x8D, 0x88, 0x8E, 0x89, 0x8B, 0x85, 0x8A, 0x82, 0x86, 0x84, 0x8C,
                        0x61, 0x6F, 0x63, 0x60, 0x67, 0x6D, 0x68, 0x6E, 0x69, 0x6B, 0x65, 0x6A, 0x62, 0x66, 0x64, 0x6C,
                    ],
                    [
                        0xB0, 0xB6, 0xB9, 0xBC, 0xB4, 0xB7, 0xB1, 0xBE, 0xBD, 0xBA, 0xBF, 0xB2, 0xB8, 0xB5, 0xB3, 0xBB,
                        0x90, 0x96, 0x99, 0x9C, 0x94, 0x97, 0x91, 0x9E, 0x9D, 0x9A, 0x9F, 0x92, 0x98, 0x95, 0x93, 0x9B,
                        0xE0, 0xE6, 0xE9, 0xEC, 0xE4, 0xE7, 0xE1, 0xEE, 0xED, 0xEA, 0xEF, 0xE2, 0xE8, 0xE5, 0xE3, 0xEB,
                        0x30, 0x36, 0x39, 0x3C, 0x34, 0x37, 0x31, 0x3E, 0x3D, 0x3A, 0x3F, 0x32, 0x38, 0x35, 0x33, 0x3B,
                        0x50, 0x56, 0x59, 0x5C, 0x54, 0x57, 0x51, 0x5E, 0x5D, 0x5A, 0x5F, 0x52, 0x58, 0x55, 0x53, 0x5B,
                        0xA0, 0xA6, 0xA9, 0xAC, 0xA4, 0xA7, 0xA1, 0xAE, 0xAD, 0xAA, 0xAF, 0xA2, 0xA8, 0xA5, 0xA3, 0xAB,
                        0x00, 0x06, 0x09, 0x0C, 0x04, 0x07, 0x01, 0x0E, 0x0D, 0x0A, 0x0F, 0x02, 0x08, 0x05, 0x03, 0x0B,
                        0x70, 0x76, 0x79, 0x7C, 0x74, 0x77, 0x71, 0x7E, 0x7D, 0x7A, 0x7F, 0x72, 0x78, 0x75, 0x73, 0x7B,
                        0x60, 0x66, 0x69, 0x6C, 0x64, 0x67, 0x61, 0x6E, 0x6D, 0x6A, 0x6F, 0x62, 0x68, 0x65, 0x63, 0x6B,
                        0xF0, 0xF6, 0xF9, 0xFC, 0xF4, 0xF7, 0xF1, 0xFE, 0xFD, 0xFA, 0xFF, 0xF2, 0xF8, 0xF5, 0xF3, 0xFB,
                        0x40, 0x46, 0x49, 0x4C, 0x44, 0x47, 0x41, 0x4E, 0x4D, 0x4A, 0x4F, 0x42, 0x48, 0x45, 0x43, 0x4B,
                        0xD0, 0xD6, 0xD9, 0xDC, 0xD4, 0xD7, 0xD1, 0xDE, 0xDD, 0xDA, 0xDF, 0xD2, 0xD8, 0xD5, 0xD3, 0xDB,
                        0x10, 0x16, 0x19, 0x1C, 0x14, 0x17, 0x11, 0x1E, 0x1D, 0x1A, 0x1F, 0x12, 0x18, 0x15, 0x13, 0x1B,
                        0x20, 0x26, 0x29, 0x2C, 0x24, 0x27, 0x21, 0x2E, 0x2D, 0x2A, 0x2F, 0x22, 0x28, 0x25, 0x23, 0x2B,
                        0x80, 0x86, 0x89, 0x8C, 0x84, 0x87, 0x81, 0x8E, 0x8D, 0x8A, 0x8F, 0x82, 0x88, 0x85, 0x83, 0x8B,
                        0xC0, 0xC6, 0xC9, 0xCC, 0xC4, 0xC7, 0xC1, 0xCE, 0xCD, 0xCA, 0xCF, 0xC2, 0xC8, 0xC5, 0xC3, 0xCB,
                    ],
                    [
                        0x0C, 0x02, 0x04, 0x0B, 0x0E, 0x03, 0x09, 0x00, 0x0D, 0x06, 0x01, 0x08, 0x0A, 0x05, 0x0F, 0x07,
                        0xEC, 0xE2, 0xE4, 0xEB, 0xEE, 0xE3, 0xE9, 0xE0, 0xED, 0xE6, 0xE1, 0xE8, 0xEA, 0xE5, 0xEF, 0xE7,
                        0x3C, 0x32, 0x34, 0x3B, 0x3E, 0x33, 0x39, 0x30, 0x3D, 0x36, 0x31, 0x38, 0x3A, 0x35, 0x3F, 0x37,
                        0x4C, 0x42, 0x44, 0x4B, 0x4E, 0x43, 0x49, 0x40, 0x4D, 0x46, 0x41, 0x48, 0x4A, 0x45, 0x4F, 0x47,
                        0x1C, 0x12, 0x14, 0x1B, 0x1E, 0x13, 0x19, 0x10, 0x1D, 0x16, 0x11, 0x18, 0x1A, 0x15, 0x1F, 0x17,
                        0x8C, 0x82, 0x84, 0x8B, 0x8E, 0x83, 0x89, 0x80, 0x8D, 0x86, 0x81, 0x88, 0x8A, 0x85, 0x8F, 0x87,
                        0x7C, 0x72, 0x74, 0x7B, 0x7E, 0x73, 0x79, 0x70, 0x7D, 0x76, 0x71, 0x78, 0x7A, 0x75, 0x7F, 0x77,
                        0xBC, 0xB2, 0xB4, 0xBB, 0xBE, 0xB3, 0xB9, 0xB0, 0xBD, 0xB6, 0xB1, 0xB8, 0xBA, 0xB5, 0xBF, 0xB7,
                        0xAC, 0xA2, 0xA4, 0xAB, 0xAE, 0xA3, 0xA9, 0xA0, 0xAD, 0xA6, 0xA1, 0xA8, 0xAA, 0xA5, 0xAF, 0xA7,
                        0xCC, 0xC2, 0xC4, 0xCB, 0xCE, 0xC3, 0xC9, 0xC0, 0xCD, 0xC6, 0xC1, 0xC8, 0xCA, 0xC5, 0xCF, 0xC7,
                        0x2C, 0x22, 0x24, 0x2B, 0x2E, 0x23, 0x29, 0x20, 0x2D, 0x26, 0x21, 0x28, 0x2A, 0x25, 0x2F, 0x27,
                        0x9C, 0x92, 0x94, 0x9B, 0x9E, 0x93, 0x99, 0x90, 0x9D, 0x96, 0x91, 0x98, 0x9A, 0x95, 0x9F, 0x97,
                        0x6C, 0x62, 0x64, 0x6B, 0x6E, 0x63, 0x69, 0x60, 0x6D, 0x66, 0x61, 0x68, 0x6A, 0x65, 0x6F, 0x67,
                        0xFC, 0xF2, 0xF4, 0xFB, 0xFE, 0xF3, 0xF9, 0xF0, 0xFD, 0xF6, 0xF1, 0xF8, 0xFA, 0xF5, 0xFF, 0xF7,
                        0xDC, 0xD2, 0xD4, 0xDB, 0xDE, 0xD3, 0xD9, 0xD0, 0xDD, 0xD6, 0xD1, 0xD8, 0xDA, 0xD5, 0xDF, 0xD7,
                        0x5C, 0x52, 0x54, 0x5B, 0x5E, 0x53, 0x59, 0x50, 0x5D, 0x56, 0x51, 0x58, 0x5A, 0x55, 0x5F, 0x57,
                    ],
                    [
                        0x27, 0x23, 0x2A, 0x2D, 0x20, 0x2B, 0x24, 0x2F, 0x2C, 0x21, 0x29, 0x26, 0x25, 0x22, 0x2E, 0x28,
                        0xB7, 0xB3, 0xBA, 0xBD, 0xB0, 0xBB, 0xB4, 0xBF, 0xBC, 0xB1, 0xB9, 0xB6, 0xB5, 0xB2, 0xBE, 0xB8,
                        0xC7, 0xC3, 0xCA, 0xCD, 0xC0, 0xCB, 0xC4, 0xCF, 0xCC, 0xC1, 0xC9, 0xC6, 0xC5, 0xC2, 0xCE, 0xC8,
                        0x97, 0x93, 0x9A, 0x9D, 0x90, 0x9B, 0x94, 0x9F, 0x9C, 0x91, 0x99, 0x96, 0x95, 0x92, 0x9E, 0x98,
                        0x67, 0x63, 0x6A, 0x6D, 0x60, 0x6B, 0x64, 0x6F, 0x6C, 0x61, 0x69, 0x66, 0x65, 0x62, 0x6E, 0x68,
                        0xA7, 0xA3, 0xAA, 0xAD, 0xA0, 0xAB, 0xA4, 0xAF, 0xAC, 0xA1, 0xA9, 0xA6, 0xA5, 0xA2, 0xAE, 0xA8,
                        0xF7, 0xF3, 0xFA, 0xFD, 0xF0, 0xFB, 0xF4, 0xFF, 0xFC, 0xF1, 0xF9, 0xF6, 0xF5, 0xF2, 0xFE, 0xF8,
                        0x47, 0x43, 0x4A, 0x4D, 0x40, 0x4B, 0x44, 0x4F, 0x4C, 0x41, 0x49, 0x46, 0x45, 0x42, 0x4E, 0x48,
                        0x37, 0x33, 0x3A, 0x3D, 0x30, 0x3B, 0x34, 0x3F, 0x3C, 0x31, 0x39, 0x36, 0x35, 0x32, 0x3E, 0x38,
                        0x87, 0x83, 0x8A, 0x8D, 0x80, 0x8B, 0x84, 0x8F, 0x8C, 0x81, 0x89, 0x86, 0x85, 0x82, 0x8E, 0x88,
                        0x57, 0x53, 0x5A, 0x5D, 0x50, 0x5B, 0x54, 0x5F, 0x5C, 0x51, 0x59, 0x56, 0x55, 0x52, 0x5E, 0x58,
                        0x07, 0x03, 0x0A, 0x0D, 0x00, 0x0B, 0x04, 0x0F, 0x0C, 0x01, 0x09, 0x06, 0x05, 0x02, 0x0E, 0x08,
                        0xD7, 0xD3, 0xDA, 0xDD, 0xD0, 0xDB, 0xD4, 0xDF, 0xDC, 0xD1, 0xD9, 0xD6, 0xD5, 0xD2, 0xDE, 0xD8,
                        0xE7, 0xE3, 0xEA, 0xED, 0xE0, 0xEB, 0xE4, 0xEF, 0xEC, 0xE1, 0xE9, 0xE6, 0xE5, 0xE2, 0xEE, 0xE8,
                        0x77, 0x73, 0x7A, 0x7D, 0x70, 0x7B, 0x74, 0x7F, 0x7C, 0x71, 0x79, 0x76, 0x75, 0x72, 0x7E, 0x78,
                        0x17, 0x13, 0x1A, 0x1D, 0x10, 0x1B, 0x14, 0x1F, 0x1C, 0x11, 0x19, 0x16, 0x15, 0x12, 0x1E, 0x18,
                    ]
                ],
                [
                    [
                        0x0E, 0x00, 0x0C, 0x0F, 0x08, 0x02, 0x07, 0x01, 0x06, 0x04, 0x0A, 0x05, 0x0D, 0x09, 0x0B, 0x03,
                        0xFE, 0xF0, 0xFC, 0xFF, 0xF8, 0xF2, 0xF7, 0xF1, 0xF6, 0xF4, 0xFA, 0xF5, 0xFD, 0xF9, 0xFB, 0xF3,
                        0x2E, 0x20, 0x2C, 0x2F, 0x28, 0x22, 0x27, 0x21, 0x26, 0x24, 0x2A, 0x25, 0x2D, 0x29, 0x2B, 0x23,
                        0x4E, 0x40, 0x4C, 0x4F, 0x48, 0x42, 0x47, 0x41, 0x46, 0x44, 0x4A, 0x45, 0x4D, 0x49, 0x4B, 0x43,
                        0x8E, 0x80, 0x8C, 0x8F, 0x88, 0x82, 0x87, 0x81, 0x86, 0x84, 0x8A, 0x85, 0x8D, 0x89, 0x8B, 0x83,
                        0xBE, 0xB0, 0xBC, 0xBF, 0xB8, 0xB2, 0xB7, 0xB1, 0xB6, 0xB4, 0xBA, 0xB5, 0xBD, 0xB9, 0xBB, 0xB3,
                        0x1E, 0x10, 0x1C, 0x1F, 0x18, 0x12, 0x17, 0x11, 0x16, 0x14, 0x1A, 0x15, 0x1D, 0x19, 0x1B, 0x13,
                        0xEE, 0xE0, 0xEC, 0xEF, 0xE8, 0xE2, 0xE7, 0xE1, 0xE6, 0xE4, 0xEA, 0xE5, 0xED, 0xE9, 0xEB, 0xE3,
                        0x3E, 0x30, 0x3C, 0x3F, 0x38, 0x32, 0x37, 0x31, 0x36, 0x34, 0x3A, 0x35, 0x3D, 0x39, 0x3B, 0x33,
                        0xAE, 0xA0, 0xAC, 0xAF, 0xA8, 0xA2, 0xA7, 0xA1, 0xA6, 0xA4, 0xAA, 0xA5, 0xAD, 0xA9, 0xAB, 0xA3,
                        0x5E, 0x50, 0x5C, 0x5F, 0x58, 0x52, 0x57, 0x51, 0x56, 0x54, 0x5A, 0x55, 0x5D, 0x59, 0x5B, 0x53,
                        0x6E, 0x60, 0x6C, 0x6F, 0x68, 0x62, 0x67, 0x61, 0x66, 0x64, 0x6A, 0x65, 0x6D, 0x69, 0x6B, 0x63,
                        0xCE, 0xC0, 0xCC, 0xCF, 0xC8, 0xC2, 0xC7, 0xC1, 0xC6, 0xC4, 0xCA, 0xC5, 0xCD, 0xC9, 0xCB, 0xC3,
                        0xDE, 0xD0, 0xDC, 0xDF, 0xD8, 0xD2, 0xD7, 0xD1, 0xD6, 0xD4, 0xDA, 0xD5, 0xDD, 0xD9, 0xDB, 0xD3,
                        0x7E, 0x70, 0x7C, 0x7F, 0x78, 0x72, 0x77, 0x71, 0x76, 0x74, 0x7A, 0x75, 0x7D, 0x79, 0x7B, 0x73,
                        0x9E, 0x90, 0x9C, 0x9F, 0x98, 0x92, 0x97, 0x91, 0x96, 0x94, 0x9A, 0x95, 0x9D, 0x99, 0x9B, 0x93,
                    ],
                    [
                        0x4F, 0x49, 0x46, 0x43, 0x4B, 0x48, 0x4E, 0x41, 0x42, 0x45, 0x40, 0x4D, 0x47, 0x4A, 0x4C, 0x44,
                        0x6F, 0x69, 0x66, 0x63, 0x6B, 0x68, 0x6E, 0x61, 0x62, 0x65, 0x60, 0x6D, 0x67, 0x6A, 0x6C, 0x64,
                        0x1F, 0x19, 0x16, 0x13, 0x1B, 0x18, 0x1E, 0x11, 0x12, 0x15, 0x10, 0x1D, 0x17, 0x1A, 0x1C, 0x14,
                        0xCF, 0xC9, 0xC6, 0xC3, 0xCB, 0xC8, 0xCE, 0xC1, 0xC2, 0xC5, 0xC0, 0xCD, 0xC7, 0xCA, 0xCC, 0xC4,
                        0xAF, 0xA9, 0xA6, 0xA3, 0xAB, 0xA8, 0xAE, 0xA1, 0xA2, 0xA5, 0xA0, 0xAD, 0xA7, 0xAA, 0xAC, 0xA4,
                        0x5F, 0x59, 0x56, 0x53, 0x5B, 0x58, 0x5E, 0x51, 0x52, 0x55, 0x50, 0x5D, 0x57, 0x5A, 0x5C, 0x54,
                        0xFF, 0xF9, 0xF6, 0xF3, 0xFB, 0xF8, 0xFE, 0xF1, 0xF2, 0xF5, 0xF0, 0xFD, 0xF7, 0xFA, 0xFC, 0xF4,
                        0x8F, 0x89, 0x86, 0x83, 0x8B, 0x88, 0x8E, 0x81, 0x82, 0x85, 0x80, 0x8D, 0x87, 0x8A, 0x8C, 0x84,
                        0x9F, 0x99, 0x96, 0x93, 0x9B, 0x98, 0x9E, 0x91, 0x92, 0x95, 0x90, 0x9D, 0x97, 0x9A, 0x9C, 0x94,
                        0x0F, 0x09, 0x06, 0x03, 0x0B, 0x08, 0x0E, 0x01, 0x02, 0x05, 0x00, 0x0D, 0x07, 0x0A, 0x0C, 0x04,
                        0xBF, 0xB9, 0xB6, 0xB3, 0xBB, 0xB8, 0xBE, 0xB1, 0xB2, 0xB5, 0xB0, 0xBD, 0xB7, 0xBA, 0xBC, 0xB4,
                        0x2F, 0x29, 0x26, 0x23, 0x2B, 0x28, 0x2E, 0x21, 0x22, 0x25, 0x20, 0x2D, 0x27, 0x2A, 0x2C, 0x24,
                        0xEF, 0xE9, 0xE6, 0xE3, 0xEB, 0xE8, 0xEE, 0xE1, 0xE2, 0xE5, 0xE0, 0xED, 0xE7, 0xEA, 0xEC, 0xE4,
                        0xDF, 0xD9, 0xD6, 0xD3, 0xDB, 0xD8, 0xDE, 0xD1, 0xD2, 0xD5, 0xD0, 0xDD, 0xD7, 0xDA, 0xDC, 0xD4,
                        0x7F, 0x79, 0x76, 0x73, 0x7B, 0x78, 0x7E, 0x71, 0x72, 0x75, 0x70, 0x7D, 0x77, 0x7A, 0x7C, 0x74,
                        0x3F, 0x39, 0x36, 0x33, 0x3B, 0x38, 0x3E, 0x31, 0x32, 0x35, 0x30, 0x3D, 0x37, 0x3A, 0x3C, 0x34,
                    ],
                    [
                        0xF3, 0xFD, 0xFB, 0xF4, 0xF1, 0xFC, 0xF6, 0xFF, 0xF2, 0xF9, 0xFE, 0xF7, 0xF5, 0xFA, 0xF0, 0xF8,
                        0x13, 0x1D, 0x1B, 0x14, 0x11, 0x1C, 0x16, 0x1F, 0x12, 0x19, 0x1E, 0x17, 0x15, 0x1A, 0x10, 0x18,
                        0xC3, 0xCD, 0xCB, 0xC4, 0xC1, 0xCC, 0xC6, 0xCF, 0xC2, 0xC9, 0xCE, 0xC7, 0xC5, 0xCA, 0xC0, 0xC8,
                        0xB3, 0xBD, 0xBB, 0xB4, 0xB1, 0xBC, 0xB6, 0xBF, 0xB2, 0xB9, 0xBE, 0xB7, 0xB5, 0xBA, 0xB0, 0xB8,
                        0xE3, 0xED, 0xEB, 0xE4, 0xE1, 0xEC, 0xE6, 0xEF, 0xE2, 0xE9, 0xEE, 0xE7, 0xE5, 0xEA, 0xE0, 0xE8,
                        0x73, 0x7D, 0x7B, 0x74, 0x71, 0x7C, 0x76, 0x7F, 0x72, 0x79, 0x7E, 0x77, 0x75, 0x7A, 0x70, 0x78,
                        0x83, 0x8D, 0x8B, 0x84, 0x81, 0x8C, 0x86, 0x8F, 0x82, 0x89, 0x8E, 0x87, 0x85, 0x8A, 0x80, 0x88,
                        0x43, 0x4D, 0x4B, 0x44, 0x41, 0x4C, 0x46, 0x4F, 0x42, 0x49, 0x4E, 0x47, 0x45, 0x4A, 0x40, 0x48,
                        0x53, 0x5D, 0x5B, 0x54, 0x51, 0x5C, 0x56, 0x5F, 0x52, 0x59, 0x5E, 0x57, 0x55, 0x5A, 0x50, 0x58,
                        0x33, 0x3D, 0x3B, 0x34, 0x31, 0x3C, 0x36, 0x3F, 0x32, 0x39, 0x3E, 0x37, 0x35, 0x3A, 0x30, 0x38,
                        0xD3, 0xDD, 0xDB, 0xD4, 0xD1, 0xDC, 0xD6, 0xDF, 0xD2, 0xD9, 0xDE, 0xD7, 0xD5, 0xDA, 0xD0, 0xD8,
                        0x63, 0x6D, 0x6B, 0x64, 0x61, 0x6C, 0x66, 0x6F, 0x62, 0x69, 0x6E, 0x67, 0x65, 0x6A, 0x60, 0x68,
                        0x93, 0x9D, 0x9B, 0x94, 0x91, 0x9C, 0x96, 0x9F, 0x92, 0x99, 0x9E, 0x97, 0x95, 0x9A, 0x90, 0x98,
                        0x03, 0x0D, 0x0B, 0x04, 0x01, 0x0C, 0x06, 0x0F, 0x02, 0x09, 0x0E, 0x07, 0x05, 0x0A, 0x00, 0x08,
                        0x23, 0x2D, 0x2B, 0x24, 0x21, 0x2C, 0x26, 0x2F, 0x22, 0x29, 0x2E, 0x27, 0x25, 0x2A, 0x20, 0x28,
                        0xA3, 0xAD, 0xAB, 0xA4, 0xA1, 0xAC, 0xA6, 0xAF, 0xA2, 0xA9, 0xAE, 0xA7, 0xA5, 0xAA, 0xA0, 0xA8,
                    ],
                    [
                        0xD8, 0xDC, 0xD5, 0xD2, 0xDF, 0xD4, 0xDB, 0xD0, 0xD3, 0xDE, 0xD6, 0xD9, 0xDA, 0xDD, 0xD1, 0xD7,
                        0x48, 0x4C, 0x45, 0x42, 0x4F, 0x44, 0x4B, 0x40, 0x43, 0x4E, 0x46, 0x49, 0x4A, 0x4D, 0x41, 0x47,
                        0x38, 0x3C, 0x35, 0x32, 0x3F, 0x34, 0x3B, 0x30, 0x33, 0x3E, 0x36, 0x39, 0x3A, 0x3D, 0x31, 0x37,
                        0x68, 0x6C, 0x65, 0x62, 0x6F, 0x64, 0x6B, 0x60, 0x63, 0x6E, 0x66, 0x69, 0x6A, 0x6D, 0x61, 0x67,
                        0x98, 0x9C, 0x95, 0x92, 0x9F, 0x94, 0x9B, 0x90, 0x93, 0x9E, 0x96, 0x99, 0x9A, 0x9D, 0x91, 0x97,
                        0x58, 0x5C, 0x55, 0x52, 0x5F, 0x54, 0x5B, 0x50, 0x53, 0x5E, 0x56, 0x59, 0x5A, 0x5D, 0x51, 0x57,
                        0x08, 0x0C, 0x05, 0x02, 0x0F, 0x04, 0x0B, 0x00, 0x03, 0x0E, 0x06, 0x09, 0x0A, 0x0D, 0x01, 0x07,
                        0xB8, 0xBC, 0xB5, 0xB2, 0xBF, 0xB4, 0xBB, 0xB0, 0xB3, 0xBE, 0xB6, 0xB9, 0xBA, 0xBD, 0xB1, 0xB7,
                        0xC8, 0xCC, 0xC5, 0xC2, 0xCF, 0xC4, 0xCB, 0xC0, 0xC3, 0xCE, 0xC6, 0xC9, 0xCA, 0xCD, 0xC1, 0xC7,
                        0x78, 0x7C, 0x75, 0x72, 0x7F, 0x74, 0x7B, 0x70, 0x73, 0x7E, 0x76, 0x79, 0x7A, 0x7D, 0x71, 0x77,
                        0xA8, 0xAC, 0xA5, 0xA2, 0xAF, 0xA4, 0xAB, 0xA0, 0xA3, 0xAE, 0xA6, 0xA9, 0xAA, 0xAD, 0xA1, 0xA7,
                        0xF8, 0xFC, 0xF5, 0xF2, 0xFF, 0xF4, 0xFB, 0xF0, 0xF3, 0xFE, 0xF6, 0xF9, 0xFA, 0xFD, 0xF1, 0xF7,
                        0x28, 0x2C, 0x25, 0x22, 0x2F, 0x24, 0x2B, 0x20, 0x23, 0x2E, 0x26, 0x29, 0x2A, 0x2D, 0x21, 0x27,
                        0x18, 0x1C, 0x15, 0x12, 0x1F, 0x14, 0x1B, 0x10, 0x13, 0x1E, 0x16, 0x19, 0x1A, 0x1D, 0x11, 0x17,
                        0x88, 0x8C, 0x85, 0x82, 0x8F, 0x84, 0x8B, 0x80, 0x83, 0x8E, 0x86, 0x89, 0x8A, 0x8D, 0x81, 0x87,
                        0xE8, 0xEC, 0xE5, 0xE2, 0xEF, 0xE4, 0xEB, 0xE0, 0xE3, 0xEE, 0xE6, 0xE9, 0xEA, 0xED, 0xE1, 0xE7,
                    ]
                ]
            ]
        ];

            magma_boxes = new byte[2 * 2 * 4 * 256];

            int index = 0;
            for (int j = 0; j < 2; j++)
            {
                for (int i = 0; i < 2; i++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        for (int b = 0; b < 256; b++)
                        {
                            magma_boxes[index++] = temp[j][i][k][b];
                        }
                    }
                }
            }
        }

        /// <summary>
        /// Increment counter in array form
        /// </summary>
        /// <param name="array"></param>
        public static void FastArrayIncrement(byte[] array)
        {
            bool per = (array[7] += 1) == 0;
            for (int j = 6; j >= 0 && per; per = (array[j] += 1) == 0, j--) ;
        }

        /// <summary>
        /// Applying of a substitution that protects against side-channel attacks.
        /// </summary>
        /// <param name="input">Input vector</param>
        /// <param name="i">Parameter that define the path</param>
        /// <param name="j">Parameter that define the path</param>
        /// <returns>Vector after aplling aof a substitution</returns>
        public static uint MagmaGostFBoxes(uint input, int i, int j)
        {
            int baseIndex = (j << 11) | (i << 10);

            uint output =
                ((uint)magma_boxes[baseIndex + (3 << 8) + ((input >> 24) & 0xFF)]) << 24 |
                ((uint)magma_boxes[baseIndex + (2 << 8) + ((input >> 16) & 0xFF)]) << 16 |
                ((uint)magma_boxes[baseIndex + (1 << 8) + ((input >> 8) & 0xFF)]) << 8 |
                ((uint)magma_boxes[baseIndex + (0 << 8) + (input & 0xFF)]);

            return (output << 11) | (output >> (32 - 11));
        }
    }
}
