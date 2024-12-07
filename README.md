# GOST cryptoalgorithms in C#

##  Attention: this library is not certified and will not be in the future. Therefore, it is only available for use in a number of scenarios

## Requirments

- .NET 9

## Installiation

Clone this repository and move the GostCryptographyLite project. In the future, it will be possible to use a NuGet package of this library.

## Encryption and decrption

### Example

``` csharp
using GostCryptographyLite;
using System.Security.Cryptography;

namespace TestGost
{
    internal class Program
    {
        static void Main(string[] args)
        {
            byte[] data = { 0x92, 0xde, 0xf0, 0x6b, 0x3c, 0x13, 0x0a, 0x59,
                            0xdb, 0x54, 0xc7, 0x04, 0xf8, 0x18, 0x9d, 0x20,
                            0x4a, 0x98, 0xfb, 0x2e, 0x67, 0xa8, 0x02, 0x4c,
                            0x89, 0x12, 0x40, 0x9b, 0x17 };

            Console.WriteLine("Input data:     " + BitConverter.ToString(data, 0, data.Length).Replace("-", "").ToLower());

            // Magma instance creation
            using (Magma magma = new Magma(GostCipherMode.OFB, PaddingMode.PKCS7, true)) // To use Kuznechik, replace Magma with Kuznechik
            {
                var key = new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00,
                                       0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

                var iv = new byte[] { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
                                      0x23, 0x45, 0x67, 0x89, 0x0a, 0xbc, 0xde, 0xf1 };

                // Encryptor creation
                var encryptor = magma.CreateEncryptor(key, iv);
                byte[] encryptedData;

                // Encrypt data with CryptoStream
                using (var memoryStream = new MemoryStream())
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    cryptoStream.Write(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();

                    encryptedData = memoryStream.ToArray();
                    Console.WriteLine("Encrypted data: " + BitConverter.ToString(encryptedData).Replace("-", "").ToLower());
                }

                // Decryptor creation
                var decryptor = magma.CreateDecryptor(key, iv);
                byte[] decryptedData;

                // Decrypt data with CryptoStream
                using (var memoryStream = new MemoryStream(encryptedData))
                using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                using (var readMemoryStream = new MemoryStream())
                {
                    cryptoStream.CopyTo(readMemoryStream);
                    decryptedData = readMemoryStream.ToArray();

                    Console.WriteLine("Decrypted data: " + BitConverter.ToString(decryptedData).Replace("-", "").ToLower());
                }
            }
        }
    }
}
```

From the example, it is clear that this library interacts with the traditional C# CryptoStream, which facilitates its integration into both new systems and existing ones.

### Important: It is highly recommended to use CryptoStream instead of the methods TransformBlock and TransformFinalBlock.

Program output:
```
Input data:     92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17
Encrypted data: db37e0e266903c830d46644c1f9a089ca0f83062430e327ec824efb8bdf9a647
Decrypted data: 92def06b3c130a59db54c704f8189d204a98fb2e67a8024c8912409b17
```

###  Avaliabale cipher modes
| Значение | Режим шифрования | Пояснение                           |
|----------|------------------|-------------------------------------|
| 1        | CBC              | Cipher Block Chaining.              |
| 2        | ECB              | Electronic Codebook.                |
| 3        | OFB              | Output Feedback.                    |
| 4        | CFB              | Cipher Feedback.                    |
| 5        | CTS              | Cipher Text Stealing. (Not using)   |
| 6        | CTR              | Counter mode.                       |

### IV length info

In GOST, encryption modes allow the use of an initialization vector with a length greater than the block size, but it must be a multiple of the block size. This behavior is NOT implemented when assigning an initialization vector to instances of the Magma and Kuznechik classes. To utilize this behavior, initialization vectors longer than the block size should be passed to the CreateEncryptor/CreateDecryptor methods as shown in example above.

### Some links to articles where the implementation was done

[Fast Implementation and Cryptanalysis of GOST R 34.12-2015 Block Ciphers (Payed accsess)](https://www.semanticscholar.org/paper/Fast-Implementation-and-Cryptanalysis-of-GOST-R-Ishchukova-Babenko/aa3d98d0b6e23617105baa32e5e3da2173dba6aa)

[S. V. Matveev, “GOST 28147-89 masking against side channel attacks”](https://www.mathnet.ru/links/d35f50fe8287f532f7a02f1d72a7d6a1/mvk143.pdf)
