using System;
using System.Security.Cryptography;

namespace GPN600_001_Testtool.Models.Cryptography
{
    public static class Aes128Crypto
    {
        public static byte[] EncryptAes128(byte[] key, byte[] data)
        {
            if (key == null || key.Length != 16)
                throw new ArgumentException("Key must be 16 bytes for AES128", nameof(key));
            if (data == null || (data.Length != 16 && data.Length != 32))
                throw new ArgumentException("Data must be 16 or 32 bytes", nameof(data));

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (var encryptor = aes.CreateEncryptor())
                {
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
                }
            }
        }

        public static byte[] DecryptAes128(byte[] key, byte[] encryptedData)
        {
            if (key == null || key.Length != 16)
                throw new ArgumentException("Key must be 16 bytes for AES128", nameof(key));
            if (encryptedData == null || (encryptedData.Length != 16 && encryptedData.Length != 32))
                throw new ArgumentException("Encrypted data must be 16 or 32 bytes", nameof(encryptedData));

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(encryptedData, 0, encryptedData.Length);
                }
            }
        }

        public static byte[] HexStringToBytes(string hexString)
        {
            if (string.IsNullOrEmpty(hexString))
                throw new ArgumentException("Hex string cannot be null or empty", nameof(hexString));

            hexString = hexString.Replace(" ", "").Replace("-", "");
            if (hexString.Length % 2 != 0)
                throw new ArgumentException("Hex string must have even number of characters", nameof(hexString));

            byte[] result = new byte[hexString.Length / 2];
            for (int i = 0; i < result.Length; i++)
                result[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return result;
        }

        public static string BytesToHexString(byte[] bytes, bool spaceSeparated = true)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            return spaceSeparated
                ? BitConverter.ToString(bytes).Replace("-", " ")
                : BitConverter.ToString(bytes).Replace("-", "");
        }

        public static void SecureClear(byte[] data)
        {
            if (data != null) Array.Clear(data, 0, data.Length);
        }

        public static bool IsValidHexString(string hexString, int expectedBytes = 0)
        {
            if (string.IsNullOrEmpty(hexString)) return false;
            string clean = hexString.Replace(" ", "").Replace("-", "");
            if (expectedBytes > 0 && clean.Length != expectedBytes * 2) return false;
            if (clean.Length % 2 != 0) return false;
            foreach (char c in clean)
                if (!Uri.IsHexDigit(c)) return false;
            return true;
        }

        public static byte[] GenerateRandomKey(int keySize)
        {
            if (keySize <= 0)
                throw new ArgumentException("Key size must be greater than 0", nameof(keySize));

            byte[] key = new byte[keySize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(key);
            }
            return key;
        }
    }
}
