using System;
using System.Security.Cryptography;
using System.Text;
using GPN600_001_Testtool.Models.Communication;

namespace GPN600_001_Testtool.Models.Cryptography
{
    /// <summary>
    /// TR-31 (ASC X9 TR 31-2018) Key Block Format with AES-128.
    /// Spec ASL-NP-37625-03 §6.1: 144-byte ASCII block = 16-byte ASCII header + 96-byte ASCII ciphertext + 32-byte ASCII MAC.
    /// </summary>
    public static class Tr31Aes128Crypto
    {
        // KDIDs from spec §6.1 (a). 0002 = AES-128, 0080 = 128-bit key length.
        private static readonly byte[] KDID_ENC_KEY = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x80 };
        private static readonly byte[] KDID_MAC_KEY = { 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x00, 0x80 };

        // Key-Length field is fixed at 0x0080 (128 bits) regardless of padding size.
        private static readonly byte[] KEY_LENGTH_FIELD = { 0x00, 0x80 };

        private const int PaddingBytes = 30;   // gives 144-byte block per spec p.21
        private const int BlockLength = 144;

        /// <summary>
        /// CGQ payload: wraps Ke under Km. Header per spec p.21: D0144K1AD00N0000.
        /// </summary>
        public static byte[] EncryptKeKeyAes128(byte[] kbpk, byte[] keyData, string portName = null)
        {
            return EncryptKeyBlock(kbpk, keyData, BuildHeader("K1", 'D'), portName);
        }

        /// <summary>
        /// CGR payload: wraps Kwa under Ke. Header per spec p.21: D0144D0AB00N0000.
        /// </summary>
        public static byte[] EncryptKwaKeyAes128(byte[] kbpk, byte[] keyData, string portName = null)
        {
            return EncryptKeyBlock(kbpk, keyData, BuildHeader("D0", 'B'), portName);
        }

        /// <summary>
        /// CGT payload: wraps Kwp (PIN key) under Ke. Spec p.21 specifies the same
        /// D0144D0AB00N0000 header as Kwa (D0 / B). Confirmed by team — auth flow used D0.
        /// </summary>
        public static byte[] EncryptKwpKeyAes128(byte[] kbpk, byte[] keyData, string portName = null)
        {
            return EncryptKeyBlock(kbpk, keyData, BuildHeader("D0", 'B'), portName);
        }

        private static byte[] BuildHeader(string keyUsage, char modeOfUse)
        {
            string header = $"D{BlockLength:D4}{keyUsage}A{modeOfUse}00N0000";
            if (header.Length != 16)
                throw new InvalidOperationException($"Key Block Header must be 16 bytes, got {header.Length}: {header}");
            return Encoding.ASCII.GetBytes(header);
        }

        private static byte[] EncryptKeyBlock(byte[] kbpk, byte[] keyData, byte[] header, string portName)
        {
            if (kbpk == null || kbpk.Length != 16)
                throw new ArgumentException("KBPK must be 16 bytes", nameof(kbpk));
            if (keyData == null || keyData.Length != 16)
                throw new ArgumentException("Key data must be 16 bytes", nameof(keyData));

            WriteTrace(portName, "=== TR-31 AES128 Encryption Started ===");
            WriteTrace(portName, $"KBPK={Hex(kbpk)}");
            WriteTrace(portName, $"KeyData={Hex(keyData)}");
            WriteTrace(portName, $"Header={Encoding.ASCII.GetString(header)}");

            byte[] encryptionKey = CalculateCmacAes128(kbpk, KDID_ENC_KEY);
            byte[] macKey = CalculateCmacAes128(kbpk, KDID_MAC_KEY);

            byte[] padding = new byte[PaddingBytes];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(padding);

            // MAC input = Header || KeyLength || Key || Padding (per TR-31 §5.3)
            byte[] macInput = Concat(header, KEY_LENGTH_FIELD, keyData, padding);
            byte[] mac = CalculateCmacAes128(macKey, macInput);

            // Encrypt input = KeyLength || Key || Padding (header is NOT encrypted)
            byte[] plaintext = Concat(KEY_LENGTH_FIELD, keyData, padding);
            byte[] ciphertext = EncryptAes128Cbc(encryptionKey, plaintext, mac);

            // Final block = Header (ASCII, 16) + Ciphertext (hex-ASCII, 96) + MAC (hex-ASCII, 32) = 144 bytes
            string ciphertextHex = BitConverter.ToString(ciphertext).Replace("-", "");
            string macHex = BitConverter.ToString(mac).Replace("-", "");

            byte[] output = new byte[16 + ciphertextHex.Length + macHex.Length];
            Buffer.BlockCopy(header, 0, output, 0, 16);
            Buffer.BlockCopy(Encoding.ASCII.GetBytes(ciphertextHex), 0, output, 16, ciphertextHex.Length);
            Buffer.BlockCopy(Encoding.ASCII.GetBytes(macHex), 0, output, 16 + ciphertextHex.Length, macHex.Length);

            WriteTrace(portName, $"TR-31 block ({output.Length} bytes ASCII): {Encoding.ASCII.GetString(output)}");
            WriteTrace(portName, "=== TR-31 AES128 Encryption Completed ===");

            return output;
        }

        // CMAC-AES-128 per RFC 4493 (using AES-128 single-block under IV=0 as the underlying primitive).
        private static byte[] CalculateCmacAes128(byte[] key, byte[] data)
        {
            byte[] zero = new byte[16];
            byte[] l = AesEcbBlock(key, zero);

            byte[] k1 = LeftShift(l);
            if ((l[0] & 0x80) != 0) k1[15] ^= 0x87;

            byte[] k2 = LeftShift(k1);
            if ((k1[0] & 0x80) != 0) k2[15] ^= 0x87;

            byte[] padded;
            byte[] subkey;
            if (data.Length > 0 && data.Length % 16 == 0)
            {
                padded = new byte[data.Length];
                Array.Copy(data, padded, data.Length);
                subkey = k1;
            }
            else
            {
                int paddedLen = ((data.Length / 16) + 1) * 16;
                padded = new byte[paddedLen];
                Array.Copy(data, padded, data.Length);
                padded[data.Length] = 0x80;
                subkey = k2;
            }

            byte[] mac = new byte[16];
            for (int i = 0; i < padded.Length; i += 16)
            {
                for (int j = 0; j < 16; j++) mac[j] ^= padded[i + j];
                if (i + 16 >= padded.Length)
                    for (int j = 0; j < 16; j++) mac[j] ^= subkey[j];
                mac = AesEcbBlock(key, mac);
            }
            return mac;
        }

        private static byte[] AesEcbBlock(byte[] key, byte[] data)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using (var encryptor = aes.CreateEncryptor())
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
            }
        }

        private static byte[] EncryptAes128Cbc(byte[] key, byte[] data, byte[] iv)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.None;
                using (var encryptor = aes.CreateEncryptor())
                    return encryptor.TransformFinalBlock(data, 0, data.Length);
            }
        }

        private static byte[] LeftShift(byte[] input)
        {
            byte[] output = new byte[input.Length];
            bool carry = false;
            for (int i = input.Length - 1; i >= 0; i--)
            {
                output[i] = (byte)(input[i] << 1);
                if (carry) output[i] |= 0x01;
                carry = (input[i] & 0x80) != 0;
            }
            return output;
        }

        private static byte[] Concat(params byte[][] arrays)
        {
            int len = 0;
            foreach (var a in arrays) len += a.Length;
            byte[] result = new byte[len];
            int offset = 0;
            foreach (var a in arrays)
            {
                Buffer.BlockCopy(a, 0, result, offset, a.Length);
                offset += a.Length;
            }
            return result;
        }

        private static string Hex(byte[] b) => BitConverter.ToString(b).Replace("-", "");

        private static void WriteTrace(string portName, string message)
        {
            if (string.IsNullOrEmpty(portName)) return;
            try { NidecLibWrapper.TraceWrite(portName, message); }
            catch { /* trace failures must not break crypto */ }
        }
    }
}
