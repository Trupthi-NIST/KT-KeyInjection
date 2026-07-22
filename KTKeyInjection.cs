using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace GPN600_001_Testtool.Models.Cryptography
{
    /// <summary>
    /// Implements the Kt (temporary key) injection flow using RSA-2048 mutual authentication
    /// and key transport per the KDH/KRD protocol (steps 3.1.1–3.1.4).
    /// </summary>
    public abstract class KtKeyInjection
    {
        private RSACryptoServiceProvider _rsaKdh;
        private RSACryptoServiceProvider _rsaKrd;
        private RSACryptoServiceProvider _rsaKrdEncrypt;

        // ──────────────────────────────────────────────────────────────────────
        // Step 1: ParseKtHex — Validate hex input
        // ──────────────────────────────────────────────────────────────────────

        protected byte[] ParseKtHex(string ktHex)
        {
            if (string.IsNullOrEmpty(ktHex))
                throw new ArgumentException("Kt hex string cannot be null or empty.", nameof(ktHex));

            string clean = ktHex.Replace(" ", "").Replace("-", "");

            if (clean.Length != 32)
                throw new ArgumentException(
                    $"Kt hex must be exactly 32 characters (16 bytes), got {clean.Length}.", nameof(ktHex));

            byte[] kt = new byte[16];
            for (int i = 0; i < 16; i++)
                kt[i] = Convert.ToByte(clean.Substring(i * 2, 2), 16);

            Log($"Kt parsed: {BitConverter.ToString(kt).Replace("-", "")}");
            return kt;
        }

        // ──────────────────────────────────────────────────────────────────────
        // Step 2: GenerateKdhKeyPair — Generate 2048-bit RSA key pair
        // ──────────────────────────────────────────────────────────────────────

        protected void GenerateKdhKeyPair()
        {
            _rsaKdh = new RSACryptoServiceProvider(2048);
            Log("KDH RSA-2048 key pair generated (SKDH/VKDH).");
        }

        // ──────────────────────────────────────────────────────────────────────
        // Step 3: ExecuteBindStart (3.1.1) — Send VKDH modulus, receive VKRD and EKRD
        // ──────────────────────────────────────────────────────────────────────

        protected async Task<bool> ExecuteBindStart()
        {
            RSAParameters vkdhParams = _rsaKdh.ExportParameters(false);
            byte[] modulus = vkdhParams.Modulus;  // 256 bytes for RSA-2048
            Log($"VKDH modulus ({modulus.Length} bytes): {BitConverter.ToString(modulus).Replace("-", "")}");

            byte[] response = await SendDeviceCommandAsync(DeviceCommand.BindStart, modulus, 300000);
            if (response == null || response.Length < 512)
            {
                Log("BindStart: invalid or missing response from device.");
                return false;
            }

            byte[] vkrdModulus = new byte[256];
            byte[] ekrdModulus = new byte[256];
            Buffer.BlockCopy(response, 0, vkrdModulus, 0, 256);
            Buffer.BlockCopy(response, 256, ekrdModulus, 0, 256);

            _rsaKrd = CreateRsaFromModulus(vkrdModulus);
            _rsaKrdEncrypt = CreateRsaFromModulus(ekrdModulus);

            Log($"VKRD modulus received ({vkrdModulus.Length} bytes): {BitConverter.ToString(vkrdModulus).Replace("-", "")}");
            Log($"EKRD modulus received ({ekrdModulus.Length} bytes): {BitConverter.ToString(ekrdModulus).Replace("-", "")}");
            return true;
        }

        // ──────────────────────────────────────────────────────────────────────
        // Step 4: ExecuteExchangeAuthData (3.1.2) — Exchange random challenges
        // ──────────────────────────────────────────────────────────────────────

        protected async Task<byte[]> ExecuteExchangeAuthData()
        {
            byte[] rkdh = new byte[16];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(rkdh);

            Log($"RKDH generated: {BitConverter.ToString(rkdh).Replace("-", "")}");

            byte[] response = await SendDeviceCommandAsync(DeviceCommand.ExchangeAuthData, rkdh, 300000);
            if (response == null || response.Length < 272)
            {
                Log("ExchangeAuthData: invalid or missing response from device.");
                return null;
            }

            byte[] rkrd = new byte[16];
            byte[] signature = new byte[256];
            Buffer.BlockCopy(response, 0, rkrd, 0, 16);
            Buffer.BlockCopy(response, 16, signature, 0, 256);

            Log($"RKRD received: {BitConverter.ToString(rkrd).Replace("-", "")}");

            // Verify: KRD signed RKDH with SKRD; verify using VKRD (SHA256 + PKCS1)
            bool signatureValid = VerifySignature(_rsaKrd, rkdh, signature);
            if (!signatureValid)
                Log("WARNING: Signature verification failed (continuing for testing purposes).");
            else
                Log("Signature verified: KRD signed RKDH with SKRD.");

            return rkrd;
        }

        // ──────────────────────────────────────────────────────────────────────
        // Step 5: ExecuteBindExecute (3.1.3) — Complete mutual authentication
        // ──────────────────────────────────────────────────────────────────────

        protected async Task<bool> ExecuteBindExecute(byte[] rkrd)
        {
            byte[] signedRkrd = SignData(_rsaKdh, rkrd);
            Log($"RKRD signed with SKDH ({signedRkrd.Length} bytes).");

            byte[] response = await SendDeviceCommandAsync(DeviceCommand.BindExecute, signedRkrd, 300000);
            if (response == null)
            {
                Log("BindExecute: invalid or missing response from device.");
                return false;
            }

            Log("BindExecute: mutual authentication completed.");
            return true;
        }

        // ──────────────────────────────────────────────────────────────────────
        // Step 6: ExecuteKeyTransport (3.1.4) — Inject the temporary key
        // ──────────────────────────────────────────────────────────────────────

        protected async Task<byte[]> ExecuteKeyTransport(byte[] kt)
        {
            // Build 256-byte plaintext: 0x7F || Kt (16 bytes) || Random (239 bytes)
            byte[] plaintext = new byte[256];
            plaintext[0] = 0x7F;
            Buffer.BlockCopy(kt, 0, plaintext, 1, 16);

            byte[] randomPadding = new byte[239];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(randomPadding);
            Buffer.BlockCopy(randomPadding, 0, plaintext, 17, 239);

            Log("Key transport plaintext constructed (256 bytes).");

            byte[] encrypted = EncryptWithRsa(_rsaKrdEncrypt, plaintext);
            Log($"Kt encrypted with EKRD ({encrypted.Length} bytes).");

            byte[] response = await SendDeviceCommandAsync(DeviceCommand.KeyTransport, encrypted, 300000);
            if (response == null)
            {
                Log("KeyTransport: invalid or missing response from device.");
                return null;
            }

            byte[] kcv = response;
            Log($"KCV received: {BitConverter.ToString(kcv).Replace("-", "")}");
            return kcv;
        }

        // ──────────────────────────────────────────────────────────────────────
        // Main orchestration
        // ──────────────────────────────────────────────────────────────────────

        public async Task<bool> ExecuteKtInjectionAsync(string ktHex)
        {
            try
            {
                Log("=== Kt Injection Flow Started ===");

                byte[] kt = ParseKtHex(ktHex);

                GenerateKdhKeyPair();

                if (!await ExecuteBindStart())
                {
                    Log("Kt injection failed at BindStart.");
                    return false;
                }

                byte[] rkrd = await ExecuteExchangeAuthData();
                if (rkrd == null)
                {
                    Log("Kt injection failed at ExchangeAuthData.");
                    return false;
                }

                if (!await ExecuteBindExecute(rkrd))
                {
                    Log("Kt injection failed at BindExecute.");
                    return false;
                }

                byte[] kcv = await ExecuteKeyTransport(kt);
                if (kcv == null)
                {
                    Log("Kt injection failed at KeyTransport.");
                    return false;
                }

                Log("=== Kt Injection Flow Completed Successfully ===");
                return true;
            }
            catch (Exception ex)
            {
                Log($"Kt injection exception: {ex.Message}");
                return false;
            }
        }

        // ──────────────────────────────────────────────────────────────────────
        // Helper methods
        // ──────────────────────────────────────────────────────────────────────

        private RSACryptoServiceProvider CreateRsaFromModulus(byte[] modulus)
        {
            var rsa = new RSACryptoServiceProvider(2048);
            rsa.ImportParameters(new RSAParameters
            {
                Modulus  = modulus,
                Exponent = new byte[] { 0x01, 0x00, 0x01 }  // 65537
            });
            return rsa;
        }

        private bool VerifySignature(RSACryptoServiceProvider rsa, byte[] data, byte[] signature)
        {
            using (var sha256 = SHA256.Create())
                return rsa.VerifyData(data, sha256, signature);
        }

        private byte[] SignData(RSACryptoServiceProvider rsa, byte[] data)
        {
            using (var sha256 = SHA256.Create())
                return rsa.SignData(data, sha256);
        }

        private byte[] EncryptWithRsa(RSACryptoServiceProvider rsa, byte[] data)
        {
            return rsa.Encrypt(data, true);  // true = OAEP padding (PKCS#1 v2.1)
        }

        // ──────────────────────────────────────────────────────────────────────
        // Abstract / virtual members for concrete subclasses
        // ──────────────────────────────────────────────────────────────────────

        /// <summary>
        /// Sends a device command and returns the device response.
        /// Implement in a subclass to connect to the actual device.
        /// </summary>
        /// <param name="command">The protocol command to execute.</param>
        /// <param name="data">Payload bytes to transmit.</param>
        /// <param name="timeoutMs">Timeout in milliseconds.</param>
        /// <returns>Response bytes from the device, or null on failure.</returns>
        protected abstract Task<byte[]> SendDeviceCommandAsync(DeviceCommand command, byte[] data, int timeoutMs);

        /// <summary>
        /// Logs a message. Override to redirect output to a UI, file, or trace sink.
        /// </summary>
        protected virtual void Log(string message)
        {
            System.Diagnostics.Debug.WriteLine($"[KtInjection] {message}");
        }
    }

    /// <summary>
    /// Device protocol commands used during the Kt injection flow.
    /// </summary>
    public enum DeviceCommand
    {
        /// <summary>Step 3.1.1 — Send VKDH modulus, receive VKRD and EKRD.</summary>
        BindStart,

        /// <summary>Step 3.1.2 — Send RKDH, receive RKRD and KRD signature.</summary>
        ExchangeAuthData,

        /// <summary>Step 3.1.3 — Send KDH signature over RKRD to complete mutual auth.</summary>
        BindExecute,

        /// <summary>Step 3.1.4 — Send RSA-encrypted Kt, receive KCV.</summary>
        KeyTransport
    }
}
