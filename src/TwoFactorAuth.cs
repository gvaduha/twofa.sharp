using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using OtpNet;

namespace gvaduha.twofa
{
    /// <summary>
    /// Application user's status of SCA configuration
    /// </summary>
    public enum ScaFactorStatus
    {
        [Description("N")]
        NotConfigured,
        [Description("W")]
        WaitingForConfirmation,
        [Description("E")]
        Enabled,
        [Description("D")]
        Disabled,
    }

    /// <summary>
    /// Application user's settings for SCA
    /// </summary>
    public struct AccountScaDetails : IAccountScaDetails
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="status">Status of SCA</param>
        /// <param name="secret">Shared secret</param>
        /// <param name="faultAttempts">Current counter of attempts to process SCA</param>
        AccountScaDetails(ScaFactorStatus status, string secret, byte faultAttempts)
        {
            Status = status;
            FaultAttempts = faultAttempts;
            SharedSecret = secret;
        }
        /// <summary>
        /// Status of SCA
        /// </summary>
        public ScaFactorStatus Status { get; set; }

        /// <summary>
        /// Shared secret using for TOTP
        /// </summary>
        public string SharedSecret { get; set; }

        /// <summary>
        /// Current counter of attempts to process SCA
        /// </summary>
        public byte FaultAttempts { get; set; }
    }

    /// <summary>
    /// TOTP algorithm settings
    /// </summary>
    struct TotpAuthenticationFactorConfig
    {
        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="codeSize">Truncate auth code to this value</param>
        /// <param name="codeStep">Auth code valid time frame in seconds</param>
        /// <param name="codeWindow">Auth code frame of tolerance codeWindow (-n..code..+n)</param>
        /// <param name="secretSize">Size of shared secret in symbols</param>
        public TotpAuthenticationFactorConfig(byte codeSize, byte codeStep, byte codeWindow, uint secretSize)
        {
            CodeSize = codeSize;
            CodeStep = codeStep;
            CodeWindow = codeWindow;
            SecretSize = secretSize;
        }

        /// <summary>
        /// Truncate auth code to this value
        /// </summary>
        public readonly byte CodeSize;

        /// <summary>
        /// Auth code valid time frame in seconds
        /// </summary>
        public readonly byte CodeStep;

        /// <summary>
        /// Auth code frame of tolerance codeWindow (-n..code..+n)
        /// </summary>
        public readonly byte CodeWindow;

        /// <summary>
        /// Size of shared secret in symbols
        /// </summary>
        public readonly uint SecretSize;

        /// <summary>
        /// Default configuration
        /// </summary>
        public static TotpAuthenticationFactorConfig Default { get; } = new TotpAuthenticationFactorConfig(6,30,5,32);
    }

    /// <summary>
    /// TOTP algorithm
    /// </summary>
    sealed class TotpAuthenticationFactor : IDisposable
    {
        private readonly RNGCryptoServiceProvider _rng = new RNGCryptoServiceProvider();
        private readonly TotpAuthenticationFactorConfig _config;
        public TotpAuthenticationFactor(TotpAuthenticationFactorConfig config)
        {
            _config = config;
        }

        // 
        /// <summary>
        /// Generates base32 shared secret
        /// </summary>
        /// <returns>base32 shared secret string</returns>
        public string GenerateSharedSecret()
        {
            var buffSize = (uint) Math.Ceiling(_config.SecretSize * 8d / 5d);
            byte [] random = new byte[buffSize];
            _rng.GetBytes(random); // could trigger exceptions
            return Base32Encoding.ToString(random).Substring(0, (int)_config.SecretSize);
        }

        /// <summary>
        /// Generates TOTP
        /// </summary>
        /// <param name="secret">shared secret. The value size should be of config.SecretSize</param>
        /// <returns>TOTP string</returns>
        public string GenerateTotp(string secret)
        {
            if (string.IsNullOrWhiteSpace(secret) || _config.SecretSize != secret.Length)
                throw new InvalidEnumArgumentException(nameof(secret));

            var secraw = Encoding.ASCII.GetBytes(secret);
            var totp = new Totp(secraw, _config.CodeStep, OtpHashMode.Sha1, _config.CodeSize, TimeCorrection.UncorrectedInstance);

            return totp.ComputeTotp();
        }            
        
        /// <summary>
        /// TOTP verification
        /// </summary>
        /// <param name="secret">shared secret</param>
        /// <param name="code">code to verify</param>
        /// <returns>True if given code is correct and false otherwise</returns>
        public bool VerifyTotp(string secret, string code)
        {
            if (string.IsNullOrWhiteSpace(secret) || _config.SecretSize != secret.Length)
                throw new InvalidEnumArgumentException(nameof(secret));
            if (string.IsNullOrWhiteSpace(code))
                throw new InvalidEnumArgumentException(nameof(code));

            var rawSecret = Encoding.ASCII.GetBytes(secret);
            var totp = new Totp(rawSecret, _config.CodeStep, OtpHashMode.Sha1, _config.CodeSize, TimeCorrection.UncorrectedInstance);
            var window = new VerificationWindow(_config.CodeWindow, _config.CodeWindow);
            var res = totp.VerifyTotp(code, out _, window);
            return res;
        }

        public void Dispose()
        {
            _rng.Dispose();
        }
    }

    /// <summary>
    /// Not crypto correct key size manipulation
    /// </summary>
    static class CryptoQuirks
    {
        /// <summary>
        /// Collapse key uniq bytes to smaller value then perform extension with transposition to maintain the same key size.
        /// Extension algorithm is:
        /// 1. shortKey = middle part of key
        /// 2. newKey = endChunkOf(newKey) + newKey + startChunkOf(newKey)
        /// </summary>
        /// <param name="key">original key</param>
        /// <param name="keyLen">length of a new key uniq bytes</param>
        /// <returns>shortKey - collapsed key, newKey - key expanded from shortKey</returns>
        public static (byte[] newKey, byte[] shortKey) CollapseKey(this byte[] key, int keyLen)
        {
            if (keyLen % 2 != 0 || key.Length % 2 != 0 || keyLen < key.Length / 2)
                throw new ArgumentException($"Keys length should be odd and {nameof(keyLen)} should be less than half of the {nameof(key)}");

            var patchSize = (key.Length - keyLen) / 2;

            var shortKey = key.Skip(key.Length / 2 - keyLen / 2).Take(keyLen).ToArray();
            var extendedKey = shortKey.Skip(shortKey.Length-patchSize).Take(patchSize)
                .Concat(shortKey)
                .Concat(shortKey.Take(patchSize));
            return (extendedKey.ToArray(), shortKey);
        }

        /// <summary>
        /// Makes inversion of Collapse key algorithm to create extended key from short one
        /// </summary>
        /// <param name="key">short key</param>
        /// <param name="keyLen">extended key length</param>
        /// <returns>extended key</returns>
        public static byte[] ExtendKey(this byte[] key, int keyLen)
        {
            if (keyLen % 2 != 0 || key.Length % 2 != 0 || keyLen / 2 > key.Length)
                throw new ArgumentException($"Keys length should be odd and {nameof(key)} should be less than half of the {nameof(keyLen)}");

            var patchSize = (keyLen - key.Length) / 2;

            var extendedKey = key.Skip(key.Length - patchSize).Take(patchSize)
                .Concat(key)
                .Concat(key.Take(patchSize));

            return extendedKey.ToArray();
        }

    }

    /// <summary>
    /// Extensions for simple symmetric string encryption
    /// </summary>
    static class StringSymCryptoExtensions
    {
        /// <summary>
        /// Symmetrically encrypts 
        /// </summary>
        /// <param name="plainText">data to encrypt</param>
        /// <param name="keySize">key size in bits. If key size is not 128 or 256 key extension is used (not recommended)</param>
        /// <returns></returns>
        public static (string cipherText, string iv, string key) SymmetricCrypt(this string plainText, int keySize = 128)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException($"{nameof(plainText)} should'n be null or empty");

            using (var crypto = new AesManaged())
            {
                var key = crypto.Key;

                // adjust key
                if (keySize != 128 && keySize != 256)
                {
                    if (keySize < 63 || keySize % 16 != 0)
                        throw new ArgumentException($"{nameof(keySize)} should be on word boundary and at least 64");

                    if (keySize < 128)
                        crypto.KeySize = 128;

                    (crypto.Key, key) = crypto.Key.CollapseKey(keySize / 8);
                }

                var encryptor = crypto.CreateEncryptor(crypto.Key, crypto.IV);
                byte[] cipherText;

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }

                        cipherText = msEncrypt.ToArray();
                    }
                }

                return (Base32Encoding.ToString(cipherText), Base32Encoding.ToString(crypto.IV), Base32Encoding.ToString(key));
            }
        }

        /// <summary>
        /// Symmetricaly decripts
        /// </summary>
        /// <param name="cipherText">text to decript</param>
        /// <param name="iv">initialization vector</param>
        /// <param name="key">decryption key. If the key size is not 128 or 256 key extension is used (not recommended)</param>
        /// <param name="keySize">size of the key in bits</param>
        /// <returns>extended key</returns>
        public static string SymmetricDecript(this string cipherText, string iv, string key, int keySize = 128)
        {
            if (string.IsNullOrEmpty(cipherText) || string.IsNullOrEmpty(iv) || string.IsNullOrEmpty(key))
                throw new ArgumentNullException("string arguments should'n be null or empty");

            string plaintext = null;

            using (var crypto = new AesManaged())
            {
                var keyRaw = Base32Encoding.ToBytes(key);

                // adjust key
                if (keyRaw.Length != 16 && keyRaw.Length != 32)
                {
                    if (keySize < 63 || keySize % 16 != 0)
                        throw new ArgumentException($"{nameof(keySize)} should be on word boundary and at least 64");

                    keyRaw = keyRaw.ExtendKey(keySize/8);
                }

                crypto.IV = Base32Encoding.ToBytes(iv);
                crypto.Key = keyRaw;

                ICryptoTransform decryptor = crypto.CreateDecryptor(crypto.Key, crypto.IV);

                using (MemoryStream msDecrypt = new MemoryStream(Base32Encoding.ToBytes(cipherText)))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }

            return plaintext;
        }
    }

    class SharedSecretExchangeConfig
    {
        public SharedSecretExchangeConfig(uint symmetricKeySize, uint symmetricExtendedKeySize)
        {
            SymmetricKeySize = symmetricKeySize;
            SymmetricExtendedKeySize = symmetricExtendedKeySize;
        }

        public readonly uint SymmetricKeySize;
        public readonly uint SymmetricExtendedKeySize;

        public static SharedSecretExchangeConfig Default { get; } = new SharedSecretExchangeConfig(80, 128);
    }
}
