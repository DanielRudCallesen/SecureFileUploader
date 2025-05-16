using SecureFileUploader.Core.Services;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureFileUploader.Infrastructure.Cryptography
{
    public class CryptoService : ICryptoService
    {
        private const int AesKeySize = 256;
        private const int RsaKeySize = 2048;
        private const int PbkdfIterations = 100000;
        private const int SaltSize = 16;
        
        public async Task<(byte[] publicKey, byte[] privateKey)> GenerateRsaKeyPairAsync()
        {
            // Generate RSA key pair
            using var rsa = RSA.Create(RsaKeySize);
            
            // Export keys
            var privateKey = rsa.ExportRSAPrivateKey();
            var publicKey = rsa.ExportRSAPublicKey();
            
            return await Task.FromResult((publicKey, privateKey));
        }

        public async Task<byte[]> EncryptPrivateKeyWithPasswordAsync(byte[] privateKey, string password)
        {
            // Generate a random salt
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            
            // Derive a key from the password
            byte[] derivedKey;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PbkdfIterations, HashAlgorithmName.SHA256))
            {
                derivedKey = pbkdf2.GetBytes(32); // 256 bits key
            }
            
            // Encrypt the private key with AES-GCM
            byte[] encrypted;
            byte[] nonce = new byte[12]; // 96 bits nonce for GCM
            byte[] tag = new byte[16];   // 128 bits tag
            
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }
            
            using (var aes = new AesGcm(derivedKey))
            {
                encrypted = new byte[privateKey.Length];
                aes.Encrypt(nonce, privateKey, encrypted, tag);
            }
            
            // Combine salt + nonce + tag + encrypted key
            byte[] result = new byte[SaltSize + nonce.Length + tag.Length + encrypted.Length];
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, result, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(encrypted, 0, result, salt.Length + nonce.Length + tag.Length, encrypted.Length);
            
            return await Task.FromResult(result);
        }

        public async Task<byte[]> DecryptPrivateKeyWithPasswordAsync(byte[] encryptedPrivateKey, string password)
        {
            // Extract salt, nonce, tag, and encrypted data
            byte[] salt = new byte[SaltSize];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            
            Buffer.BlockCopy(encryptedPrivateKey, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(encryptedPrivateKey, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(encryptedPrivateKey, salt.Length + nonce.Length, tag, 0, tag.Length);
            
            int encryptedLength = encryptedPrivateKey.Length - (salt.Length + nonce.Length + tag.Length);
            byte[] encrypted = new byte[encryptedLength];
            Buffer.BlockCopy(encryptedPrivateKey, salt.Length + nonce.Length + tag.Length, encrypted, 0, encrypted.Length);
            
            // Derive the key from password and salt
            byte[] derivedKey;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PbkdfIterations, HashAlgorithmName.SHA256))
            {
                derivedKey = pbkdf2.GetBytes(32); // 256 bits key
            }
            
            // Decrypt the private key
            byte[] decrypted = new byte[encrypted.Length];
            try
            {
                using var aes = new AesGcm(derivedKey);
                aes.Decrypt(nonce, encrypted, tag, decrypted);
            }
            catch (CryptographicException)
            {
                throw new InvalidOperationException("Incorrect password or corrupted data");
            }
            
            return await Task.FromResult(decrypted);
        }

        public async Task<(byte[] encryptedData, byte[] aesKey)> EncryptFileAsync(Stream fileStream)
        {
            // Generate a random AES key
            using var aes = Aes.Create();
            aes.KeySize = AesKeySize;
            aes.GenerateKey();
            byte[] aesKey = aes.Key;
            
            // Convert the input stream to bytes (for simplicity in this example)
            byte[] data;
            using (var memoryStream = new MemoryStream())
            {
                await fileStream.CopyToAsync(memoryStream);
                data = memoryStream.ToArray();
            }
            
            // Encrypt the data
            byte[] encryptedData;
            using (var encryptor = aes.CreateEncryptor())
            using (var memoryStream = new MemoryStream())
            {
                // Write the IV to the beginning of the output stream
                await memoryStream.WriteAsync(aes.IV, 0, aes.IV.Length);
                
                // Encrypt the data and write to the output stream
                using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                {
                    await cryptoStream.WriteAsync(data, 0, data.Length);
                    cryptoStream.FlushFinalBlock();
                }
                
                encryptedData = memoryStream.ToArray();
            }
            
            return (encryptedData, aesKey);
        }

        public async Task<Stream> DecryptFileAsync(Stream encryptedStream, byte[] aesKey)
        {
            // Create AES instance with the provided key
            using var aes = Aes.Create();
            aes.KeySize = AesKeySize;
            aes.Key = aesKey;
            
            // Read the IV from the beginning of the encrypted data
            byte[] iv = new byte[16]; // AES IV is always 16 bytes
            await encryptedStream.ReadAsync(iv, 0, iv.Length);
            aes.IV = iv;
            
            // Create a memory stream to hold the decrypted data
            var decryptedStream = new MemoryStream();
            
            // Decrypt the data
            using (var decryptor = aes.CreateDecryptor())
            using (var cryptoStream = new CryptoStream(encryptedStream, decryptor, CryptoStreamMode.Read))
            {
                await cryptoStream.CopyToAsync(decryptedStream);
            }
            
            // Reset the position of the decrypted stream to the beginning
            decryptedStream.Position = 0;
            
            return decryptedStream;
        }

        public async Task<byte[]> EncryptAesKeyWithRsaAsync(byte[] aesKey, byte[] rsaPublicKey)
        {
            using var rsa = RSA.Create();
            rsa.ImportRSAPublicKey(rsaPublicKey, out _);
            
            // Encrypt the AES key with RSA-OAEP (SHA-256)
            byte[] encryptedKey = rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256);
            
            return await Task.FromResult(encryptedKey);
        }

        public async Task<byte[]> DecryptAesKeyWithRsaAsync(byte[] encryptedAesKey, byte[] rsaPrivateKey)
        {
            try
            {
                using var rsa = RSA.Create();
                rsa.ImportRSAPrivateKey(rsaPrivateKey, out _);
                
                // Decrypt the AES key with RSA-OAEP (SHA-256)
                byte[] decryptedKey = rsa.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);
                
                return await Task.FromResult(decryptedKey);
            }
            catch (CryptographicException ex)
            {
                throw new InvalidOperationException("Failed to decrypt the file encryption key. This could be due to an incorrect password encryption keys.", ex);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("An unexpected error occurred during decryption of the file encryption key.", ex);
            }
        }

        public async Task<byte[]> EncryptAesKeyWithPasswordAsync(byte[] aesKey, string password)
        {
            // Generate a random salt
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            
            // Derive a key from the password
            byte[] derivedKey;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PbkdfIterations, HashAlgorithmName.SHA256))
            {
                derivedKey = pbkdf2.GetBytes(32); // 256 bits key
            }
            
            // Encrypt the AES key with AES-GCM
            byte[] encrypted;
            byte[] nonce = new byte[12]; // 96 bits nonce for GCM
            byte[] tag = new byte[16];   // 128 bits tag
            
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(nonce);
            }
            
            using (var aes = new AesGcm(derivedKey))
            {
                encrypted = new byte[aesKey.Length];
                aes.Encrypt(nonce, aesKey, encrypted, tag);
            }
            
            // Combine salt + nonce + tag + encrypted key
            byte[] result = new byte[SaltSize + nonce.Length + tag.Length + encrypted.Length];
            Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
            Buffer.BlockCopy(nonce, 0, result, salt.Length, nonce.Length);
            Buffer.BlockCopy(tag, 0, result, salt.Length + nonce.Length, tag.Length);
            Buffer.BlockCopy(encrypted, 0, result, salt.Length + nonce.Length + tag.Length, encrypted.Length);
            
            return await Task.FromResult(result);
        }
        
        public async Task<byte[]> DecryptAesKeyWithPasswordAsync(byte[] encryptedAesKey, string password)
        {
            // Extract salt, nonce, tag, and encrypted data
            byte[] salt = new byte[SaltSize];
            byte[] nonce = new byte[12];
            byte[] tag = new byte[16];
            
            Buffer.BlockCopy(encryptedAesKey, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(encryptedAesKey, salt.Length, nonce, 0, nonce.Length);
            Buffer.BlockCopy(encryptedAesKey, salt.Length + nonce.Length, tag, 0, tag.Length);
            
            int encryptedLength = encryptedAesKey.Length - (salt.Length + nonce.Length + tag.Length);
            byte[] encrypted = new byte[encryptedLength];
            Buffer.BlockCopy(encryptedAesKey, salt.Length + nonce.Length + tag.Length, encrypted, 0, encrypted.Length);
            
            // Derive the key from password and salt
            byte[] derivedKey;
            using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, PbkdfIterations, HashAlgorithmName.SHA256))
            {
                derivedKey = pbkdf2.GetBytes(32); // 256 bits key
            }
            
            // Decrypt the AES key
            byte[] decrypted = new byte[encrypted.Length];
            try
            {
                using var aes = new AesGcm(derivedKey);
                aes.Decrypt(nonce, encrypted, tag, decrypted);
            }
            catch (CryptographicException)
            {
                throw new InvalidOperationException("Incorrect password or corrupted data");
            }
            
            return await Task.FromResult(decrypted);
        }
    }
} 