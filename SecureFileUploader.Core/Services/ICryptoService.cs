using System;
using System.IO;
using System.Threading.Tasks;

namespace SecureFileUploader.Core.Services
{
    public interface ICryptoService
    {
        // RSA key pair management
        Task<(byte[] publicKey, byte[] privateKey)> GenerateRsaKeyPairAsync();
        Task<byte[]> EncryptPrivateKeyWithPasswordAsync(byte[] privateKey, string password);
        Task<byte[]> DecryptPrivateKeyWithPasswordAsync(byte[] encryptedPrivateKey, string password);
        
        // AES encryption for files
        Task<(byte[] encryptedData, byte[] aesKey)> EncryptFileAsync(Stream fileStream);
        Task<Stream> DecryptFileAsync(Stream encryptedStream, byte[] aesKey);
        
        // RSA encryption for AES keys
        Task<byte[]> EncryptAesKeyWithRsaAsync(byte[] aesKey, byte[] rsaPublicKey);
        Task<byte[]> DecryptAesKeyWithRsaAsync(byte[] encryptedAesKey, byte[] rsaPrivateKey);
        
        // Password-based encryption for AES keys (for file sharing with access codes)
        Task<byte[]> EncryptAesKeyWithPasswordAsync(byte[] aesKey, string password);
        Task<byte[]> DecryptAesKeyWithPasswordAsync(byte[] encryptedAesKey, string password);
    }
} 