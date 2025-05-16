using Microsoft.EntityFrameworkCore;
using SecureFileUploader.Core.Entities;
using SecureFileUploader.Core.Services;
using SecureFileUploader.Infrastructure.Data;
using System;
using System.Threading.Tasks;

namespace SecureFileUploader.Infrastructure.KeyManagement
{
    public class KeyManagementService : IKeyManagementService
    {
        private readonly ApplicationDbContext _dbContext;
        private readonly ICryptoService _cryptoService;
        
        public KeyManagementService(ApplicationDbContext dbContext, ICryptoService cryptoService)
        {
            _dbContext = dbContext;
            _cryptoService = cryptoService;
        }
        
        public async Task GenerateAndStoreUserKeysAsync(string userId, string password)
        {
            // Check if user already has keys
            var existingKeys = await _dbContext.UserKeyPairs.FirstOrDefaultAsync(k => k.UserId == userId);
            if (existingKeys != null)
            {
                throw new InvalidOperationException("User already has encryption keys");
            }
            
            // Generate RSA key pair
            var (publicKey, privateKey) = await _cryptoService.GenerateRsaKeyPairAsync();
            
            // Encrypt the private key with the user's password
            var encryptedPrivateKey = await _cryptoService.EncryptPrivateKeyWithPasswordAsync(privateKey, password);
            
            // Create and store user key pair
            var userKeyPair = new UserKeyPair
            {
                Id = Guid.NewGuid(),
                UserId = userId,
                PublicKey = publicKey,
                EncryptedPrivateKey = encryptedPrivateKey,
                CreatedAt = DateTime.UtcNow
            };
            
            _dbContext.UserKeyPairs.Add(userKeyPair);
            await _dbContext.SaveChangesAsync();
        }
        
        public async Task<byte[]> GetDecryptedPrivateKeyAsync(string userId, string password)
        {
            // Get user's key pair
            var userKeyPair = await _dbContext.UserKeyPairs.FirstOrDefaultAsync(k => k.UserId == userId);
            if (userKeyPair == null)
            {
                throw new InvalidOperationException("User does not have encryption keys");
            }
            
            // Decrypt the private key with the user's password
            try
            {
                return await _cryptoService.DecryptPrivateKeyWithPasswordAsync(userKeyPair.EncryptedPrivateKey, password);
            }
            catch (Exception ex)
            {
                throw new UnauthorizedAccessException("Invalid password or corrupted key", ex);
            }
        }
    }
} 