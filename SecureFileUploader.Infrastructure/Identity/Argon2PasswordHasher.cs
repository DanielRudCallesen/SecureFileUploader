using Konscious.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using SecureFileUploader.Core.Entities;
using System;
using System.Security.Cryptography;
using System.Text;

namespace SecureFileUploader.Infrastructure.Identity
{
    public class Argon2PasswordHasher : IPasswordHasher<ApplicationUser>
    {
        // Parameters for Argon2 - tuned for security and performance
        private const int MemorySize = 65536;    // 64MB
        private const int Iterations = 3;        // Number of iterations
        private const int DegreeOfParallelism = 4; // Parallel threads
        private const int SaltSize = 16;         // 128 bits salt
        private const int HashSize = 32;         // 256 bits hash
        
        public string HashPassword(ApplicationUser user, string password)
        {
            // Generate a random salt
            byte[] salt = new byte[SaltSize];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            
            // Compute the hash
            byte[] hash = HashPassword(password, salt);
            
            // Combine salt and hash and convert to base64
            byte[] combined = new byte[SaltSize + HashSize];
            Buffer.BlockCopy(salt, 0, combined, 0, SaltSize);
            Buffer.BlockCopy(hash, 0, combined, SaltSize, HashSize);
            
            return Convert.ToBase64String(combined);
        }

        public PasswordVerificationResult VerifyHashedPassword(ApplicationUser user, string hashedPassword, string providedPassword)
        {
            // Convert from base64
            byte[] combined;
            try
            {
                combined = Convert.FromBase64String(hashedPassword);
            }
            catch
            {
                return PasswordVerificationResult.Failed;
            }
            
            // Ensure the hash is in the expected format
            if (combined.Length != SaltSize + HashSize)
            {
                return PasswordVerificationResult.Failed;
            }
            
            // Extract salt and hash from combined array
            byte[] salt = new byte[SaltSize];
            byte[] hash = new byte[HashSize];
            Buffer.BlockCopy(combined, 0, salt, 0, SaltSize);
            Buffer.BlockCopy(combined, SaltSize, hash, 0, HashSize);
            
            // Compute hash for the provided password
            byte[] newHash = HashPassword(providedPassword, salt);
            
            // Compare the stored hash with the computed hash
            bool verified = SlowEquals(hash, newHash);
            
            return verified ? PasswordVerificationResult.Success : PasswordVerificationResult.Failed;
        }
        
        private byte[] HashPassword(string password, byte[] salt)
        {
            // Convert password to bytes
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            
            // Create Argon2id instance
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = DegreeOfParallelism,
                Iterations = Iterations,
                MemorySize = MemorySize
            };
            
            return argon2.GetBytes(HashSize);
        }
        
        // Constant-time comparison of hash arrays to prevent timing attacks
        private bool SlowEquals(byte[] a, byte[] b)
        {
            uint diff = (uint)a.Length ^ (uint)b.Length;
            for (int i = 0; i < a.Length && i < b.Length; i++)
            {
                diff |= (uint)(a[i] ^ b[i]);
            }
            return diff == 0;
        }
    }
} 