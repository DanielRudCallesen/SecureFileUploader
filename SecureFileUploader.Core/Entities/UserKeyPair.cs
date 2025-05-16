using System;

namespace SecureFileUploader.Core.Entities
{
    public class UserKeyPair
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }
        public byte[] PublicKey { get; set; }
        public byte[] EncryptedPrivateKey { get; set; }
        public DateTime CreatedAt { get; set; }
        
        // Navigation property
        public ApplicationUser User { get; set; }
    }
} 