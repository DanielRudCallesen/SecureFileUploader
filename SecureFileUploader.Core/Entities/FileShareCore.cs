using System;

namespace SecureFileUploader.Core.Entities
{
    public class FileShareCore
    {
        public Guid Id { get; set; }
        public Guid FileId { get; set; }
        public string SharedWithUserId { get; set; }
        public DateTime SharedDate { get; set; }
        public byte[] EncryptedAesKey { get; set; }
        
        // Navigation properties
        public FileMetadata File { get; set; }
        public ApplicationUser SharedWithUser { get; set; }
    }
} 