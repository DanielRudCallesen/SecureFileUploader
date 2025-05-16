using System;
using System.Collections.Generic;

namespace SecureFileUploader.Core.Entities
{
    public class FileMetadata
    {
        public Guid Id { get; set; }
        public string FileName { get; set; }
        public string ContentType { get; set; }
        public long FileSize { get; set; }
        public DateTime UploadDate { get; set; }
        public string StoragePath { get; set; }
        public byte[] EncryptedAesKey { get; set; }
        
        // Foreign key
        public string OwnerId { get; set; }
        
        // Navigation property
        public ApplicationUser Owner { get; set; }
        public ICollection<FileShareCore> Shares { get; set; } = new List<FileShareCore>();
    }
} 