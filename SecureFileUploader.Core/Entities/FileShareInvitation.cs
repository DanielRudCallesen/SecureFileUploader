using System;

namespace SecureFileUploader.Core.Entities
{
    public class FileShareInvitation
    {
        public Guid Id { get; set; }
        public Guid FileId { get; set; }
        public string InvitedEmail { get; set; }
        public string OwnerId { get; set; }
        public DateTime InvitedDate { get; set; }
        public DateTime? AcceptedDate { get; set; }
        public bool IsActive { get; set; }
        public byte[] EncryptedAesKey { get; set; }
        public string AccessCode { get; set; }
        public DateTime? AccessCodeExpiry { get; set; }
        
        // Navigation properties
        public FileMetadata File { get; set; }
        public ApplicationUser Owner { get; set; }
    }
} 