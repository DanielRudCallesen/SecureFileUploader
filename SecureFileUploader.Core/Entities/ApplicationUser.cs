using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace SecureFileUploader.Core.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public UserKeyPair KeyPair { get; set; }
        public ICollection<FileMetadata> Files { get; set; } = new List<FileMetadata>();
        public ICollection<FileShareCore> SharedFiles { get; set; } = new List<FileShareCore>();
    }
} 