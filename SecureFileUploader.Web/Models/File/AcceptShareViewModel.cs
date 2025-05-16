using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileUploader.Web.Models.File
{
    public class AcceptShareViewModel
    {
        public Guid InvitationId { get; set; }
        
        [Required(ErrorMessage = "The file owner's password is required to decrypt the shared file.")]
        [Display(Name = "File Owner's Password")]
        [DataType(DataType.Password)]
        public string OwnerPassword { get; set; }
        
        // Additional display information
        public string FileName { get; set; }
        public string SharedByName { get; set; }
    }
} 