using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileUploader.Web.Models.File
{
    public class ShareFileViewModel
    {
        public Guid FileId { get; set; }
        
        [Required(ErrorMessage = "Please enter an email address")]
        [EmailAddress(ErrorMessage = "Please enter a valid email address")]
        [Display(Name = "Recipient Email")]
        public string RecipientEmail { get; set; }
        
        [Display(Name = "Message (Optional)")]
        public string Message { get; set; }
        
        // File information for display
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string ContentType { get; set; }
    }
} 