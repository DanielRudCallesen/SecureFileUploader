using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileUploader.Web.Models.File
{
    public class SharedAccessViewModel
    {
        public Guid InvitationId { get; set; }
        
        [Required(ErrorMessage = "Please enter the access code")]
        [Display(Name = "Access Code")]
        public string AccessCode { get; set; }
        
        public string FileName { get; set; }
        public long FileSize { get; set; }
        public string ContentType { get; set; }
        public string SharedBy { get; set; }
    }
} 