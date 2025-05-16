using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileUploader.Web.Models.File
{
    public class FilePasswordViewModel
    {
        public Guid FileId { get; set; }
        
        [Required(ErrorMessage = "Password is required to decrypt the file")]
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
} 