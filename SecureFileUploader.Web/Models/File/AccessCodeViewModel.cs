using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileUploader.Web.Models.File
{
    public class AccessCodeViewModel
    {
        public Guid FileId { get; set; }
        
        [Required(ErrorMessage = "Access code is required")]
        [Display(Name = "Access Code")]
        public string AccessCode { get; set; }
        
        [Display(Name = "File Name")]
        public string FileName { get; set; }
        
        [Display(Name = "Shared By")]
        public string SharedBy { get; set; }
    }
} 