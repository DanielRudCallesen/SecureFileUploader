using System;
using System.ComponentModel.DataAnnotations;

namespace SecureFileUploader.Web.Models.File
{
    public class DeleteFileViewModel
    {
        public Guid FileId { get; set; }
        
        [Display(Name = "File Name")]
        public string FileName { get; set; }
        
        [Display(Name = "File Size")]
        public long FileSize { get; set; }
        
        [Display(Name = "Upload Date")]
        public DateTime UploadDate { get; set; }
    }
} 