using Microsoft.AspNetCore.Http;
using System.ComponentModel.DataAnnotations;

namespace SecureFileUploader.Web.Models.File
{
    public class UploadViewModel
    {
        [Required(ErrorMessage = "Please select a file")]
        [Display(Name = "File")]
        public IFormFile File { get; set; }
    }
} 