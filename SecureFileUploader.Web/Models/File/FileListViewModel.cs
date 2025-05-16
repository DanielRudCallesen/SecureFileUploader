using SecureFileUploader.Core.Services;
using System.Collections.Generic;

namespace SecureFileUploader.Web.Models.File
{
    public class FileListViewModel
    {
        public List<FileDto> OwnedFiles { get; set; } = new List<FileDto>();
        public List<FileDto> SharedFiles { get; set; } = new List<FileDto>();
    }
} 