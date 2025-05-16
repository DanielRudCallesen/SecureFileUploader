using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace SecureFileUploader.Core.Services
{
    public interface IFileService
    {
        Task<Guid> UploadFileAsync(IFormFile file, string userId);
        Task<(Stream fileStream, string fileName, string contentType)> DownloadFileAsync(Guid fileId, string userId, string password);
        Task<bool> ShareFileAsync(Guid fileId, string ownerId, string recipientEmail, string customMessage = null);
        Task<(Stream fileStream, string fileName, string contentType)> DownloadSharedFileAsync(Guid invitationId, string accessCode);
        Task<List<FileDto>> GetUserFilesAsync(string userId);
        Task<List<FileDto>> GetSharedFilesAsync(string userId);
        Task<bool> DeleteFileAsync(Guid fileId, string userId);
        Task<bool> RemoveSharedFileAsync(Guid fileId, string userId);
    }
    
    public class FileDto
    {
        public Guid Id { get; set; }
        public string FileName { get; set; }
        public string ContentType { get; set; }
        public long FileSize { get; set; }
        public DateTime UploadDate { get; set; }
        public string OwnerName { get; set; }
        public string SharedBy { get; set; }
    }
} 