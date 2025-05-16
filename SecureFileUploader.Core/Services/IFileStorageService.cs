using System;
using System.IO;
using System.Threading.Tasks;

namespace SecureFileUploader.Core.Services
{
    public interface IFileStorageService
    {
        Task<string> SaveFileAsync(byte[] fileData, Guid fileId);
        Task<byte[]> GetFileAsync(string filePath);
        Task DeleteFileAsync(string filePath);
    }
} 