using Microsoft.Extensions.Configuration;
using SecureFileUploader.Core.Services;
using System;
using System.IO;
using System.Threading.Tasks;

namespace SecureFileUploader.Infrastructure.FileStorage
{
    public class LocalFileStorageService : IFileStorageService
    {
        private readonly string _storageBasePath;
        
        public LocalFileStorageService(IConfiguration configuration)
        {
            _storageBasePath = configuration["FileStorage:BasePath"] 
                ?? Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "FileStorage");
            
            // Ensure the directory exists
            if (!Directory.Exists(_storageBasePath))
            {
                Directory.CreateDirectory(_storageBasePath);
            }
        }
        
        public async Task<string> SaveFileAsync(byte[] fileData, Guid fileId)
        {
            // Create a unique path for the file using the fileId
            string fileName = $"{fileId}.bin";
            string filePath = Path.Combine(_storageBasePath, fileName);
            
            // Write the encrypted data to disk
            await File.WriteAllBytesAsync(filePath, fileData);
            
            return filePath;
        }
        
        public async Task<byte[]> GetFileAsync(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException("The requested file was not found.", filePath);
            }
            
            return await File.ReadAllBytesAsync(filePath);
        }
        
        public Task DeleteFileAsync(string filePath)
        {
            if (File.Exists(filePath))
            {
                File.Delete(filePath);
            }
            
            return Task.CompletedTask;
        }
    }
} 