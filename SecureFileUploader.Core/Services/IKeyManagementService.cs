using System.Threading.Tasks;

namespace SecureFileUploader.Core.Services
{
    public interface IKeyManagementService
    {
        Task GenerateAndStoreUserKeysAsync(string userId, string password);
        Task<byte[]> GetDecryptedPrivateKeyAsync(string userId, string password);
    }
} 