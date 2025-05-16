using System.IO;
using System.Threading.Tasks;

namespace SecureFileUploader.Core.Services
{
    public interface IAntiVirusService
    {
        Task<(bool isClean, string scanResult)> ScanFileAsync(Stream fileStream);
    }
} 