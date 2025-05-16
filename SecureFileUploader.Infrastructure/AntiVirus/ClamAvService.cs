using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using nClam;
using SecureFileUploader.Core.Services;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SecureFileUploader.Infrastructure.AntiVirus
{
    public class ClamAvService : IAntiVirusService
    {
        private readonly string _clamAvServer;
        private readonly int _clamAvPort;
        private readonly ILogger<ClamAvService> _logger;
        
        public ClamAvService(IConfiguration configuration, ILogger<ClamAvService> logger)
        {
            _clamAvServer = configuration["ClamAV:Server"] ?? "localhost";
            _clamAvPort = int.Parse(configuration["ClamAV:Port"] ?? "3310");
            _logger = logger;
        }
        
        public async Task<(bool isClean, string scanResult)> ScanFileAsync(Stream fileStream)
        {
            if (fileStream == null)
            {
                throw new ArgumentNullException(nameof(fileStream));
            }

            try
            {
                // Reset stream position to beginning
                if (fileStream.CanSeek)
                {
                    fileStream.Position = 0;
                }
                
                // Create ClamAV client using nClam
                var clam = new ClamClient(_clamAvServer, _clamAvPort);
                
                // Perform scan
                var scanResult = await clam.SendAndScanFileAsync(fileStream);
                
                // Reset stream position to beginning for further processing
                if (fileStream.CanSeek)
                {
                    fileStream.Position = 0;
                }
                
                // Interpret the results
                bool isClean = scanResult.Result == ClamScanResults.Clean;
                string message;
                
                switch (scanResult.Result)
                {
                    case ClamScanResults.Clean:
                        message = "File is clean";
                        break;
                    case ClamScanResults.VirusDetected:
                        var virusName = scanResult.InfectedFiles?.FirstOrDefault()?.VirusName ?? "Unknown virus";
                        message = $"Virus detected: {virusName}";
                        break;
                    case ClamScanResults.Error:
                        message = $"Scan error: {scanResult.RawResult ?? "Unknown error"}";
                        break;
                    default:
                        message = $"Unknown result: {scanResult.RawResult ?? "No details available"}";
                        break;
                }
                
                _logger.LogInformation("ClamAV scan result: {Result} - {Message}", 
                    scanResult.Result, message);
                
                return (isClean, message);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error occurred while scanning file with ClamAV");
                throw new InvalidOperationException("Failed to scan file with ClamAV", ex);
            }
        }
    }
} 