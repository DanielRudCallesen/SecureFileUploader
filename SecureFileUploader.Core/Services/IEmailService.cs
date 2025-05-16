using System.Threading.Tasks;

namespace SecureFileUploader.Core.Services
{
    public interface IEmailService
    {
        Task SendFileShareInvitationAsync(
            string recipientEmail, 
            string senderName,
            string fileName,
            string accessLink,
            string accessCode,
            string customMessage = null);
            
        Task SendEmailConfirmationAsync(
            string email,
            string username,
            string confirmationLink);
    }
} 