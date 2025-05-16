using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureFileUploader.Core.Services;
using System;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace SecureFileUploader.Infrastructure.Email
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        private readonly string? _smtpHost;
        private readonly int _smtpPort;
        private readonly string? _smtpUsername;
        private readonly string? _smtpPassword;
        private readonly string? _senderEmail;
        private readonly string _senderName;
        private readonly bool _enableSsl;
        private readonly string _appBaseUrl;
        
        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
            
            // Load email configuration
            _smtpHost = _configuration["Email:SmtpServer"];
            _smtpPort = int.TryParse(_configuration["Email:SmtpPort"], out int port) ? port : 587;
            _smtpUsername = _configuration["Email:Username"];
            _smtpPassword = _configuration["Email:Password"];
            _senderEmail = _configuration["Email:SenderEmail"];
            _senderName = _configuration["Email:SenderName"] ?? "Secure File Uploader";
            _enableSsl = bool.TryParse(_configuration["Email:EnableSsl"], out bool ssl) ? ssl : true;
            _appBaseUrl = _configuration["AppBaseUrl"] ?? "https://localhost:7277";
            

        }
        
        public async Task SendFileShareInvitationAsync(
            string recipientEmail, 
            string senderName, 
            string fileName, 
            string accessLink,
            string accessCode,
            string customMessage = null)
        {
           
            
            try
            {
                // Construct the full access link with base URL
                var fullAccessLink = _appBaseUrl.TrimEnd('/') + "/" + accessLink.TrimStart('/');
                
                using var mailMessage = new MailMessage
                {
                    From = new MailAddress(_senderEmail, _senderName),
                    Subject = $"{senderName} shared a file with you: {fileName}",
                    IsBodyHtml = true,
                    Body = BuildShareEmailBody(senderName, fileName, fullAccessLink, accessCode, customMessage)
                };
                
                mailMessage.To.Add(new MailAddress(recipientEmail));
                
                using var smtpClient = new SmtpClient(_smtpHost, _smtpPort)
                {
                    Credentials = new NetworkCredential(_smtpUsername, _smtpPassword),
                    EnableSsl = _enableSsl
                };
                
                await smtpClient.SendMailAsync(mailMessage);
                
                _logger.LogInformation("File share invitation email sent to {Email} for file {FileName}",
                    recipientEmail, fileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send file share invitation email to {Email}: {ErrorMessage}", 
                    recipientEmail, ex.Message);
                throw new InvalidOperationException("Failed to send invitation email. Please try again later.", ex);
            }
        }
        
        private string BuildShareEmailBody(string senderName, string fileName, string accessLink, string accessCode, string customMessage)
        {
            var template = new StringBuilder();
            
            template.AppendLine("<html><body style='font-family: Arial, sans-serif; line-height: 1.6;'>");
            template.AppendLine("<div style='max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;'>");
            template.AppendLine("<div style='background-color: #4285f4; padding: 15px; border-radius: 5px 5px 0 0;'>");
            template.AppendLine("<h1 style='color: white; margin: 0;'>Secure File Share</h1>");
            template.AppendLine("</div>");
            template.AppendLine("<div style='padding: 20px;'>");
            template.AppendLine($"<p><strong>{WebUtility.HtmlEncode(senderName)}</strong> has shared a file with you:</p>");
            template.AppendLine($"<p style='font-size: 18px; background-color: #f5f5f5; padding: 10px; border-radius: 5px;'>{WebUtility.HtmlEncode(fileName)}</p>");
            
            if (!string.IsNullOrEmpty(customMessage))
            {
                template.AppendLine("<div style='background-color: #f9f9f9; padding: 15px; border-left: 4px solid #4285f4; margin: 15px 0;'>");
                template.AppendLine($"<p><em>Message from {WebUtility.HtmlEncode(senderName)}:</em></p>");
                template.AppendLine($"<p>\"{WebUtility.HtmlEncode(customMessage)}\"</p>");
                template.AppendLine("</div>");
            }
            
            template.AppendLine("<p>To access this file:</p>");
            template.AppendLine("<ol>");
            template.AppendLine($"<li>Click the link below to <a href='{accessLink}'>access the file</a></li>");
            template.AppendLine("<li>Sign in to your account or register if you don't have one</li>");
            template.AppendLine($"<li>Enter the following access code when prompted: <strong style='font-size: 18px; background-color: #f5f5f5; padding: 5px 10px; border-radius: 3px;'>{accessCode}</strong></li>");
            template.AppendLine("</ol>");
            
            template.AppendLine("<div style='text-align: center; margin-top: 25px;'>");
            template.AppendLine($"<a href='{accessLink}' style='background-color: #4285f4; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; font-weight: bold;'>View Shared File</a>");
            template.AppendLine("</div>");
            
            template.AppendLine("<p style='margin-top: 30px; font-size: 12px; color: #666;'>This file has been shared securely through Secure File Uploader. The access code will expire in 7 days.</p>");
            template.AppendLine("</div>");
            template.AppendLine("</div>");
            template.AppendLine("</body></html>");
            
            return template.ToString();
        }

        public async Task SendEmailConfirmationAsync(string email, string username, string confirmationLink)
        {
                       
            try
            {
                // Use the confirmation link as is since it already includes the base URL
                using var mailMessage = new MailMessage
                {
                    From = new MailAddress(_senderEmail, _senderName),
                    Subject = "Confirm your Secure File Uploader account",
                    IsBodyHtml = true,
                    Body = BuildEmailConfirmationBody(username, confirmationLink)
                };
                
                mailMessage.To.Add(new MailAddress(email));
                
                using var smtpClient = new SmtpClient(_smtpHost, _smtpPort)
                {
                    Credentials = new NetworkCredential(_smtpUsername, _smtpPassword),
                    EnableSsl = _enableSsl
                };
                
                await smtpClient.SendMailAsync(mailMessage);
                
                _logger.LogInformation("Email confirmation sent to {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email confirmation to {Email}: {ErrorMessage}", 
                    email, ex.Message);
                throw new InvalidOperationException("Failed to send confirmation email. Please try again later.", ex);
            }
        }
        
        private string BuildEmailConfirmationBody(string username, string confirmationLink)
        {
            var template = new StringBuilder();
            
            template.AppendLine("<html><body style='font-family: Arial, sans-serif; line-height: 1.6;'>");
            template.AppendLine("<div style='max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;'>");
            template.AppendLine("<div style='background-color: #4285f4; padding: 15px; border-radius: 5px 5px 0 0;'>");
            template.AppendLine("<h1 style='color: white; margin: 0;'>Secure File Uploader</h1>");
            template.AppendLine("</div>");
            template.AppendLine("<div style='padding: 20px;'>");
            template.AppendLine($"<p>Hello <strong>{WebUtility.HtmlEncode(username)}</strong>,</p>");
            template.AppendLine("<p>Thank you for registering with Secure File Uploader. To complete your registration and verify your email address, please click the button below:</p>");
            
            template.AppendLine("<div style='text-align: center; margin: 30px 0;'>");
            template.AppendLine($"<a href='{confirmationLink}' style='background-color: #4285f4; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold;'>Confirm Email Address</a>");
            template.AppendLine("</div>");
            
            template.AppendLine("<p>If the button doesn't work, you can also confirm your account by copying and pasting the following link into your browser:</p>");
            template.AppendLine($"<p><a href='{confirmationLink}'>{confirmationLink}</a></p>");
            
            template.AppendLine("<p>If you didn't create an account, you can ignore this email.</p>");
            
            template.AppendLine("<p>Best regards,<br>The Secure File Uploader Team</p>");
            template.AppendLine("</div>");
            template.AppendLine("<div style='background-color: #f5f5f5; padding: 15px; border-radius: 0 0 5px 5px; font-size: 12px; color: #666;'>");
            template.AppendLine("<p>This is an automated email. Please do not reply to this message.</p>");
            template.AppendLine("</div>");
            template.AppendLine("</div>");
            template.AppendLine("</body></html>");
            
            return template.ToString();
        }
    }
} 