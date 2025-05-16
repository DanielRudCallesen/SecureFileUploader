using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.DependencyInjection;
using SecureFileUploader.Core.Entities;
using SecureFileUploader.Core.Services;
using SecureFileUploader.Infrastructure.Data;
using SecureFileUploader.Web.Models.File;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Claims;

namespace SecureFileUploader.Web.Controllers
{
    [Authorize]
    public class FileController : BaseController
    {
        private readonly IFileService _fileService;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _dbContext;
        
        public FileController(
            IFileService fileService,
            UserManager<ApplicationUser> userManager,
            ApplicationDbContext dbContext,
            ILogger<FileController> logger)
            : base(logger)
        {
            _fileService = fileService;
            _userManager = userManager;
            _dbContext = dbContext;
        }
        
        [HttpGet]
        public async Task<IActionResult> Index()
        {
            try
            {
                var userId = GetUserId();
                var ownedFiles = await _fileService.GetUserFilesAsync(userId);
                var sharedFiles = await _fileService.GetSharedFilesAsync(userId);
                
                var model = new FileListViewModel
                {
                    OwnedFiles = ownedFiles.OrderByDescending(f => f.UploadDate).ToList(),
                    SharedFiles = sharedFiles.OrderByDescending(f => f.UploadDate).ToList()
                };
                
                return View(model);
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }
        
        [HttpGet]
        public IActionResult Upload()
        {
            return View();
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Upload(UploadViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            
            try
            {
                if (model.File == null)
                {
                    ModelState.AddModelError("File", "Please select a file to upload.");
                    return View(model);
                }
                
                if (model.File.Length == 0)
                {
                    ModelState.AddModelError("File", "The file is empty. Please upload a file with content in it.");
                    return View(model);
                }
                
                // Validate file size (e.g., max 100MB)
                const long maxFileSize = 100 * 1024 * 1024; // 100MB
                if (model.File.Length > maxFileSize)
                {
                    ModelState.AddModelError("File", "File size exceeds the maximum allowed (100MB).");
                    return View(model);
                }
                
                // Validate file extension
                var allowedExtensions = new[] { ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".zip" };
                var extension = Path.GetExtension(model.File.FileName).ToLowerInvariant();
                if (!allowedExtensions.Contains(extension))
                {
                    ModelState.AddModelError("File", "File type not allowed.");
                    return View(model);
                }
                
                var userId = GetUserId();
                
                var fileId = await _fileService.UploadFileAsync(model.File, userId);
                _logger.LogInformation("File uploaded successfully with ID: {FileId}", fileId);
                
                TempData["SuccessMessage"] = "File uploaded successfully.";
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading file: {Message}", ex.Message);
                return HandleException(ex, "Error uploading file. Please try again.");
            }
        }
        
        [HttpGet]
        public async Task<IActionResult> Download(Guid id)
        {
            try
            {
                // Instead of direct download, redirect to password entry page
                var model = new FilePasswordViewModel
                {
                    FileId = id
                };
                
                return View("EnterPassword", model);
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error preparing file download.");
            }
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DownloadWithPassword(FilePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View("EnterPassword", model);
            }
            
            try
            {
                var userId = GetUserId();
                var (fileStream, fileName, contentType) = await _fileService.DownloadFileAsync(
                    model.FileId, userId, model.Password);
                
                return File(fileStream, contentType, fileName);
            }
            catch (UnauthorizedAccessException ex)
            {
                ModelState.AddModelError("Password", ex.Message);
                return View("EnterPassword", model);
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error downloading file.");
            }
        }
        
        [HttpGet]
        public async Task<IActionResult> Share(Guid id)
        {
            try
            {
                var userId = GetUserId();
                
                // Get file info to display
                var ownedFiles = await _fileService.GetUserFilesAsync(userId);
                var file = ownedFiles.FirstOrDefault(f => f.Id == id);
                
                if (file == null)
                {
                    TempData["ErrorMessage"] = "File not found or you don't have permission to share it.";
                    return RedirectToAction(nameof(Index));
                }
                
                var model = new ShareFileViewModel
                {
                    FileId = id,
                    FileName = file.FileName,
                    FileSize = file.FileSize,
                    ContentType = file.ContentType
                };
                
                return View(model);
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Share(ShareFileViewModel model)
        {
            if (!ModelState.IsValid)
            {
                // Repopulate file information
                try
                {
                    var userId = GetUserId();
                    var ownedFiles = await _fileService.GetUserFilesAsync(userId);
                    var file = ownedFiles.FirstOrDefault(f => f.Id == model.FileId);
                    
                    if (file != null)
                    {
                        model.FileName = file.FileName;
                        model.FileSize = file.FileSize;
                        model.ContentType = file.ContentType;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error repopulating file info in Share form");
                }
                
                return View(model);
            }
            
            try
            {
                var userId = GetUserId();

                // Check if an invitation already exists for this file/email
                var existingInvitation = await _dbContext.FileShareInvitations
                    .FirstOrDefaultAsync(i => i.FileId == model.FileId && 
                                             i.InvitedEmail.ToLower() == model.RecipientEmail.ToLower() && 
                                             i.IsActive);
                
                bool isReshare = existingInvitation != null;
                
                var success = await _fileService.ShareFileAsync(
                    model.FileId, 
                    userId, 
                    model.RecipientEmail, 
                    model.Message);
                
                if (success)
                {
                    if (isReshare)
                    {
                        TempData["SuccessMessage"] = $"Invitation email resent to {model.RecipientEmail}.";
                    }
                    else
                    {
                        TempData["SuccessMessage"] = $"File shared successfully with {model.RecipientEmail}.";
                    }
                }
                else
                {
                    TempData["ErrorMessage"] = "Failed to share file. Please try again.";
                }
                
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sharing file: {Message}", ex.Message);
                return HandleException(ex, "Error sharing file.");
            }
        }
        
        [HttpGet]
        public async Task<IActionResult> Delete(Guid id)
        {
            try
            {
                // Get file info to display in confirmation view
                var userId = GetUserId();
                var ownedFiles = await _fileService.GetUserFilesAsync(userId);
                var file = ownedFiles.FirstOrDefault(f => f.Id == id);
                
                if (file == null)
                {
                    TempData["ErrorMessage"] = "File not found or you don't have permission to delete it.";
                    return RedirectToAction(nameof(Index));
                }
                
                var model = new DeleteFileViewModel
                {
                    FileId = id,
                    FileName = file.FileName,
                    FileSize = file.FileSize,
                    UploadDate = file.UploadDate
                };
                
                return View(model);
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteConfirm(DeleteFileViewModel model)
        {
            try
            {
                var userId = GetUserId();
                var success = await _fileService.DeleteFileAsync(model.FileId, userId);
                
                if (success)
                {
                    TempData["SuccessMessage"] = "File deleted successfully.";
                }
                else
                {
                    TempData["ErrorMessage"] = "Failed to delete file. Please try again.";
                }
                
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error deleting file.");
            }
        }

        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> SharedAccess(Guid id)
        {
            try
            {
                // Find the invitation
                var invitation = await _dbContext.FileShareInvitations
                    .Include(i => i.File)
                    .Include(i => i.Owner)
                    .FirstOrDefaultAsync(i => i.Id == id && i.IsActive);
                
                if (invitation == null)
                {
                    TempData["ErrorMessage"] = "Invalid or expired share link.";
                    return RedirectToAction("Login", "Account");
                }

                if (invitation.AccessCodeExpiry.HasValue && invitation.AccessCodeExpiry.Value < DateTime.UtcNow)
                {
                    TempData["ErrorMessage"] = "This share link has expired.";
                    return RedirectToAction("Login", "Account");
                }
                
                // Check if user is logged in
                if (!User.Identity.IsAuthenticated)
                {
                    // Store invitation ID in TempData for after login/registration
                    TempData["PendingShareInvitationId"] = id.ToString();
                    
                    // Redirect to login with return URL
                    return RedirectToAction("Login", "Account", new { 
                        returnUrl = Url.Action("SharedAccess", "File", new { id = id }),
                        email = invitation.InvitedEmail 
                    });
                }
                
                // User is authenticated, get their ID
                var userId = GetUserId();
                var userEmail = User.FindFirstValue(ClaimTypes.Email);
                
                // Validate that the email matches
                if (!string.Equals(userEmail, invitation.InvitedEmail, StringComparison.OrdinalIgnoreCase))
                {
                    TempData["ErrorMessage"] = "This file was shared with a different email address.";
                    return RedirectToAction("Index");
                }

                // Show the access code entry form
                var model = new SharedAccessViewModel
                {
                    InvitationId = id,
                    FileName = invitation.File.FileName,
                    FileSize = invitation.File.FileSize,
                    ContentType = invitation.File.ContentType,
                    SharedBy = invitation.Owner.UserName
                };
                
                return View(model);
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error accessing shared file.");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> SharedAccess(SharedAccessViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                var (fileStream, fileName, contentType) = await _fileService.DownloadSharedFileAsync(
                    model.InvitationId, model.AccessCode);
                
                return File(fileStream, contentType, fileName);
            }
            catch (InvalidOperationException ex)
            {
                ModelState.AddModelError("AccessCode", ex.Message);
                return View(model);
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error downloading shared file.");
            }
        }

        [HttpGet]
        public async Task<IActionResult> RemoveShared(Guid id)
        {
            try
            {
                var userId = GetUserId();
                var userEmail = User.FindFirstValue(ClaimTypes.Email);
                
                // Try to find the file using our helper method
                var fileInfo = await FindSharedFileAsync(id, userId, userEmail);
                
                if (fileInfo == null)
                {
                    TempData["ErrorMessage"] = "File not found or you don't have permission to remove it.";
                    return RedirectToAction(nameof(Index));
                }
                
                var model = new RemoveSharedFileViewModel
                {
                    FileId = id,
                    FileName = fileInfo.FileName,
                    FileSize = fileInfo.FileSize,
                    SharedBy = fileInfo.SharedBy
                };
                
                return View(model);
            }
            catch (Exception ex)
            {
                return HandleException(ex);
            }
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> RemoveSharedConfirm(RemoveSharedFileViewModel model)
        {
            try
            {
                var userId = GetUserId();
                var success = await _fileService.RemoveSharedFileAsync(model.FileId, userId);
                
                TempData[success ? "SuccessMessage" : "ErrorMessage"] = 
                    success ? "File removed from your shared files." : "Failed to remove shared file. Please try again.";
                
                return RedirectToAction(nameof(Index));
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error removing shared file.");
            }
        }

        // Helper method to find a shared file by ID for the current user
        private async Task<Core.Services.FileDto> FindSharedFileAsync(Guid fileId, string userId, string userEmail)
        {
            // First try to find file in the user's shared files list
            var sharedFiles = await _fileService.GetSharedFilesAsync(userId);
            var file = sharedFiles.FirstOrDefault(f => f.Id == fileId);
            if (file != null)
                return file;
            
            // Check for a direct file share
            var directShare = await _dbContext.FileShares
                .Include(fs => fs.File)
                .ThenInclude(f => f.Owner)
                .FirstOrDefaultAsync(fs => fs.FileId == fileId && fs.SharedWithUserId == userId);
            
            if (directShare != null)
            {
                return new Core.Services.FileDto
                {
                    Id = directShare.FileId,
                    FileName = directShare.File.FileName,
                    FileSize = directShare.File.FileSize,
                    ContentType = directShare.File.ContentType,
                    UploadDate = directShare.File.UploadDate,
                    SharedBy = directShare.File.Owner.UserName
                };
            }
            
            // Check for a file share invitation
            var invitation = await _dbContext.FileShareInvitations
                .Include(i => i.File)
                .ThenInclude(f => f.Owner)
                .FirstOrDefaultAsync(i => i.FileId == fileId && 
                                          i.InvitedEmail.ToLower() == userEmail.ToLower() && 
                                          i.IsActive);
            
            if (invitation != null)
            {
                return new Core.Services.FileDto
                {
                    Id = invitation.FileId,
                    FileName = invitation.File.FileName,
                    FileSize = invitation.File.FileSize,
                    ContentType = invitation.File.ContentType,
                    UploadDate = invitation.File.UploadDate,
                    SharedBy = invitation.Owner.UserName
                };
            }
            
            return null;
        }

        [HttpGet]
        public async Task<IActionResult> AccessShared(Guid id)
        {
            try
            {
                // Get the user's email
                var userId = GetUserId();
                var userEmail = User.FindFirstValue(ClaimTypes.Email);
                
                // Find the invitation for this file and user's email
                var invitation = await _dbContext.FileShareInvitations
                    .Include(i => i.File)
                    .Include(i => i.Owner)
                    .FirstOrDefaultAsync(i => i.FileId == id && 
                                               i.InvitedEmail.ToLower() == userEmail.ToLower() && 
                                               i.IsActive);
                
                if (invitation == null)
                {
                    TempData["ErrorMessage"] = "File not found or you don't have permission to access it.";
                    return RedirectToAction(nameof(Index));
                }
                
                var model = new AccessCodeViewModel
                {
                    FileId = id,
                    FileName = invitation.File.FileName,
                    SharedBy = invitation.Owner.UserName
                };
                
                return View(model);
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error accessing shared file.");
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> AccessShared(AccessCodeViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            
            try
            {
                // Get the user's email
                var userId = GetUserId();
                var userEmail = User.FindFirstValue(ClaimTypes.Email);
                
                // Find the invitation
                var invitation = await _dbContext.FileShareInvitations
                    .FirstOrDefaultAsync(i => i.FileId == model.FileId && 
                                               i.InvitedEmail.ToLower() == userEmail.ToLower() && 
                                               i.IsActive);
                
                if (invitation == null)
                {
                    TempData["ErrorMessage"] = "File not found or you don't have permission to access it.";
                    return RedirectToAction(nameof(Index));
                }
                
                // Download the file using the access code
                try
                {
                    var (fileStream, fileName, contentType) = await _fileService.DownloadSharedFileAsync(
                        invitation.Id, model.AccessCode);
                    
                    return File(fileStream, contentType, fileName);
                }
                catch (InvalidOperationException ex)
                {
                    ModelState.AddModelError("AccessCode", ex.Message);
                    return View(model);
                }
            }
            catch (Exception ex)
            {
                return HandleException(ex, "Error downloading shared file.");
            }
        }
    }
} 