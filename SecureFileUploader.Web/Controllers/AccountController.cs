using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using SecureFileUploader.Core.Entities;
using SecureFileUploader.Core.Services;
using SecureFileUploader.Web.Models.Account;
using System;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Diagnostics;

namespace SecureFileUploader.Web.Controllers
{
    public class AccountController : BaseController
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IKeyManagementService _keyManagementService;
        private readonly IEmailService _emailService;
        private readonly IConfiguration _configuration;
        
        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IKeyManagementService keyManagementService,
            IEmailService emailService,
            IConfiguration configuration,
            ILogger<AccountController> logger) 
            : base(logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _keyManagementService = keyManagementService;
            _emailService = emailService;
            _configuration = configuration;
        }
        
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Index()
        {
            return RedirectToAction("Index", "File");
        }
        
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Register()
        {
            return View();
        }
        
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                try
                {
                   
                    var user = new ApplicationUser { UserName = model.Username, Email = model.Email };
                    var result = await _userManager.CreateAsync(user, model.Password);
                    
                    if (result.Succeeded)
                    {
                        _logger.LogInformation("User created a new account with password.");
                        
                        // Generate encryption keys for the user
                        await _keyManagementService.GenerateAndStoreUserKeysAsync(user.Id, model.Password);
                        _logger.LogInformation("Generated encryption key for user");
                        
                        // Generate email confirmation token and encode it
                        var emailConfirmationToken = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                        _logger.LogInformation("Generated email confirmation token and encoded it for the user");

                        // Use proper URL encoding for the token
                        var tokenEncoded = Uri.EscapeDataString(emailConfirmationToken);
                        
                        // Build the confirmation URL manually to ensure it's correct
                        var baseUrl = _configuration["AppBaseUrl"]?.TrimEnd('/') ?? "https://localhost:7277";
                        var confirmationLink = $"{baseUrl}/Account/ConfirmEmail?userId={user.Id}&token={tokenEncoded}";
                        
                        _logger.LogInformation("Generated confirmation link: {Link}", confirmationLink);
                        
                        // Send confirmation email
                        await _emailService.SendEmailConfirmationAsync(user.Email, user.UserName, confirmationLink);

                        // Check for pending share invitation
                        var pendingInvitationId = TempData["PendingShareInvitationId"] as string;
                        if (!string.IsNullOrEmpty(pendingInvitationId) && Guid.TryParse(pendingInvitationId, out Guid invitationId))
                        {
                            // Store the invitation ID in TempData for after email confirmation
                            TempData["PendingShareInvitationId"] = pendingInvitationId;
                            _logger.LogInformation("Pending share invitation {InvitationId} preserved for user {UserId}", 
                                invitationId, user.Id);
                        }
                        
                        // Redirect to email confirmation info page
                        return RedirectToAction(nameof(RegisterConfirmation), new { email = model.Email });
                    }
                    
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error during registration for user {Email}", model.Email);
                    ModelState.AddModelError(string.Empty, "An error occurred during registration. Please try again.");
                }
            }
            
            return View(model);
        }
        
        [HttpGet]
        [AllowAnonymous]
        public IActionResult RegisterConfirmation(string email)
        {
            ViewData["Email"] = email;
            return View();
        }
        
        [HttpGet]
        [AllowAnonymous]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            _logger.LogInformation("ConfirmEmail action called with userId: {UserId}", userId);
            
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(token))
            {
                _logger.LogWarning("UserId or token is null in ConfirmEmail action");
                ViewData["ErrorMessage"] = "Invalid confirmation link. Missing user ID or token.";
                return View("Error", new SecureFileUploader.Web.Models.ErrorViewModel());
            }
            
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                _logger.LogWarning("User ID {UserId} not found", userId);
                ViewData["ErrorMessage"] = "User ID not found.";
                return View("Error", new SecureFileUploader.Web.Models.ErrorViewModel());
            }
            
            try
            {
                // Try with the raw token first
                var result = await _userManager.ConfirmEmailAsync(user, token);
                
                if (!result.Succeeded)
                {
                    // If that fails, try with URL decoding
                    var decodedToken = HttpUtility.UrlDecode(token);
                    result = await _userManager.ConfirmEmailAsync(user, decodedToken);
                }
                
                if (result.Succeeded)
                {
                    _logger.LogInformation("Email confirmed successfully for user {UserId}", userId);

                    // Check for pending share invitation
                    var pendingInvitationId = TempData["PendingShareInvitationId"] as string;
                    if (!string.IsNullOrEmpty(pendingInvitationId) && Guid.TryParse(pendingInvitationId, out Guid invitationId))
                    {
                        // Redirect to the shared file access page
                        return RedirectToAction("SharedAccess", "File", new { id = invitationId });
                    }

                    return View("ConfirmEmail");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        _logger.LogWarning("Error confirming email for user {UserId}: {Error}", 
                            userId, error.Description);
                    }
                    
                    ViewData["ErrorMessage"] = "Could not confirm your email. The token may be invalid or expired.";
                    return View("Error", new SecureFileUploader.Web.Models.ErrorViewModel());
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Exception during email confirmation for user {UserId}", userId);
                ViewData["ErrorMessage"] = "An error occurred while confirming your email.";
                return View("Error", new SecureFileUploader.Web.Models.ErrorViewModel());
            }
        }
        
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }
        
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            
            if (ModelState.IsValid)
            {
                try
                {
                    // Find user by email or username
                    var user = await _userManager.FindByEmailAsync(model.EmailOrUsername);
                    
                    // If not found by email, try by username
                    if (user == null)
                    {
                        user = await _userManager.FindByNameAsync(model.EmailOrUsername);
                    }
                    
                    if (user == null)
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                        return View(model);
                    }
                    
                    if (!await _userManager.IsEmailConfirmedAsync(user))
                    {
                        ModelState.AddModelError(string.Empty, 
                            "You must confirm your email before you can log in. " +
                            "Please check your email for the confirmation link.");
                        return View(model);
                    }
                    
                    // Sign in with the username
                    var result = await _signInManager.PasswordSignInAsync(
                        user.UserName, model.Password, model.RememberMe, lockoutOnFailure: true);
                    
                    if (result.Succeeded)
                    {
                        _logger.LogInformation("User logged in.");
                        return RedirectToLocal(returnUrl);
                    }
                    
                    if (result.IsLockedOut)
                    {
                        _logger.LogWarning("User account locked out.");
                        return RedirectToAction(nameof(Lockout));
                    }
                    else
                    {
                        ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                        return View(model);
                    }
                }
                catch (Exception ex)
                {
                    return HandleException(ex, "Login failed. Please try again.");
                }
            }
            
            return View(model);
        }
        
        [HttpGet]
        [AllowAnonymous]
        public IActionResult Lockout()
        {
            return View();
        }
        
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();
            _logger.LogInformation("User logged out.");
            return RedirectToAction("Login", "Account");
        }
        
        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "File");
            }
        }
    }
} 