using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Security.Claims;
using System.Diagnostics;
using SecureFileUploader.Web.Models;

namespace SecureFileUploader.Web.Controllers
{
    public abstract class BaseController : Controller
    {
        protected readonly ILogger _logger;
        
        protected BaseController(ILogger logger)
        {
            _logger = logger;
        }
        
        protected string GetUserId()
        {
            return User.FindFirstValue(ClaimTypes.NameIdentifier);
        }
        
        protected string GetUserName()
        {
            return User.FindFirstValue(ClaimTypes.Name);
        }
        
        protected IActionResult HandleException(Exception ex, string userErrorMessage = null)
        {
            _logger.LogError(ex, "Error occurred in {Controller}: {Message}", 
                GetType().Name, ex.Message);
            
            if (Request.Headers["X-Requested-With"] == "XMLHttpRequest")
            {
                return Json(new { success = false, message = userErrorMessage ?? "An error occurred" });
            }
            
            ViewData["ErrorMessage"] = userErrorMessage ?? "An error occurred";
            return Error();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            var errorMessage = ViewData["ErrorMessage"] as string ?? 
                             TempData["ErrorMessage"] as string ?? 
                             "An error occurred while processing your request.";
            
            return View("~/Views/Shared/Error.cshtml", new ErrorViewModel 
            { 
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier,
                ErrorMessage = errorMessage
            });
        }
    }
} 