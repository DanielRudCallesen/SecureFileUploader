using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using SecureFileUploader.Core.Entities;
using SecureFileUploader.Core.Services;
using SecureFileUploader.Infrastructure.AntiVirus;
using SecureFileUploader.Infrastructure.Cryptography;
using SecureFileUploader.Infrastructure.Data;
using SecureFileUploader.Infrastructure.Email;
using SecureFileUploader.Infrastructure.FileStorage;
using SecureFileUploader.Infrastructure.Files;
using SecureFileUploader.Infrastructure.Identity;
using SecureFileUploader.Infrastructure.KeyManagement;

namespace SecureFileUploader.Infrastructure
{
    public static class DependencyInjection
    {
        public static IServiceCollection AddInfrastructureServices(this IServiceCollection services, IConfiguration configuration)
        {
            // Add DbContext
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(
                    configuration.GetConnectionString("DefaultConnection"),
                    b => b.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName)));
            
            // Add Identity services
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                // Configure Identity password requirements
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
                options.Password.RequiredLength = 12;
                
                // Configure lockout settings
                options.Lockout.DefaultLockoutTimeSpan = System.TimeSpan.FromMinutes(15);
                options.Lockout.MaxFailedAccessAttempts = 5;
                
                // User settings
                options.User.RequireUniqueEmail = true;
                
                // Email confirmation settings
                options.SignIn.RequireConfirmedEmail = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
            
            // Replace default password hasher with Argon2 implementation
            services.AddScoped<IPasswordHasher<ApplicationUser>, Argon2PasswordHasher>();
            
            // Register application services
            services.AddScoped<ICryptoService, CryptoService>();
            services.AddScoped<IFileStorageService, LocalFileStorageService>();
            services.AddScoped<IAntiVirusService, ClamAvService>();
            services.AddScoped<IFileService, FileService>();
            services.AddScoped<IKeyManagementService, KeyManagementService>();
            services.AddScoped<IEmailService, EmailService>();
            
            return services;
        }
    }
} 