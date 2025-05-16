using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using SecureFileUploader.Core.Entities;

namespace SecureFileUploader.Infrastructure.Data
{
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<FileMetadata> FileMetadata { get; set; }
        public DbSet<UserKeyPair> UserKeyPairs { get; set; }
        public DbSet<FileShareCore> FileShares { get; set; }
        public DbSet<FileShareInvitation> FileShareInvitations { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configure entity relationships and constraints
            builder.Entity<FileMetadata>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.FileName).IsRequired().HasMaxLength(255);
                entity.Property(e => e.StoragePath).IsRequired().HasMaxLength(1000);
                entity.Property(e => e.UploadDate).IsRequired();
                entity.Property(e => e.ContentType).HasMaxLength(100);
                entity.Property(e => e.EncryptedAesKey).IsRequired();
                
                // Relationship with user
                entity.HasOne(e => e.Owner)
                      .WithMany(u => u.Files)
                      .HasForeignKey(e => e.OwnerId)
                      .OnDelete(DeleteBehavior.Restrict);
            });

            builder.Entity<UserKeyPair>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.PublicKey).IsRequired();
                entity.Property(e => e.EncryptedPrivateKey).IsRequired();
                entity.Property(e => e.CreatedAt).IsRequired();
                
                // One-to-one relationship with user
                entity.HasOne(e => e.User)
                      .WithOne(u => u.KeyPair)
                      .HasForeignKey<UserKeyPair>(e => e.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });

            builder.Entity<FileShareCore>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.SharedDate).IsRequired();
                entity.Property(e => e.EncryptedAesKey).IsRequired();
                
                // Relationship with file
                entity.HasOne(e => e.File)
                      .WithMany(f => f.Shares)
                      .HasForeignKey(e => e.FileId)
                      .OnDelete(DeleteBehavior.Cascade);
                
                // Relationship with user being shared with
                entity.HasOne(e => e.SharedWithUser)
                      .WithMany(u => u.SharedFiles)
                      .HasForeignKey(e => e.SharedWithUserId)
                      .OnDelete(DeleteBehavior.Restrict);
            });

            builder.Entity<FileShareInvitation>(entity =>
            {
                entity.HasKey(e => e.Id);
                entity.Property(e => e.InvitedEmail).IsRequired().HasMaxLength(256);
                entity.Property(e => e.OwnerId).IsRequired();
                entity.Property(e => e.InvitedDate).IsRequired();
                entity.Property(e => e.IsActive).IsRequired();
                entity.Property(e => e.EncryptedAesKey).IsRequired();
                entity.Property(e => e.AccessCode).HasMaxLength(32);
                entity.Property(e => e.AccessCodeExpiry);
                
                // Relationship with file
                entity.HasOne(e => e.File)
                      .WithMany()
                      .HasForeignKey(e => e.FileId)
                      .OnDelete(DeleteBehavior.Cascade);
                
                // Relationship with owner
                entity.HasOne(e => e.Owner)
                      .WithMany()
                      .HasForeignKey(e => e.OwnerId)
                      .OnDelete(DeleteBehavior.Restrict);
            });
        }
    }
} 