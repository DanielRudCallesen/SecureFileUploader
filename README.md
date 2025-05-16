## Configuration --- WILL NOT BE POSSIBLE TO USE THIS PROJECT.
## You need ClamAvNet server setup and nClam Nuget Package to try out this project.
## If you have it and can set it up for your self, it would be possible to run this project if you follow instructions below.

### Email Settings

For security reasons, email credentials are not stored in the repository. 

#### Using .NET User Secrets

```bash
# Initialize user secrets for the web project (run once)
cd SecureFileUploader
dotnet user-secrets init --project SecureFileUploader.Web

# Set the email configuration
dotnet user-secrets set "Email:SmtpServer" "smtp.example.com" --project SecureFileUploader.Web
dotnet user-secrets set "Email:SmtpPort" "587" --project SecureFileUploader.Web
dotnet user-secrets set "Email:Username" "your-email@example.com" --project SecureFileUploader.Web
dotnet user-secrets set "Email:Password" "your-password" --project SecureFileUploader.Web
dotnet user-secrets set "Email:SenderEmail" "secure-files@example.com" --project SecureFileUploader.Web
dotnet user-secrets set "Email:SenderName" "Secure File Uploader" --project SecureFileUploader.Web
dotnet user-secrets set "Email:EnableSsl" "true" --project SecureFileUploader.Web

# See the list for email configuration
dotnet user-secrets list --project SecureFileUploader.Web
```


### File Storage Configuration

Configure the file storage location in `appsettings.json`:

```json
"FileStorage": {
  "BasePath": "C:\\YourPath\\SecureFileUploaderStorage"
}
```

## Database Setup

1. Ensure you have SQL Server installed (LocalDB works for development)
2. Update the connection string in `appsettings.json` if needed
3. Run the following commands to create the database:

```bash
dotnet ef database update --project SecureFileUploader.Infrastructure --startup-project SecureFileUploader.Web
```

## Running the Application

```bash
dotnet run --project SecureFileUploader.Web
```



