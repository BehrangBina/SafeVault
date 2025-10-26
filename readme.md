# SafeVault API (C# / .NET 8)

**SafeVault** is a secure ASP.NET Core Web API project designed to demonstrate secure coding principles.  
It implements input validation, authentication, authorization (RBAC), and protection against common vulnerabilities such as SQL Injection and XSS.

This project was built with guidance from Microsoft Copilot to support secure coding practices.

---

## Features

- **Input Validation** using [FluentValidation](https://docs.fluentvalidation.net/)
- **SQL Injection Prevention** with [Entity Framework Core](https://learn.microsoft.com/ef/)
- **JWT Authentication** for secure login and user sessions
- **Role-Based Access Control (RBAC)** for User and Admin roles
- **XSS Protection** using [HtmlSanitizer](https://github.com/mganss/HtmlSanitizer)
- **Secure Password Hashing** with [BCrypt.Net](https://github.com/BcryptNet/bcrypt.net)
- **Integration Testing** using [xUnit](https://xunit.net/)
- **REST Client File (`request.http`)** for endpoint testing in VS Code

---

## Project Structure

SafeVault/
├─ src/
│ └─ SafeVault.Api/
│ ├─ Controllers/
│ │ ├─ AuthController.cs
│ │ └─ VaultController.cs
│ ├─ Data/
│ │ └─ AppDbContext.cs
│ ├─ Domain/
│ │ ├─ User.cs
│ │ └─ VaultItem.cs
│ ├─ Dtos/
│ │ ├─ RegisterRequest.cs
│ │ ├─ LoginRequest.cs
│ │ └─ VaultItemCreate.cs
│ ├─ Security/
│ │ ├─ JwtService.cs
│ │ └─ PasswordHasher.cs
│ ├─ Validation/
│ │ ├─ RegisterRequestValidator.cs
│ │ ├─ LoginRequestValidator.cs
│ │ └─ VaultItemCreateValidator.cs
│ ├─ Program.cs
│ ├─ request.http
│ └─ README.md
│
├─ tests/
│ └─ SafeVault.Tests/
│ ├─ AuthTests.cs
│ ├─ VaultTests.cs
│ ├─ CustomWebApplicationFactory.cs
│ └─ AssemblyInfo.cs
│
├─ SUMMARY.md
├─ IMPLEMENTATION_GUIDE.md
├─ PROJECT_SUBMISSION.md
└─ SafeVault.sln

