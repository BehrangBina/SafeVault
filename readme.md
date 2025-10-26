# SafeVault (ASP.NET Core 8 Web API)

- **Validation:** FluentValidation (email/password/content rules)
- **SQLi prevention:** EF Core parameterized queries
- **Auth + RBAC:** JWT Bearer with role claims ("User", "Admin")
- **XSS mitigation:** HtmlSanitizer on stored content + security headers
- **Tests:** xUnit integration tests

## Quickstart

```bash
cd src/SafeVault.Api
dotnet restore
dotnet run
# Swagger at http://localhost:5000/swagger (port may vary)

# Env (recommended)
# setx ASPNETCORE_URLS "http://localhost:5000"
# setx Jwt__Secret "change-me" (Windows) or export Jwt__Secret=change-me (bash)
```