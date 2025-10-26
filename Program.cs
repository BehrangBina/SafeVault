using FluentValidation.AspNetCore;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SafeVault.Api.Data;
using SafeVault.Api.Dtos;
using SafeVault.Api.Validation;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using SafeVault.Api.Security;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SafeVault API",
        Version = "v1"
    });
});
// EF Core (SQLite) - SQLi safe via parameters
builder.Services.AddDbContext<AppDbContext>(o =>
    o.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=safevault.db"));

// JWT Auth
var secret = builder.Configuration["Jwt:Secret"] ?? "dev-secret-change-me";
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new()
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.FromMinutes(1),
            NameClaimType = ClaimTypes.NameIdentifier,
            RoleClaimType = ClaimTypes.Role
        };
        o.Events = new JwtBearerEvents
        {
            OnTokenValidated = ctx =>
            {
                // Map "sub" → NameIdentifier so CurrentUserId works
                var sub = ctx.Principal?.FindFirst("sub")?.Value;
                if (!string.IsNullOrEmpty(sub))
                {
                    var idClaim = new Claim(ClaimTypes.NameIdentifier, sub);
                    var identity = ctx.Principal!.Identities.First();
                    identity.AddClaim(idClaim);
                }
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();

// FluentValidation
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddTransient<IValidator<RegisterRequest>, RegisterRequestValidator>();
builder.Services.AddTransient<IValidator<LoginRequest>, LoginRequestValidator>();
builder.Services.AddTransient<IValidator<VaultItemCreate>, VaultItemCreateValidator>();
var app = builder.Build();
// Security headers (helps reduce XSS risk in future HTML responses)
app.Use(async (ctx, next) =>
{
    ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
    ctx.Response.Headers["X-Frame-Options"] = "DENY";
    ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
    ctx.Response.Headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";
    await next();
});
// Ensure DB created & seed an admin
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    await db.Database.EnsureCreatedAsync();
    if (!await db.Users.AnyAsync(u => u.Role == "Admin"))
    {
        db.Users.Add(new SafeVault.Api.Domain.User
        {
            Email = "admin@safevault.local",
            PasswordHash = PasswordHasher.Hash("AdminPass123!"),
            Role = "Admin"
        });
        await db.SaveChangesAsync();
    }
}
// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "SafeVault API v1");
    });
}
app.MapGet("/healthz", () => Results.Ok(new { ok = true }));

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();
app.Run();