using System.IdentityModel.Tokens.Jwt;
using System.Text;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Api.Data;
using SafeVault.Api.Security;
using SafeVault.Api.Validation;

var builder = WebApplication.CreateBuilder(args);

// ---- EF Core (SQLite)
var connectionString = builder.Configuration.GetConnectionString("Default")
    ?? "Data Source=./data/safevault.db";

builder.Services.AddDbContext<AppDbContext>(o => o.UseSqlite(connectionString));

// ---- Controllers + FluentValidation
builder.Services.AddControllers();

// Register FluentValidation validators from assembly
builder.Services.AddValidatorsFromAssemblyContaining<RegisterRequestValidator>();

// ---- JWT Service
builder.Services.AddSingleton<JwtService>();

// ---- JWT Authentication Configuration
var secret = builder.Configuration["Jwt:Secret"];
if (string.IsNullOrEmpty(secret) || secret.Length < 32)
{
    throw new InvalidOperationException(
        "Jwt:Secret must be configured in appsettings.json and be at least 32 characters long");
}

var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

// Disable legacy inbound claim mapping to use standard JWT claims
JwtSecurityTokenHandler.DefaultMapInboundClaims = false;

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1),

            // Use JWT-standard claim types
            NameClaimType = "sub",
            RoleClaimType = "role"
        };
    });

builder.Services.AddAuthorization();

// ---- CORS Configuration (adjust origins as needed)
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
            ?? new[] { "http://localhost:3000", "http://localhost:5173" };

        policy.WithOrigins(allowedOrigins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials();
    });
});

// ---- Swagger (Development only)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new Microsoft.OpenApi.Models.OpenApiInfo
    {
        Title = "SafeVault API",
        Version = "v1",
        Description = "Secure password management API"
    });

    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token in the text input below. Example: \"Bearer eyJhbGciOi...\"",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// ---- Database Initialization & Admin Seeding
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    try
    {
        await db.Database.EnsureCreatedAsync();
        logger.LogInformation("Database initialized successfully");

        // Seed admin user if none exists
        if (!await db.Users.AnyAsync(u => u.Role == "Admin"))
        {
            db.Users.Add(new SafeVault.Api.Domain.User
            {
                Email = "admin@safevault.local",
                PasswordHash = PasswordHasher.Hash("AdminPass123!"),
                Role = "Admin"
            });
            await db.SaveChangesAsync();
            logger.LogInformation("Admin user seeded: admin@safevault.local");
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "An error occurred while initializing the database");
        throw;
    }
}

// ---- Security Headers Middleware
app.Use(async (ctx, next) =>
{
    // Skip strict CSP for Swagger endpoints
    var isSwagger = ctx.Request.Path.StartsWithSegments("/swagger");

    if (!isSwagger)
    {
        ctx.Response.Headers["X-Content-Type-Options"] = "nosniff";
        ctx.Response.Headers["X-Frame-Options"] = "DENY";
        ctx.Response.Headers["X-XSS-Protection"] = "1; mode=block";
        ctx.Response.Headers["Referrer-Policy"] = "no-referrer";
        ctx.Response.Headers["Content-Security-Policy"] =
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'";

        // HSTS for production
        if (!app.Environment.IsDevelopment())
        {
            ctx.Response.Headers["Strict-Transport-Security"] =
                "max-age=31536000; includeSubDomains";
        }
    }

    await next();
});

// ---- Middleware Pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseHsts();
}

app.UseHttpsRedirection();

// Enable CORS
app.UseCors();

// Swagger (Development only)
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "SafeVault API v1");
        c.RoutePrefix = "swagger";
    });
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Health check endpoint
app.MapGet("/healthz", () => Results.Ok(new
{
    status = "healthy",
    timestamp = DateTime.UtcNow,
    version = "1.0.0"
}))
.AllowAnonymous();

app.Run();

// Make Program class accessible for integration testing
public partial class Program { }