using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SafeVault.Api.Data;
using SafeVault.Api.Domain;
using SafeVault.Api.Security;
using System.Data.Common;

namespace SafeVault.Tests;

public class CustomWebApplicationFactory : WebApplicationFactory<Program>
{
    private SqliteConnection? _connection;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Remove the existing DbContext registration
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.RemoveAll<AppDbContext>();

            // Create and open in-memory SQLite connection
            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();

            // Register the test database
            services.AddDbContext<AppDbContext>(options =>
            {
                options.UseSqlite(_connection);
                options.EnableSensitiveDataLogging(); // Helpful for debugging tests
            });

            // Ensure the database is created and seeded
            var sp = services.BuildServiceProvider();
            using var scope = sp.CreateScope();
            var scopedServices = scope.ServiceProvider;
            var db = scopedServices.GetRequiredService<AppDbContext>();

            // Create the schema
            db.Database.EnsureCreated();

            // Seed test data
            SeedTestData(db);
        });

        // Use test environment
        builder.UseEnvironment("Testing");
    }

    private static void SeedTestData(AppDbContext db)
    {
        // Clear existing data (in case of re-seeding)
        db.Users.RemoveRange(db.Users);
        db.SaveChanges();

        // Seed admin user
        var adminUser = new User
        {
            Email = "admin@safevault.local",
            PasswordHash = PasswordHasher.Hash("AdminPass123!"),
            Role = "Admin"
        };

        // Seed regular test user
        var testUser = new User
        {
            Email = "test@safevault.local",
            PasswordHash = PasswordHasher.Hash("TestPass123!"),
            Role = "User"
        };

        db.Users.AddRange(adminUser, testUser);
        db.SaveChanges();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _connection?.Close();
            _connection?.Dispose();
            _connection = null;
        }
        base.Dispose(disposing);
    }
}