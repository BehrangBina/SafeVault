using Microsoft.EntityFrameworkCore;
using SafeVault.Api.Domain;

namespace SafeVault.Api.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
        {
        }

        public DbSet<User> Users => Set<User>();
        public DbSet<VaultItem> VaultItems => Set<VaultItem>();
    }
}