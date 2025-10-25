namespace SafeVault.Api.Domain
{
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; } = default!;
        public string PasswordHash { get; set; } = default!;
        public string Role { get; set; } = "User"; // "User" or "Admin"
        public ICollection<VaultItem> Items { get; set; } = new List<VaultItem>();
    }
}
