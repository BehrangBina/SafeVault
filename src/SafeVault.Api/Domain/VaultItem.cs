namespace SafeVault.Api.Domain
{
    public class VaultItem
    {
        public int Id { get; set; }
        public string Content { get; set; } = default!;
        public int OwnerId { get; set; }
        public User Owner { get; set; } = default!;
    }
}
