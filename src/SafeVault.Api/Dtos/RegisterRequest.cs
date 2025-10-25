namespace SafeVault.Api.Dtos
{
    public record RegisterRequest(string Email, string Password, string? Role);

}
