using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using SafeVault.Tests.Helpers;
using Xunit;

namespace SafeVault.Tests.Integration;

public class PasswordTests : AuthenticatedTestBase
{
    public PasswordTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    [Fact]
    public async Task GetPasswords_AsAuthenticated_ReturnsSuccess()
    {
        // Arrange
        await AuthenticateAsUserAsync();

        // Act
        var response = await Client.GetAsync("/api/passwords");

        // Assert
        response.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task GetPasswords_AsUnauthenticated_ReturnsUnauthorized()
    {
        // Act (no authentication)
        var response = await Client.GetAsync("/api/passwords");

        // Assert
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task CreatePassword_WithValidData_ReturnsCreated()
    {
        // Arrange
        await AuthenticateAsUserAsync();
        
        var newPassword = new
        {
            title = "Test Password",
            username = "testuser",
            password = "SecurePass123!",
            url = "https://example.com",
            notes = "Test notes"
        };

        // Act
        var response = await Client.PostAsJsonAsync("/api/passwords", newPassword);

        // Assert
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(result.TryGetProperty("id", out _));
    }

    [Fact]
    public async Task GetPassword_ThatDoesNotExist_ReturnsNotFound()
    {
        // Arrange
        await AuthenticateAsUserAsync();
        var nonExistentId = Guid.NewGuid();

        // Act
        var response = await Client.GetAsync($"/api/passwords/{nonExistentId}");

        // Assert
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task DeletePassword_AsOwner_ReturnsNoContent()
    {
        // Arrange
        await AuthenticateAsUserAsync();

        // Create a password first
        var newPassword = new
        {
            title = "To Delete",
            username = "user",
            password = "pass",
            url = "https://example.com"
        };

        var createResponse = await Client.PostAsJsonAsync("/api/passwords", newPassword);
        var created = await createResponse.Content.ReadFromJsonAsync<JsonElement>();
        var passwordId = created.GetProperty("id").GetString();

        // Act
        var response = await Client.DeleteAsync($"/api/passwords/{passwordId}");

        // Assert
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
    }

    [Fact]
    public async Task UpdatePassword_AsOwner_ReturnsOk()
    {
        // Arrange
        await AuthenticateAsUserAsync();

        // Create a password first
        var newPassword = new
        {
            title = "Original Title",
            username = "user",
            password = "pass",
            url = "https://example.com"
        };

        var createResponse = await Client.PostAsJsonAsync("/api/passwords", newPassword);
        var created = await createResponse.Content.ReadFromJsonAsync<JsonElement>();
        var passwordId = created.GetProperty("id").GetString();

        // Update data
        var updatePassword = new
        {
            title = "Updated Title",
            username = "updateduser",
            password = "newpass",
            url = "https://updated.com"
        };

        // Act
        var response = await Client.PutAsJsonAsync($"/api/passwords/{passwordId}", updatePassword);

        // Assert
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        
        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Updated Title", result.GetProperty("title").GetString());
    }

    [Fact]
    public async Task GetPasswords_DifferentUsers_ReturnsDifferentData()
    {
        // Arrange - Create password as user 1
        var client1 = await CreateAuthenticatedClientAsync("test@safevault.local", "TestPass123!");
        
        var password1 = new
        {
            title = "User 1 Password",
            username = "user1",
            password = "pass1",
            url = "https://user1.com"
        };
        await client1.PostAsJsonAsync("/api/passwords", password1);

        // Create password as user 2 (admin)
        var client2 = await CreateAuthenticatedClientAsync("admin@safevault.local", "AdminPass123!");
        
        var password2 = new
        {
            title = "User 2 Password",
            username = "user2",
            password = "pass2",
            url = "https://user2.com"
        };
        await client2.PostAsJsonAsync("/api/passwords", password2);

        // Act - Get passwords for each user
        var response1 = await client1.GetAsync("/api/passwords");
        var response2 = await client2.GetAsync("/api/passwords");

        var passwords1 = await response1.Content.ReadFromJsonAsync<JsonElement>();
        var passwords2 = await response2.Content.ReadFromJsonAsync<JsonElement>();

        // Assert - Each user should only see their own passwords
        Assert.NotEqual(
            passwords1.GetArrayLength(),
            passwords2.GetArrayLength()
        );
    }
}