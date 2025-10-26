using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using SafeVault.Tests.Helpers;
using Xunit;

namespace SafeVault.Tests.Integration;

public class VaultTests : AuthenticatedTestBase
{
    public VaultTests(CustomWebApplicationFactory factory) : base(factory)
    {
    }

    private async Task<string> GetTokenForNewUserAsync()
    {
        var email = $"user{Guid.NewGuid():N}@example.com";
        var password = "SecurePass123!";

        // Register
        var registerRequest = new
        {
            email,
            password,
            confirmPassword = password
        };
        await Client.PostAsJsonAsync("/api/auth/register", registerRequest);

        // Login
        var loginRequest = new { email, password };
        var loginResponse = await Client.PostAsJsonAsync("/api/auth/login", loginRequest);
        var loginResult = await loginResponse.Content.ReadFromJsonAsync<Dictionary<string, string>>();
        
        return loginResult!["token"];
    }

    [Fact]
    public async Task CreatePassword_SanitizesXSS()
    {
        // Arrange
        await AuthenticateAsUserAsync();
        
        var maliciousPassword = new
        {
            title = "Test <script>alert(1)</script>",
            username = "user",
            password = "pass123",
            url = "https://example.com",
            notes = "Notes with <script>alert('xss')</script>"
        };

        // Act
        var createResponse = await Client.PostAsJsonAsync("/api/passwords", maliciousPassword);

        // Assert
        createResponse.StatusCode.Should().Be(HttpStatusCode.Created);
        
        var created = await createResponse.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        created!["title"].ToString().Should().NotContain("<script>");
        created["title"].ToString().Should().Contain("alert(1)"); // Text should remain
        
        // Verify sanitization persists on retrieval
        var passwordId = created["id"].ToString();
        var getResponse = await Client.GetAsync($"/api/passwords/{passwordId}");
        var retrieved = await getResponse.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        
        retrieved!["title"].ToString().Should().NotContain("<script>");
    }

    [Fact]
    public async Task ListPasswords_OnlyReturnsUserOwnPasswords()
    {
        // Arrange - Create password as user 1
        var token1 = await GetTokenForNewUserAsync();
        var client1 = Factory.CreateClient();
        client1.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
        
        await client1.PostAsJsonAsync("/api/passwords", new
        {
            title = "User 1 Secret",
            username = "user1",
            password = "pass1",
            url = "https://user1.com"
        });

        // Create password as user 2
        var token2 = await GetTokenForNewUserAsync();
        var client2 = Factory.CreateClient();
        client2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
        
        await client2.PostAsJsonAsync("/api/passwords", new
        {
            title = "User 2 Secret",
            username = "user2",
            password = "pass2",
            url = "https://user2.com"
        });

        // Act - Get passwords for each user
        var response1 = await client1.GetAsync("/api/passwords");
        var response2 = await client2.GetAsync("/api/passwords");

        var passwords1 = await response1.Content.ReadFromJsonAsync<List<Dictionary<string, object>>>();
        var passwords2 = await response2.Content.ReadFromJsonAsync<List<Dictionary<string, object>>>();

        // Assert - Each user should only see their own passwords
        passwords1.Should().HaveCount(1);
        passwords2.Should().HaveCount(1);
        
        passwords1![0]["title"].ToString().Should().Be("User 1 Secret");
        passwords2![0]["title"].ToString().Should().Be("User 2 Secret");
    }

    [Fact]
    public async Task AdminCanViewAllPasswords()
    {
        // Arrange - Create password as regular user
        var userToken = await GetTokenForNewUserAsync();
        var userClient = Factory.CreateClient();
        userClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        
        await userClient.PostAsJsonAsync("/api/passwords", new
        {
            title = "User Secret",
            username = "user",
            password = "secret123",
            url = "https://example.com"
        });

        // Act - Admin views all passwords
        await AuthenticateAsAdminAsync();
        var response = await Client.GetAsync("/api/passwords/all");

        // Assert
        response.EnsureSuccessStatusCode();
        var allPasswords = await response.Content.ReadFromJsonAsync<List<Dictionary<string, object>>>();
        allPasswords.Should().NotBeNull();
        allPasswords!.Count.Should().BeGreaterThanOrEqualTo(1);
    }

    [Fact]
    public async Task UserCannotViewAllPasswords()
    {
        // Arrange
        await AuthenticateAsUserAsync();

        // Act
        var response = await Client.GetAsync("/api/passwords/all");

        // Assert
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task UserCannotDeleteOthersPasswords()
    {
        // Arrange - User 1 creates a password
        var token1 = await GetTokenForNewUserAsync();
        var client1 = Factory.CreateClient();
        client1.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
        
        var createResponse = await client1.PostAsJsonAsync("/api/passwords", new
        {
            title = "User 1 Password",
            username = "user1",
            password = "pass1",
            url = "https://user1.com"
        });
        
        var created = await createResponse.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        var passwordId = created!["id"].ToString();

        // Act - User 2 tries to delete User 1's password
        var token2 = await GetTokenForNewUserAsync();
        var client2 = Factory.CreateClient();
        client2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
        
        var deleteResponse = await client2.DeleteAsync($"/api/passwords/{passwordId}");

        // Assert
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task UserCanDeleteOwnPassword()
    {
        // Arrange
        await AuthenticateAsUserAsync();
        
        var createResponse = await Client.PostAsJsonAsync("/api/passwords", new
        {
            title = "To Delete",
            username = "user",
            password = "pass",
            url = "https://example.com"
        });
        
        var created = await createResponse.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        var passwordId = created!["id"].ToString();

        // Act
        var deleteResponse = await Client.DeleteAsync($"/api/passwords/{passwordId}");

        // Assert
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.NoContent);
        
        // Verify it's deleted
        var getResponse = await Client.GetAsync($"/api/passwords/{passwordId}");
        getResponse.StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task UserCannotUpdateOthersPasswords()
    {
        // Arrange - User 1 creates a password
        var token1 = await GetTokenForNewUserAsync();
        var client1 = Factory.CreateClient();
        client1.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token1);
        
        var createResponse = await client1.PostAsJsonAsync("/api/passwords", new
        {
            title = "Original",
            username = "user1",
            password = "pass1",
            url = "https://user1.com"
        });
        
        var created = await createResponse.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        var passwordId = created!["id"].ToString();

        // Act - User 2 tries to update User 1's password
        var token2 = await GetTokenForNewUserAsync();
        var client2 = Factory.CreateClient();
        client2.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token2);
        
        var updateResponse = await client2.PutAsJsonAsync($"/api/passwords/{passwordId}", new
        {
            title = "Hacked",
            username = "hacker",
            password = "hacked",
            url = "https://hacked.com"
        });

        // Assert
        updateResponse.StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task AdminCanDeleteAnyPassword()
    {
        // Arrange - Regular user creates a password
        var userToken = await GetTokenForNewUserAsync();
        var userClient = Factory.CreateClient();
        userClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", userToken);
        
        var createResponse = await userClient.PostAsJsonAsync("/api/passwords", new
        {
            title = "User Password",
            username = "user",
            password = "pass",
            url = "https://example.com"
        });
        
        var created = await createResponse.Content.ReadFromJsonAsync<Dictionary<string, object>>();
        var passwordId = created!["id"].ToString();

        // Act - Admin deletes the password
        await AuthenticateAsAdminAsync();
        var deleteResponse = await Client.DeleteAsync($"/api/passwords/{passwordId}");

        // Assert
        deleteResponse.StatusCode.Should().Be(HttpStatusCode.NoContent);
    }
}