using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace SafeVault.Tests.Helpers;

public static class TestHelpers
{
    /// <summary>
    /// Authenticates a user and returns the JWT token
    /// </summary>
    public static async Task<string> GetAuthTokenAsync(
        HttpClient client, 
        string email = "admin@safevault.local", 
        string password = "AdminPass123!")
    {
        var loginRequest = new
        {
            email,
            password
        };

        var response = await client.PostAsJsonAsync("/api/auth/login", loginRequest);
        response.EnsureSuccessStatusCode();

        var result = await response.Content.ReadFromJsonAsync<JsonElement>();
        return result.GetProperty("token").GetString() 
            ?? throw new InvalidOperationException("Token not found in response");
    }

    /// <summary>
    /// Authenticates and adds the Bearer token to the client's default headers
    /// </summary>
    public static async Task AuthenticateClientAsync(
        HttpClient client, 
        string email = "admin@safevault.local", 
        string password = "AdminPass123!")
    {
        var token = await GetAuthTokenAsync(client, email, password);
        client.DefaultRequestHeaders.Authorization = 
            new AuthenticationHeaderValue("Bearer", token);
    }

    /// <summary>
    /// Creates an authenticated HttpClient
    /// </summary>
    public static async Task<HttpClient> CreateAuthenticatedClientAsync(
        CustomWebApplicationFactory factory,
        string email = "admin@safevault.local",
        string password = "AdminPass123!")
    {
        var client = factory.CreateClient();
        await AuthenticateClientAsync(client, email, password);
        return client;
    }

    /// <summary>
    /// Removes authentication from client
    /// </summary>
    public static void RemoveAuthentication(HttpClient client)
    {
        client.DefaultRequestHeaders.Authorization = null;
    }
}

/// <summary>
/// Base class for tests that require authentication
/// </summary>
public abstract class AuthenticatedTestBase : IClassFixture<CustomWebApplicationFactory>
{
    protected readonly CustomWebApplicationFactory Factory;
    protected readonly HttpClient Client;

    protected AuthenticatedTestBase(CustomWebApplicationFactory factory)
    {
        Factory = factory;
        Client = factory.CreateClient();
    }

    /// <summary>
    /// Authenticate as admin user
    /// </summary>
    protected async Task AuthenticateAsAdminAsync()
    {
        await TestHelpers.AuthenticateClientAsync(
            Client, 
            "admin@safevault.local", 
            "AdminPass123!");
    }

    /// <summary>
    /// Authenticate as regular test user
    /// </summary>
    protected async Task AuthenticateAsUserAsync()
    {
        await TestHelpers.AuthenticateClientAsync(
            Client, 
            "test@safevault.local", 
            "TestPass123!");
    }

    /// <summary>
    /// Create a new authenticated client (doesn't affect the default Client)
    /// </summary>
    protected async Task<HttpClient> CreateAuthenticatedClientAsync(
        string email = "admin@safevault.local",
        string password = "AdminPass123!")
    {
        return await TestHelpers.CreateAuthenticatedClientAsync(Factory, email, password);
    }
}