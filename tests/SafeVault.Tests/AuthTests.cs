using FluentAssertions;
using Microsoft.AspNetCore.Mvc.Testing;
using SafeVault.Api.Dtos;
using System.Net.Http.Json;

namespace SafeVault.Tests
{
    public class AuthTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly HttpClient _client;

        public AuthTests(WebApplicationFactory<Program> factory)
        {
            _client = factory.WithWebHostBuilder(_ => { }).CreateClient();
        }

        [Fact]
        public async Task Register_Then_Login_Works()
        {
            var email = $"user{Guid.NewGuid():N}@ex.com";
            var reg = await _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "GoodPass123!", null));
            reg.StatusCode.Should().Be(System.Net.HttpStatusCode.Created);

            var login = await _client.PostAsJsonAsync("/auth/login", new LoginRequest(email, "GoodPass123!"));
            login.EnsureSuccessStatusCode();
            var body = await login.Content.ReadFromJsonAsync<Dictionary<string, string>>();
            body.Should().ContainKey("token");
        }

        [Fact]
        public async Task PasswordPolicy_Enforced()
        {
            var email = $"short{Guid.NewGuid():N}@ex.com";
            var reg = await _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "short", null));
            ((int)reg.StatusCode).Should().Be(400);
        }
    }
}
