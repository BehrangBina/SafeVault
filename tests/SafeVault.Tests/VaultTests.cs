namespace SafeVault.Tests
{
    using System.Net.Http.Headers;
    using System.Net.Http.Json;
    using FluentAssertions;
    using global::SafeVault.Api.Dtos;
    using Microsoft.AspNetCore.Mvc.Testing;
 
 
    public class VaultTests : IClassFixture<WebApplicationFactory<Program>>
    {
        private readonly HttpClient _client;

        public VaultTests(WebApplicationFactory<Program> factory)
        {
            _client = factory.CreateClient();
        }

        private async Task<string> GetTokenAsync(string email)
        {
            await _client.PostAsJsonAsync("/auth/register", new RegisterRequest(email, "GoodPass123!", null));
            var login = await _client.PostAsJsonAsync("/auth/login", new LoginRequest(email, "GoodPass123!"));
            var body = await login.Content.ReadFromJsonAsync<Dictionary<string, string>>();
            return body!["token"];
        }

        private static void Bearer(HttpClient c, string token)
            => c.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        [Fact]
        public async Task Create_List_Sanitizes_XSS()
        {
            var token = await GetTokenAsync($"u{Guid.NewGuid():N}@ex.com");
            Bearer(_client, token);

            var create = await _client.PostAsJsonAsync("/vault", new VaultItemCreate("hello <script>alert(1)</script>"));
            create.StatusCode.Should().Be(System.Net.HttpStatusCode.Created);
            var created = await create.Content.ReadFromJsonAsync<Dictionary<string, object>>();
            created!["content"].ToString().Should().NotContain("<script>");

            var list = await _client.GetAsync("/vault");
            var items = await list.Content.ReadFromJsonAsync<List<Dictionary<string, object>>>();
            items!.Should().HaveCount(1);
            items[0]["content"].ToString().Should().Contain("alert(1)");
        }

        [Fact]
        public async Task Admin_Can_View_All()
        {
            // admin seeded in Program.cs (admin@safevault.local / AdminPass123!)
            var login = await _client.PostAsJsonAsync("/auth/login", new LoginRequest("admin@safevault.local", "AdminPass123!"));
            login.EnsureSuccessStatusCode();
            var adminBody = await login.Content.ReadFromJsonAsync<Dictionary<string, string>>();
            Bearer(_client, adminBody!["token"]);

            // create an item as a user
            var tokenUser = await GetTokenAsync($"m{Guid.NewGuid():N}@ex.com");
            Bearer(_client, tokenUser);
            await _client.PostAsJsonAsync("/vault", new VaultItemCreate("user secret"));

            // call /vault/all as admin
            Bearer(_client, adminBody["token"]);
            var all = await _client.GetAsync("/vault/all");
            all.EnsureSuccessStatusCode();
            var rows = await all.Content.ReadFromJsonAsync<List<Dictionary<string, object>>>();
            rows!.Count.Should().BeGreaterThanOrEqualTo(1);
        }

        [Fact]
        public async Task User_Cannot_Delete_Others()
        {
            var tok1 = await GetTokenAsync($"a{Guid.NewGuid():N}@ex.com");
            Bearer(_client, tok1);
            var created = await _client.PostAsJsonAsync("/vault", new VaultItemCreate("mine"));
            var cbody = await created.Content.ReadFromJsonAsync<Dictionary<string, object>>();
            var id = cbody!["id"].ToString();

            // second user tries to delete
            var tok2 = await GetTokenAsync($"b{Guid.NewGuid():N}@ex.com");
            Bearer(_client, tok2);
            var del = await _client.DeleteAsync($"/vault/{id}");
            del.StatusCode.Should().Be(System.Net.HttpStatusCode.Forbidden);
        }
    }

}
