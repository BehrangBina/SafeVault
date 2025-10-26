using Ganss.Xss;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Api.Data;
using SafeVault.Api.Domain;
using SafeVault.Api.Dtos;
using System.Security.Claims;

namespace SafeVault.Api.Controllers
{
    [ApiController]
    [Route("vault")]
    public class VaultController : ControllerBase
    {
        private static readonly HtmlSanitizer Sanitizer = new();
        private readonly AppDbContext db;

        public VaultController(AppDbContext db)
        {
            this.db = db;
        }
        private int CurrentUserId => int.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "0");

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Create([FromBody] VaultItemCreate req)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);
            // Sanitize to mitigate stored XSS in any downstream HTML contexts
            var safe = Sanitizer.Sanitize(req.Content);

            // parameterized via EF Core; no raw SQL concatenation
            var item = new VaultItem { Content = safe, OwnerId = CurrentUserId };
            db.VaultItems.Add(item);
            await db.SaveChangesAsync();

            return StatusCode(201, new { id = item.Id, content = item.Content });
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> Mine()
        {
            var items = await db.VaultItems
                .Where(v => v.OwnerId == CurrentUserId)
                .Select(v => new { v.Id, v.Content })
                .ToListAsync();

            return Ok(items);
        }

        [HttpGet("all")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> All()
        {
            var items = await db.VaultItems
                .Select(v => new { v.Id, v.Content, v.OwnerId })
                .ToListAsync();

            return Ok(items);
        }

        [HttpDelete("{id:int}")]
        [Authorize]
        public async Task<IActionResult> Delete(int id)
        {
            var item = await db.VaultItems.FindAsync(id);
            if (item is null) return NotFound(new { error = "Not found" });

            var role = User.FindFirstValue(ClaimTypes.Role);
            if (!(role == "Admin" || item.OwnerId == CurrentUserId))
                return Forbid();

            db.VaultItems.Remove(item);
            await db.SaveChangesAsync();
            return Ok(new { message = "deleted" });
        }
    }
}
