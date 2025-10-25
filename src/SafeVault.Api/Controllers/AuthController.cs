using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SafeVault.Api.Data;
using SafeVault.Api.Domain;
using SafeVault.Api.Dtos;
using SafeVault.Api.Security;

namespace SafeVault.Api.Controllers
{
    [ApiController]
    [Route("auth")]
    public class AuthController : ControllerBase

    {
        private readonly AppDbContext db;
        private readonly JwtService jwt;
        public AuthController(AppDbContext db, JwtService jwt)
        {
            this.db = db;
            this.jwt = jwt;
        }
    
        // Copilot: suggest EF Core query by email with AsNoTracking for faster lookups
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest req)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var exists = await db.Users.AsNoTracking().AnyAsync(u => u.Email == req.Email);
            if (exists) return BadRequest(new { error = "Email already registered" });

            var role = (req.Role is "Admin" or "User") ? req.Role! : "User";
            var user = new User
            {
                Email = req.Email,
                PasswordHash = PasswordHasher.Hash(req.Password),
                Role = role
            };
            db.Users.Add(user);
            await db.SaveChangesAsync();
            return StatusCode(201, new { message = "registered" });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest req)
        {
            if (!ModelState.IsValid) return ValidationProblem(ModelState);

            var user = await db.Users.SingleOrDefaultAsync(u => u.Email == req.Email);
            if (user is null || !PasswordHasher.Verify(req.Password, user.PasswordHash))
                return Unauthorized(new { error = "Invalid credentials" });

            var token = jwt.CreateToken(user.Id, user.Role);
            return Ok(new { token, role = user.Role });
        }
    }
}
