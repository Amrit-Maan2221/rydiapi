using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Data.SqlClient;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace rydeapi.Controllers
{
    public class RegisterRequest
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public string Password { get; set; }
        public string Country { get; set; }
    }

    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    [ApiController]
    [Route("api/[controller]/[action]")]
    public class AuthController : ControllerBase
    {
        private readonly string _connectionString;
        private readonly IConfiguration _configuration;

        public AuthController(IConfiguration configuration)
        {
            _configuration = configuration;
            _connectionString = configuration.GetConnectionString("DefaultConnection") ?? throw new Exception("Connection string not found.");
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            // Hash the password
            var passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);

            // Check if the user already exists
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                var checkUserQuery = "SELECT COUNT(1) FROM Users WHERE nvcEmail = @Email";
                using (var checkUserCommand = new SqlCommand(checkUserQuery, connection))
                {
                    checkUserCommand.Parameters.AddWithValue("@Email", request.Email);
                    var userExists = (int)await checkUserCommand.ExecuteScalarAsync() > 0;

                    if (userExists)
                    {
                        return Conflict(new { message = "A user with this email already exists." });
                    }
                }

                // Insert the new user
                var insertUserQuery = @"
                    INSERT INTO Users (nvcName, nvcEmail, nvcPhone, nvcPasswordHash, nvcCountry)
                    VALUES (@Name, @Email, @Phone, @PasswordHash, @Country)";

                using (var insertUserCommand = new SqlCommand(insertUserQuery, connection))
                {
                    insertUserCommand.Parameters.AddWithValue("@Name", request.Name);
                    insertUserCommand.Parameters.AddWithValue("@Email", request.Email);
                    insertUserCommand.Parameters.AddWithValue("@Phone", request.Phone ?? (object)DBNull.Value);
                    insertUserCommand.Parameters.AddWithValue("@PasswordHash", passwordHash);
                    insertUserCommand.Parameters.AddWithValue("@Country", request.Country);

                    await insertUserCommand.ExecuteNonQueryAsync();
                }
            }

            return Ok(new { message = "User registered successfully." });
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            if (string.IsNullOrEmpty(request.Email) || string.IsNullOrEmpty(request.Password))
            {
                return BadRequest(new { message = "Email and password are required." });
            }

            string? passwordHash = null;
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();

                var getUserQuery = @"
                    SELECT nvcPasswordHash 
                    FROM Users 
                    WHERE nvcEmail = @Email";

                using (var getUserCommand = new SqlCommand(getUserQuery, connection))
                {
                    getUserCommand.Parameters.AddWithValue("@Email", request.Email);
                    passwordHash = (string?)await getUserCommand.ExecuteScalarAsync();
                }
            }

            if (passwordHash == null || !BCrypt.Net.BCrypt.Verify(request.Password, passwordHash))
            {
                return Unauthorized(new { message = "Invalid email or password." });
            }

            // Generate JWT token
            var token = GenerateJwtToken(request.Email);

            return Ok(new { message = "Login successful.", token });
        }

        private string GenerateJwtToken(string email)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Secret"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, email)
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpiryInMonths"])),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
