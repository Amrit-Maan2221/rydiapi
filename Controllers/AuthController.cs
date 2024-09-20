using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
using System.Text;

// For more information on enabling Web API for empty projects, visit https://go.microsoft.com/fwlink/?LinkID=397860

namespace rydeapi.Controllers
{
    public class RegisterRequest
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Phone { get; set; }
        public string Password { get; set; }
        public string Country { get; set; } // Added Country field
    }



    [ApiController]
    [Route("api/[controller]/[action]")]
    public class AuthController : ControllerBase
    {
        private readonly string _connectionString;

        public AuthController(IConfiguration configuration)
        {
            _connectionString = configuration.GetConnectionString("DefaultConnection") ?? throw new Exception();
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

        [HttpGet]
        public async Task<IActionResult> Register()
        {
            

            return Ok(new { message = "User registered successfully." });
        }

    }
}
