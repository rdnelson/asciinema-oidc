using System;
using System.Data;
using System.Data.Common;
using System.IO;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Asciinema.Server.Oidc.Controllers
{
    [Route("/")]
    public class AuthController : Controller
    {
        private readonly IOptionsSnapshot<AsciinemaConfig> _asciinemaConfig;
        private readonly IDbConnection _connection;
        private readonly ILogger<AuthController> _logger;

        public AuthController(IDbConnection connection, IOptionsSnapshot<AsciinemaConfig> asciinemaConfig, ILogger<AuthController> logger)
        {
            _connection = connection;

            if (connection.State != ConnectionState.Open)
            {
                connection.Open();
            }

            _asciinemaConfig = asciinemaConfig;
            _logger = logger;
        }

        [Authorize]
        [HttpGet("/login/new")]
        public async Task<IActionResult> CreateAuthLink()
        {
            var email = User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email)?.Value;
            if (email == null)
            {
                return Forbid();
            }

            using (var cmd = _connection.CreateCommand())
            {
                cmd.CommandText = "SELECT id, last_login_at FROM users WHERE email = @p";
                var emailParam = cmd.CreateParameter();
                emailParam.DbType = DbType.String;
                emailParam.ParameterName = "p";
                emailParam.Value = email;
                cmd.Parameters.Add(emailParam);

                using var row = cmd.ExecuteReader();
                if (row.Read())
                {
                    _logger.LogDebug("User exists");
                    var id = row.GetInt32(0);
                    var lastLogin = row.GetDateTime(1);
                    return await Login(id, lastLogin);
                }
                else
                {
                    _logger.LogDebug("Creating user");
                    return await Signup(email);
                }
            }

        }

        public async Task<IActionResult> Login(long id, DateTime lastLogin)
        {
            var payload = new byte[]
            {
                131,
                104, 3,
                104, 2,
                98, 0, 0, 0, 2, // User id
                98, 97, 116, 160, 236, // Last Login timestamp
                110, 6, 0, 112, 184, 177, 175, 124, 1, // Created timestamp ms
                98, 0, 1, 81, 128 // Validity
            };

            Array.Copy(BitConverter.GetBytes(id).Reverse().ToArray(), 4, payload, 6, 4);

            var lastLoginOffset = new DateTimeOffset(lastLogin, TimeSpan.Zero);
            var lastLoginTimestamp = lastLoginOffset.ToUnixTimeSeconds();
            Array.Copy(BitConverter.GetBytes(lastLoginTimestamp).Reverse().ToArray(), 4, payload, 11, 4);

            Console.WriteLine($"Login for user {id}");

            UpdateTimestamp(payload, 18);

            return Redirect($"/session/new?t={await GetLink("login", payload)}");
        }

        public async Task<IActionResult> Signup(string email)
        {
            var payloadHeader = new byte[]
            {
                131,
                104, 3,
                109
            };

            var payloadFooter = new byte[]
            {
                110, 6, 0, 214, 60, 87, 174, 124, 1, // Created timestamp ms
                98, 0, 1, 81, 128 // Validity
            };
            UpdateTimestamp(payloadFooter, 3);

            var body = BitConverter.GetBytes(email.Length).Reverse()
                .Concat(Encoding.UTF8.GetBytes(email));


            var payload = payloadHeader.Concat(body).Concat(payloadFooter).ToArray();

            var redirect = $"/users/new?t={await GetLink("signup", payload)}";

            return Redirect(redirect);
        }

        public async Task<string> GetLink(string op, byte[] payload)
        {
            _logger.LogDebug($"Using secret of {_asciinemaConfig.Value.Secret.Length} bytes.");
            var key = KeyDerivation.Pbkdf2(_asciinemaConfig.Value.Secret, Encoding.UTF8.GetBytes(op), KeyDerivationPrf.HMACSHA256, 1000, 32);
            var hmac = new HMACSHA256(key);

            var data = ToBase64("HS256") + "." + ToBase64(payload).Replace("=", string.Empty);
            var binData = Encoding.ASCII.GetBytes(data);

            var sig = await hmac.ComputeHashAsync(new MemoryStream(binData));
            var sigStr = ToBase64(sig);
            return data + "." + sigStr;
        }

        private void UpdateTimestamp(byte[] data, int offset)
        {
            var timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
            var timestampBytes = BitConverter.GetBytes(timestamp);
            Array.Copy(timestampBytes, 0, data, offset, 6);
        }

        public string ToBase64(string data) =>
            ToBase64(Encoding.UTF8.GetBytes(data));

        public string ToBase64(byte[] data)
        {
            return Convert.ToBase64String(data, Base64FormattingOptions.None)
                .Replace("=", string.Empty)
                .Replace("+", "-")
                .Replace("/", "_");
        }
    }
}
