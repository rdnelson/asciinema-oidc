namespace Asciinema.Server.Oidc
{
    public class DatabaseConfig
    {
        public string Host { get; set; } = "postgres";

        public string User { get; set; } = "postgres";

        public string Password { get; set; } = "postgres";

        public string Database { get; set; } = "postgres";

        public bool DisableSslVerification { get; set; } = false;

        public string ConnectionString { get; set; }
    }
}
