using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace Asciinema.Server.Oidc
{
    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var oidcConfig = new OidcConfig();
            _configuration.GetSection("Oidc").Bind(oidcConfig);

            var dbConfig = new DatabaseConfig();
            _configuration.GetSection("Database").Bind(dbConfig);

            services.Configure<AsciinemaConfig>(_configuration.GetSection("Asciinema").Bind);

            var connString = dbConfig.ConnectionString ??
                new NpgsqlConnectionStringBuilder
                {
                    Host = dbConfig.Host,
                    Database = dbConfig.Database,
                    Username = dbConfig.User,
                    Password = dbConfig.Password,
                    SslMode = SslMode.Prefer,
                }.ConnectionString;

            Console.WriteLine($"Connecting to database: {dbConfig.Host}");

            services.AddScoped<IDbConnection>(sp => new NpgsqlConnection(connString));

            services.Configure<ForwardedHeadersOptions>(opts => {
                opts.ForwardedHeaders = ForwardedHeaders.XForwardedHost | ForwardedHeaders.XForwardedProto | ForwardedHeaders.XForwardedFor;
                opts.KnownNetworks.Clear();
                opts.KnownProxies.Clear();
            });

            services.AddAuthentication(opts => {
                opts.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                opts.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
                .AddCookie()
                .AddOpenIdConnect(cfg => {
                    cfg.Authority = oidcConfig.Authority;
                    cfg.ClientId = oidcConfig.ClientId;
                    cfg.ClientSecret = oidcConfig.ClientSecret;
                });

            services.AddControllers();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseForwardedHeaders();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
