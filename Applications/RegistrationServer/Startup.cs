using Accounts;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Pivotal.Discovery.Client;
using Projects;
using Steeltoe.CloudFoundry.Connector.MySql.EFCore;
using Users;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Steeltoe.Security.Authentication.CloudFoundry;

namespace RegistrationServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            // Add framework services.
            services.AddMvc(mvcOptions =>
            {
                if (!Configuration.GetValue("DISABLE_AUTH", false))
                {
                    // Set Authorized as default policy
                    var policy = new AuthorizationPolicyBuilder(JwtBearerDefaults.AuthenticationScheme)
                    .RequireAuthenticatedUser()
                    .RequireClaim("scope", "uaa.resource")
                    .Build();
                    mvcOptions.Filters.Add(new AuthorizeFilter(policy));
                }
            });

            services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddCloudFoundryJwtBearer(Configuration);

            services.AddDbContext<AccountContext>(options => options.UseMySql(Configuration));
            services.AddDbContext<ProjectContext>(options => options.UseMySql(Configuration));
            services.AddDbContext<UserContext>(options => options.UseMySql(Configuration));

            services.AddScoped<IAccountDataGateway, AccountDataGateway>();
            services.AddScoped<IProjectDataGateway, ProjectDataGateway>();
            services.AddScoped<IUserDataGateway, UserDataGateway>();
            services.AddScoped<IRegistrationService, RegistrationService>();
            services.AddDiscoveryClient(Configuration);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            app.UseMvc();
            app.UseDiscoveryClient();
        }
    }
}