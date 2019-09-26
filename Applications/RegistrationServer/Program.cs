using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Steeltoe.Extensions.Configuration.CloudFoundry;

namespace RegistrationServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            BuildWebHost(args).Run();
        }

        public static IWebHost BuildWebHost(string[] args) =>
            WebHostBuilder(args).Build();

        public static IWebHostBuilder WebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                // https://github.com/aspnet/KestrelHttpServer/issues/1998#issuecomment-322922164
                .UseConfiguration(new ConfigurationBuilder().AddCommandLine(args).Build())
                .UseCloudFoundryHosting()
                .AddCloudFoundry()
                .UseStartup<Startup>();
    }
}