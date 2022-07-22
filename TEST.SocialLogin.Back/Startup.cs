using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using TEST.SocialLogin.Back.Data;
using TEST.SocialLogin.Back.Entities;
using TEST.SocialLogin.Back.Interfaces;
using TEST.SocialLogin.Back.Services;

namespace TEST.SocialLogin.Back
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {

            #region Services
            //NOTE: Services
            services.AddSingleton<ILoggerProvider, FileLoggerProvider>();
            services.AddSingleton<IEmailService, EmailService>();
            services.AddTransient<IAccountService, AccountService>();
            #endregion

            #region DB
            //NOTE: DataBase
            const string connectionString = "DatabaseConnection";
            services.AddDbContextPool<ApplicationContext>(
                options =>
                    options.UseSqlServer(
                        Configuration.GetConnectionString(connectionString), sqloptions =>
                        {
                            sqloptions.EnableRetryOnFailure(
                                maxRetryCount: 3,
                                maxRetryDelay: TimeSpan.FromSeconds(10),
                                errorNumbersToAdd: new List<int>() { });
                        })
            );
            #endregion

            #region Authentication
            //NOTE: ASP Identity
            services.AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                //options.SignIn.RequireConfirmedEmail = true;
                //options.User.RequireUniqueEmail = true;
                options.Password.RequiredLength = 6;
                options.Password.RequiredUniqueChars = 1;
                options.Password.RequireDigit = true;
                options.Password.RequireLowercase = true;
                options.Password.RequireUppercase = true;
                options.Password.RequireNonAlphanumeric = true;
            })
                .AddEntityFrameworkStores<ApplicationContext>()
                .AddDefaultTokenProviders();
            // NOTE: Token Authentication
            var key = Encoding.ASCII.GetBytes(Configuration["ApiConfiguration:Secret"]);
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            })
                .AddJwtBearer(x =>
                {
                    x.RequireHttpsMetadata = false;
                    x.SaveToken = true;
                    x.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(key),
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.Zero //the default for this setting is 5 minutes
                    };
                    x.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = context =>
                        {
                            if (context.Exception.GetType() == typeof(SecurityTokenExpiredException))
                            {
                                context.Response.Headers.Add("Token-Expired", "true");
                            }
                            return Task.CompletedTask;
                        }
                    };
                });
            //NOTE: Social Logins
            services.AddAuthentication()
                .AddGoogle(options =>
                {
                    options.ClientId = Configuration["Google:ClientId"];
                    options.ClientSecret = Configuration["Google:ClientSecret"];
                    //options.CallbackPath = "";
                })
                .AddFacebook(options =>
                {
                    options.AppId = Configuration["Facebook:AppId"];
                    options.AppSecret = Configuration["Facebook:AppSecret"];
                });
            #endregion

            #region CORS
            //NOTE: Cors
            services.AddCors(confg =>
                confg.AddPolicy("AllowCors",
                    p => p
                        .WithOrigins(Configuration["CORS:AllowedCors"].Split(","))
                        .WithMethods("POST", "PUT", "GET", "DELETE")
                        .AllowAnyHeader()));
            #endregion

            //NOTE: Default
            services.AddControllers()
                .AddNewtonsoftJson(options =>
                {
                    options.SerializerSettings.ReferenceLoopHandling = Newtonsoft.Json.ReferenceLoopHandling.Ignore;
                    options.SerializerSettings.NullValueHandling = Newtonsoft.Json.NullValueHandling.Ignore;
                });

            //NOTE: Swagger
            services.AddSwaggerGen(c =>
            {
                c.AddSecurityDefinition(JwtBearerDefaults.AuthenticationScheme, new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
                    Name = "Bearer",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = JwtBearerDefaults.AuthenticationScheme,
                    BearerFormat = "JTW"
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = JwtBearerDefaults.AuthenticationScheme,
                            }
                        },
                        new string[] { }
                    }
                });
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "TEST.SocialLogin.Back", Version = "v1" });
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            app.UseSwagger();
            app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "TEST.SocialLogin.Back v1"));
            app.UseHttpsRedirection();
            app.UseCors("AllowCors");
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
