using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace TEST.SocialLogin.Back.Controllers
{
    /// <summary>
    /// Endpoint to check system status.
    /// </summary>
    [Route("api/[controller]/Usuarios")]
    [ApiController]
    public class HealthController : ControllerBase
    {
        private readonly IHostEnvironment _env;
        private readonly IConfiguration _configuration;
        private readonly ILogger<HealthController> _logger;

        /// <summary></summary><param name="configuration"></param><param name="env"></param><param name="logger"></param>
        public HealthController(IConfiguration configuration, IHostEnvironment env, ILogger<HealthController> logger)
        {
            _configuration = configuration;
            _env = env;
            _logger = logger;
        }

        /// <summary>
        /// Logs an error with a specific format.
        /// </summary>
        /// <param name="e">Exception to log.</param>
        /// <param name="methodName">Method name to log.</param>
        private void LogErrors(Exception e, string methodName)
        {
            _logger.Log(LogLevel.Error, $"{nameof(HealthController)}.{methodName}: {e.Message}");
            _logger.Log(LogLevel.Error, $"{nameof(HealthController)}.{methodName}: {e.InnerException}");
        }

        /// <summary>
        /// Gets the current environment and app version.
        /// </summary>
        /// <response code="200">Environment information.</response>
        /// <response code="500">Server error.</response>
        [HttpGet]
        public IActionResult Get()
        {
            try
            {
                var environment = $"Environment: {_configuration["Environment"]}";
                var version = $"Version: {_configuration["Version"]}";
                return Ok(string.Join("\n", new[] { environment, version }));
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(Get));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// Shows the logs for the specified date.
        /// </summary>
        /// <param name="date">Date of the log in format 'yyyyMMdd'.</param>
        /// <returns>Log.</returns>
        /// <response code="200">Log information.</response>
        /// <response code="404">Log not found.</response>
        /// <response code="500">Server error.</response>
        [HttpGet("{date}")]
        public IActionResult Logs(string date)
        {
            var directoryPath = Path.Combine(_env.ContentRootPath, "Logs");
            var fileName = $"{date}_Logs.txt";
            var filePath = Path.Combine(directoryPath, fileName);
            string file;
            try
            {
                if (!System.IO.File.Exists(filePath))
                {
                    _logger.Log(LogLevel.Warning, $"{nameof(HealthController)}.{nameof(Logs)}: Requested log {date} not found.");
                    return NotFound();
                }
                file = System.IO.File.ReadAllText(filePath);
            }
            catch (Exception e)
            {
                LogErrors(e, nameof(Logs));
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
            return Ok(file);
        }
    }
}
