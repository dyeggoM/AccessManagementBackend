using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace TEST.SocialLogin.Back.Services
{
    /// <summary></summary>
    public class FileLoggerProvider : ILoggerProvider
    {
        private readonly IHostEnvironment _env;
        /// <summary></summary><param name="env"></param>
        public FileLoggerProvider(IHostEnvironment env)
        {
            _env = env;
        }
        /// <summary></summary><param name="categoryName"></param><returns></returns>
        public ILogger CreateLogger(string categoryName)
        {
            return new FileLogger(_env);
        }
        /// <summary></summary>
        public void Dispose()
        {
        }
    }

    /// <summary></summary>
    public class FileLogger : ILogger
    {
        private readonly IHostEnvironment _env;

        /// <summary></summary><param name="env"></param>
        public FileLogger(IHostEnvironment env)
        {
            _env = env;
        }

        /// <summary></summary><typeparam name="TState"></typeparam><param name="state"></param><returns></returns>
        public IDisposable BeginScope<TState>(TState state)
        {
            return null;
        }

        /// <summary></summary><param name="logLevel"></param><returns></returns>
        public bool IsEnabled(LogLevel logLevel)
        {
            return logLevel != LogLevel.None;
        }

        /// <summary></summary><typeparam name="TState"></typeparam><param name="logLevel"></param><param name="eventId"></param><param name="state"></param><param name="exception"></param><param name="formatter"></param>
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            if (!IsEnabled(logLevel))
            {
                return;
            }
            var stateResult = exception != null ? exception.StackTrace : "";
            var logRecord = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss+00:00}] [{logLevel}] {formatter(state, exception)} {stateResult}";
            var directoryPath = Path.Combine(_env.ContentRootPath, "Logs");
            if (!Directory.Exists(directoryPath))
                Directory.CreateDirectory(directoryPath);
            var fileName = $"{DateTime.UtcNow.AddHours(-5):yyyyMMdd}_Logs.txt";
            var filePath = Path.Combine(directoryPath, fileName);
            try
            {
                using (var streamWriter = new StreamWriter(filePath, true))
                {
                    streamWriter.WriteLine(logRecord);
                }
            }
            catch (Exception)
            {
                return;
            }
        }
    }
}
