using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Threading.Tasks;
using TEST.SocialLogin.Back.Entities;
using TEST.SocialLogin.Back.Interfaces;

namespace TEST.SocialLogin.Back.Services
{
    /// <summary>
    /// Email service
    /// </summary>
    public class EmailService: IEmailService
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<EmailService> _logger;
        /// <summary></summary><param name="configuration"></param><param name="logger"></param>
        public EmailService(IConfiguration configuration, ILogger<EmailService> logger)
        {
            _configuration = configuration;
            _logger = logger;
        }

        /// <summary>
        /// Logs an error with a specific format.
        /// </summary>
        /// <param name="e">Exception to log.</param>
        /// <param name="methodName">Method name to log.</param>
        private void LogErrors(Exception e, string methodName)
        {
            _logger.Log(LogLevel.Error, $"{nameof(EmailService)}.{methodName}: {e.Message}");
            _logger.Log(LogLevel.Error, $"{nameof(EmailService)}.{methodName}: {e.InnerException}");
        }

        /// <summary>
        /// This method sends an email.
        /// </summary>
        /// <param name="emailDTO">Email parameters.</param>
        /// <returns></returns>
        public async Task<bool> SendTextEmail(ConfigEmailDTO emailDTO)
        {
            var t = Task.Run(() => {
                try
                {
                    var smtpClient = new SmtpClient
                    {
                        UseDefaultCredentials = false,
                        Host = _configuration[$"EmailConfiguration:Host"],
                        Port = int.Parse(_configuration[$"EmailConfiguration:Port"]),
                        Credentials = new System.Net.NetworkCredential(_configuration[$"EmailConfiguration:User"], _configuration[$"EmailConfiguration:Password"]),
                        EnableSsl = bool.Parse(_configuration[$"EmailConfiguration:SSL"])
                    };
                    var fromMail = new MailAddress(emailDTO.From, emailDTO.FromName);
                    var toMail = new MailAddress(emailDTO.To);
                    var mail = new MailMessage(fromMail, toMail);
                    mail.Subject = emailDTO.Subject;
                    mail.Body = emailDTO.Body;
                    mail.IsBodyHtml = emailDTO.IsHtml;
                    smtpClient.Send(mail);
                    return true;
                }
                catch (Exception e)
                {
                    LogErrors(e, nameof(SendTextEmail));
                    return false;
                }
            });
            return await t;
        }
    }
}
