using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using TEST.SocialLogin.Back.Entities;

namespace TEST.SocialLogin.Back.Interfaces
{
    /// <summary>
    /// Email service
    /// </summary>
    public interface IEmailService
    {
        /// <summary>
        /// Sends email
        /// </summary>
        /// <param name="emailDTO">Email configuration</param>
        /// <returns></returns>
        Task<bool> SendTextEmail(ConfigEmailDTO emailDTO);
    }
}
