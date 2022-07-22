using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace TEST.SocialLogin.Back.Entities
{
    public class DTORegister : DTOCaptcha
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
        public string Provider { get; set; }
        public string Token { get; set; }

    }
}
