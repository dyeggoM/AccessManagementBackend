using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;


namespace TEST.SocialLogin.Back.Entities
{
    public class DTOExternalProviderLogin : DTOCaptcha
    {
        [Required]
        public string Provider { get; set; }

        [Required]
        public string IdToken { get; set; }

    }
}
