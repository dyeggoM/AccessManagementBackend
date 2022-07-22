﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.ComponentModel.DataAnnotations;

namespace TEST.SocialLogin.Back.Entities
{
    public class DTOLogin : DTOCaptcha
    {
        [Required]
        [EmailAddress]
        public string Email { get; set; }

        //[Required]
        [DataType(DataType.Password)]
        public string Password { get; set; }

    }
}
