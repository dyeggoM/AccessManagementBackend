using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TEST.SocialLogin.Back.Entities
{
    public class ApplicationUser : IdentityUser
    {
        public string RefreshToken { get; set; }
    }
}
