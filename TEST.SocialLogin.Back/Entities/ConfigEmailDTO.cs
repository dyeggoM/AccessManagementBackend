using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TEST.SocialLogin.Back.Entities
{
    public class ConfigEmailDTO
    {
        public string From { get; set; }
        public string FromName { get; set; }
        public string To { get; set; }
        public string ToName { get; set; }
        public string Subject { get; set; }
        public string Body { get; set; }
        public bool IsHtml { get; set; }
    }
}
