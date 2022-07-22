using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace TEST.SocialLogin.Back.Entities
{
    /// <summary>
    /// DTO to receive information from external login providers like Google and Facebook.
    /// </summary>
    public class ConfigExternalProviderDataDTO
    {
        [JsonProperty("id")]
        public string Id { get; set; }
        [JsonProperty("email")]
        public string Email { get; set; }
        [JsonProperty("first_name")]
        public string FirstName { get; set; }
        [JsonProperty("last_name")]
        public string LastName { get; set; }
    }
}
