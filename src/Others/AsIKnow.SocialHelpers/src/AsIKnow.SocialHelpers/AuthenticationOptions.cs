using AspNet.Security.OAuth.Instagram;
using Microsoft.AspNetCore.Authentication.Facebook;
using Microsoft.AspNetCore.Authentication.Google;
using System;
using System.Collections.Generic;
using System.Text;

namespace AsIKnow.SocialHelpers
{
    public class AuthenticationOptions
    {
        public FacebookOptions Facebook { get; set; }
        public GoogleOptions Google { get; set; }
        public InstagramAuthenticationOptions Instagram { get; set; }
    }
}
