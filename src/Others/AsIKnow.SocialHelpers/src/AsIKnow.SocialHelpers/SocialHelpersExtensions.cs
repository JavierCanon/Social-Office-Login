using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json.Linq;
using System;
using System.Linq;
using System.Net.Mail;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AsIKnow.SocialHelpers
{
    public static class SocialHelpersExtensions
    {
        private static bool IsValidEmail(string emailaddress)
        {
            try
            {
                MailAddress m = new MailAddress(emailaddress);

                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }

        public static IServiceCollection AddSocialHelpers(this IServiceCollection ext, AuthenticationOptions options)
        {
            //TODO: vedi se rendere configurabili anche gli altri parametri
            if (options.Facebook != null)
            {
                ext.AddAuthentication().AddFacebook(facebookOptions =>
                {
                    facebookOptions.AppId = options.Facebook.AppId;
                    facebookOptions.AppSecret = options.Facebook.AppSecret;

                    //https://developers.facebook.com/docs/graph-api/reference/user
                    facebookOptions.Scope.Add("email");
                    facebookOptions.Fields.Add("gender");
                    facebookOptions.Fields.Add("verified");
                    facebookOptions.Fields.Add("birthday");
                    facebookOptions.Fields.Add("devices");
                    facebookOptions.Fields.Add("link");
                    facebookOptions.SaveTokens = true;
                });
            }

            if (options.Google != null)
            {
                ext.AddAuthentication().AddGoogle(googleOptions =>
                {
                    googleOptions.ClientId = options.Google.ClientId;
                    googleOptions.ClientSecret = options.Google.ClientSecret;
                    //https://stackoverflow.com/questions/45855503/how-to-retrieve-google-profile-picture-from-logged-in-user-with-asp-net-core-ide
                    googleOptions.Scope.Add("profile");
                    googleOptions.Scope.Add("email");
                    googleOptions.Scope.Add("openid");
                    googleOptions.SaveTokens = true;
                });
            }

            if (options.Instagram != null)
            {
                ext.AddAuthentication().AddInstagram(instagramOptions =>
                {
                    instagramOptions.ClientId = options.Instagram.ClientId;
                    instagramOptions.ClientSecret = options.Instagram.ClientSecret;
                    instagramOptions.SignInScheme = IdentityConstants.ExternalScheme;
                    instagramOptions.UseSignedRequests = true;
                    instagramOptions.Events.OnCreatingTicket = ctx =>
                    {
                        ctx.Identity.AddClaim(new Claim("sub", ctx.TokenResponse.Response["user"]["id"].Value<string>()));
                        ctx.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, ctx.TokenResponse.Response["user"]["id"].Value<string>()));
                        if (IsValidEmail(ctx.TokenResponse.Response["user"]["username"].Value<string>()))
                        {
                            ctx.Identity.AddClaim(new Claim("email", ctx.TokenResponse.Response["user"]["username"].Value<string>()));
                            ctx.Identity.AddClaim(new Claim(ClaimTypes.Email, ctx.TokenResponse.Response["user"]["username"].Value<string>()));
                        }
                        else
                        {
                            ctx.Identity.AddClaim(new Claim("email", ""));
                            ctx.Identity.AddClaim(new Claim(ClaimTypes.Email, ""));
                        }

                        string name = ctx.TokenResponse.Response["user"]["full_name"].Value<string>()?.Split(' ')?.FirstOrDefault()??"";
                        string surname = ctx.TokenResponse.Response["user"]["full_name"].Value<string>().Replace($"{name} ","");

                        ctx.Identity.AddClaim(new Claim("name", ctx.TokenResponse.Response["user"]["username"].Value<string>()));
                        ctx.Identity.AddClaim(new Claim("full_name", ctx.TokenResponse.Response["user"]["full_name"].Value<string>()));
                        ctx.Identity.AddClaim(new Claim("given_name", name));
                        ctx.Identity.AddClaim(new Claim("givenname", name));
                        ctx.Identity.AddClaim(new Claim("family_name", surname));
                        ctx.Identity.AddClaim(new Claim("surname", surname));
                        ctx.Identity.AddClaim(new Claim(ClaimTypes.GivenName, ctx.TokenResponse.Response["user"]["full_name"].Value<string>()));
                        ctx.Identity.AddClaim(new Claim(ExternalLoginExtensions.PictureClaim, ctx.TokenResponse.Response["user"]["profile_picture"].Value<string>()));

                        return Task.CompletedTask;
                    };
                });
            }

            return ext;
        }
    }
}
