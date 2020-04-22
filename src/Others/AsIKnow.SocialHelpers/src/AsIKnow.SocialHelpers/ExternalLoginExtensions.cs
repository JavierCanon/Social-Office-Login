using Microsoft.AspNetCore.Identity;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;

namespace AsIKnow.SocialHelpers
{
    public static class ExternalLoginExtensions
    {
        public const string PictureClaim = "urn:asiknow.it/external/picture";
        public const string BirthdayClaim = "urn:asiknow.it/external/birthday";

        public static async Task GetExtendedInfo(this ExternalLoginInfo ext)
        {
            string userId = ext.Principal.Claims.First(p => p.Type == ClaimTypes.NameIdentifier).Value;

            List<Claim> claims = null;
            ClaimsPrincipal tmp = null;

            switch (ext.LoginProvider.ToLower())
            {
                case "facebook":
                    string fb_baseUrl = "https://graph.facebook.com";
                    string fb_version = "v2.10";

                    claims = new List<Claim>();
                    claims.AddRange(ext.Principal.Claims);
                    claims.Add(new Claim(PictureClaim, $"{fb_baseUrl}/{fb_version}/{userId}/picture?type=normal"));
                    if(claims.FirstOrDefault(p => p.Type == "urn:facebook:birthday")!=null)
                        claims.Add(new Claim(BirthdayClaim, claims.First(p=>p.Type == "urn:facebook:birthday").Value));
                    tmp = new ClaimsPrincipal(new ClaimsIdentity(claims));
                    ext.Principal = tmp;

                    break;
                case "google":
                    using (HttpClient client = new HttpClient())
                    {
                        client.DefaultRequestHeaders.Accept.Clear();
                        client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", ext.AuthenticationTokens.First(p=>p.Name=="access_token").Value);

                        HttpResponseMessage resp = await client.GetAsync($"https://www.googleapis.com/plus/v1/people/me?prettyPrint=false");

                        JObject jsonObj = JObject.Parse(await resp.Content.ReadAsStringAsync());

                        claims = new List<Claim>();
                        claims.AddRange(ext.Principal.Claims);
                        if(!jsonObj["image"]["isDefault"].Value<bool>())
                            claims.Add(new Claim(PictureClaim, jsonObj["image"]["url"].Value<string>()));
                        if(jsonObj["birthday"]!=null)
                            claims.Add(new Claim(BirthdayClaim, DateTime.Parse(jsonObj["birthday"].Value<string>()).ToString()));
                        if (jsonObj["gender"] != null)
                            claims.Add(new Claim(ClaimTypes.Gender, jsonObj["gender"].Value<string>()));
                        tmp = new ClaimsPrincipal(new ClaimsIdentity(claims));
                        ext.Principal = tmp;

                        break;
                    }
                case "instagram":

                    break;
                default:
                    break;
            }
        }

        public static async Task<byte[]> CopyExternalAvatarInByteArray(this ExternalLoginInfo ext)
        {
            string original_url = ext.Principal.Claims.FirstOrDefault(p => p.Type == PictureClaim)?.Value;
            if (original_url != null)
            {
                using (HttpClient client = new HttpClient())
                {
                    HttpResponseMessage result = await client.GetAsync(original_url);
                    
                    return await result.Content.ReadAsByteArrayAsync();
                }
            }
            else
                return null;
        }
        public static async Task<string> CopyExternalAvatarInTempFile(this ExternalLoginInfo ext)
        {
            string original_url = ext.Principal.Claims.FirstOrDefault(p => p.Type == PictureClaim)?.Value;
            if (original_url != null)
            {
                string tmp = Path.GetTempFileName();

                File.WriteAllBytes(tmp, await ext.CopyExternalAvatarInByteArray());

                return tmp;
            }
            else
                return null;
        }
    }
}
