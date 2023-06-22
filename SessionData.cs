using System.Net;

namespace SteamAuth
{
    public class SessionData
    {
        public string proxy = "";
        public int proxy_type = 0;

        public SessionData(string proxy, int proxy_type)
        {
            this.proxy = proxy;
            this.proxy_type = proxy_type;
        }

        public string SessionID { get; set; }

        //public string SteamLogin { get; set; }

        public string steamRememberLogin { get; set; }


        public string SteamLoginSecure { get; set; }

        public string WebCookie { get; set; }

        public string OAuthToken { get; set; }

        public ulong SteamID { get; set; }

        public void AddCookies(CookieContainer cookies)
        {
            cookies.Add(new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
            cookies.Add(new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));

            cookies.Add(new Cookie("steamid", SteamID.ToString(), "/", ".steamcommunity.com"));
            /*cookies.Add(new Cookie("steamLogin", SteamLogin, "/", ".steamcommunity.com")
            {
                HttpOnly = true
            });*/

            if (!string.IsNullOrEmpty(steamRememberLogin))
                cookies.Add(new Cookie("steamRememberLogin", steamRememberLogin, "/", ".steamcommunity.com")
                {
                    HttpOnly = true
                });

            cookies.Add(new Cookie("steamLoginSecure", SteamLoginSecure, "/", ".steamcommunity.com")
            {
                HttpOnly = true,
                Secure = true
            });
            cookies.Add(new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));
            cookies.Add(new Cookie("dob", "", "/", ".steamcommunity.com"));
            cookies.Add(new Cookie("sessionid", this.SessionID, "/", ".steamcommunity.com"));
        }
    }
}
