using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace SteamAuth
{
    /// <summary>
    /// Handles logging the user into the mobile Steam website. Necessary to generate OAuth token and session cookies.
    /// </summary>
    public class UserLogin
    {
        public string proxy = "";
        public int proxy_type = 0;

        public string Username;
        public string Password;

        public string refresh_token;

        public ulong SteamID;

        public bool RequiresCaptcha;
        public string CaptchaGID = null;
        public string CaptchaText = null;

        public bool RequiresEmail;
        public string EmailDomain = null;
        public string EmailCode = null;

        public bool Requires2FA;
        public string TwoFactorCode = null;

        public SessionData Session = null;
        public bool LoggedIn = false;

        public CookieContainer _cookies = new CookieContainer();

        public UserLogin(string username, string password, string proxy, int proxy_type)
        {
            this.Username = username;
            this.Password = password;

            this.proxy = proxy;
            this.proxy_type = proxy_type;
        }

        public UserLogin(string username, string password)
        {
            this.Username = username;
            this.Password = password;
        }

        public LoginResult DoLoginV2()
        {
            var postData = new NameValueCollection();
            Dictionary<string, string> multipartData = new Dictionary<string, string>();

            var cookies = _cookies;
            string response = null;

            if (cookies.Count == 0)
            {
                //Generate a SessionID
                SteamWeb.Request("https://steamcommunity.com/", "GET", proxy, proxy_type, "", cookies);
                SteamWeb.Request("https://store.steampowered.com/", "GET", proxy, proxy_type, "", cookies);
            }

            var c1 = cookies.GetCookies(new Uri("https://steamcommunity.com"));

            if (c1["sessionid"] == null || c1["sessionid"].Value == null)
                return LoginResult.GeneralFailure;


            response = SteamWeb.Request(APIEndpoints.GetPasswordRSAPublicKey + "?account_name=" + this.Username, "GET", proxy, proxy_type, postData, cookies);
            if (response == null || response.Contains("<BODY>\nAn error occurred while processing your request.")) return LoginResult.GeneralFailure;

            var rsaResponse = JsonConvert.DeserializeObject<GetPasswordRSAPublicKey>(response);

            if (rsaResponse == null || rsaResponse.response == null || string.IsNullOrEmpty(rsaResponse.response.publickey_exp))
            {
                return LoginResult.BadRSA;
            }

            Thread.Sleep(350); //Sleep for a bit to give Steam a chance to catch up??

            RNGCryptoServiceProvider secureRandom = new RNGCryptoServiceProvider();
            byte[] encryptedPasswordBytes;
            using (var rsaEncryptor = new RSACryptoServiceProvider())
            {
                var passwordBytes = Encoding.ASCII.GetBytes(this.Password);
                var rsaParameters = rsaEncryptor.ExportParameters(false);
                rsaParameters.Exponent = Util.HexStringToByteArray(rsaResponse.response.publickey_exp);
                rsaParameters.Modulus = Util.HexStringToByteArray(rsaResponse.response.publickey_mod);
                rsaEncryptor.ImportParameters(rsaParameters);
                encryptedPasswordBytes = rsaEncryptor.Encrypt(passwordBytes, false);
            }

            string encryptedPassword = Convert.ToBase64String(encryptedPasswordBytes);

            //-------------------------------------

            postData.Clear();
            postData.Add("persistence", "1");
            postData.Add("encrypted_password", encryptedPassword);
            postData.Add("account_name", this.Username);
            postData.Add("encryption_timestamp", rsaResponse.response.timestamp);


            response = SteamWeb.Request(APIEndpoints.BeginAuthSessionViaCredentials, "POST", proxy, proxy_type, postData, cookies);
            if (response == null) return LoginResult.GeneralFailure;

            var loginResponse = JsonConvert.DeserializeObject<BeginAuthSessionViaCredentials>(response);

            if (loginResponse == null || loginResponse.response == null || string.IsNullOrEmpty(loginResponse.response.client_id))
            {
                return LoginResult.BadCredentials;
            }

            //-------------------------------------

            if (loginResponse.response.allowed_confirmations != null && loginResponse.response.allowed_confirmations.FirstOrDefault(x => x.confirmation_type == 3) != null)
            {
                this.Requires2FA = true;
                return LoginResult.Need2FA;
            }

            if (string.IsNullOrEmpty(this.EmailCode) && loginResponse.response.allowed_confirmations != null && loginResponse.response.allowed_confirmations.FirstOrDefault(x => x.confirmation_type == 2) != null)
            {
               /* multipartData.Clear();
               
                multipartData.Add("clientid", loginResponse.response.client_id);
                multipartData.Add("steamid", loginResponse.response.steamid);

                response = SteamWeb.Request(" https://login.steampowered.com/jwt/checkdevice/" + loginResponse.response.steamid, "POST", proxy, proxy_type, multipartData, cookies);
                if (response == null) return LoginResult.GeneralFailure;*/


                this.RequiresEmail = true;
                this.SteamID = ulong.Parse(loginResponse.response.steamid);
                return LoginResult.NeedEmail;
            }

            if (!string.IsNullOrEmpty(this.EmailCode))
            {
                postData.Clear();
                postData.Add("client_id", loginResponse.response.client_id);
                postData.Add("steamid", loginResponse.response.steamid);
                postData.Add("code_type", "2");
                postData.Add("code", this.EmailCode);


                response = SteamWeb.MobileLoginRequest(APIEndpoints.UpdateAuthSessionWithSteamGuardCode, "POST", proxy, proxy_type, postData, cookies);
                if (response == null) return LoginResult.GeneralFailure;

                /*var _BeginAuthSessionViaCredentials = JsonConvert.DeserializeObject<BeginAuthSessionViaCredentials>(response);

                if (_BeginAuthSessionViaCredentials == null || _BeginAuthSessionViaCredentials.response == null || string.IsNullOrEmpty(_BeginAuthSessionViaCredentials.response.client_id))
                {
                    return LoginResult.BadCredentials;
                }*/
            }

            //-------------------------------------

            postData.Clear();
            postData.Add("client_id", loginResponse.response.client_id);
            postData.Add("request_id", loginResponse.response.request_id);

            response = SteamWeb.Request(APIEndpoints.PollAuthSessionStatus, "POST", proxy, proxy_type, postData, cookies);
            if (response == null) return LoginResult.GeneralFailure;

            var _PollAuthSessionStatus = JsonConvert.DeserializeObject<PollAuthSessionStatus>(response);

            if (_PollAuthSessionStatus == null || _PollAuthSessionStatus.response == null || string.IsNullOrEmpty(_PollAuthSessionStatus.response.refresh_token) || string.IsNullOrEmpty(_PollAuthSessionStatus.response.access_token))
            {
                return LoginResult.BadCredentials;
            }

            //-------------------------------------

            postData.Clear();
            postData.Add("nonce", _PollAuthSessionStatus.response.refresh_token);
            postData.Add("sessionid", cookies.GetCookies(new Uri("https://steamcommunity.com"))["sessionid"].Value);
            postData.Add("redir", "https://steamcommunity.com/login/home/?goto=");

            response = SteamWeb.Request(APIEndpoints.finalizelogin, "POST", proxy, proxy_type, postData, cookies);
            if (response == null) return LoginResult.GeneralFailure;

            var _finalizelogin = JsonConvert.DeserializeObject<finalizelogin>(response);

            if (_finalizelogin == null || _finalizelogin.transfer_info == null || _finalizelogin.transfer_info.Count == 0 || _finalizelogin.transfer_info.FirstOrDefault(x => x.url == "https://steamcommunity.com/login/settoken") == null || string.IsNullOrEmpty(_finalizelogin.steamID))
            {
                return LoginResult.GeneralFailure;
            }

            //-------------------------------------

            
            multipartData.Clear();
            multipartData.Add("nonce", _finalizelogin.transfer_info.FirstOrDefault(x => x.url == "https://steamcommunity.com/login/settoken").@params.nonce);
            multipartData.Add("auth", _finalizelogin.transfer_info.FirstOrDefault(x => x.url == "https://steamcommunity.com/login/settoken").@params.auth);
            multipartData.Add("steamID", loginResponse.response.steamid);

            response = SteamWeb.Request(APIEndpoints.settoken, "POST", proxy, proxy_type, multipartData, cookies);
            if (response == null) return LoginResult.GeneralFailure;


            //--------------------------------------

            //Dictionary<string, string> multipartData = new Dictionary<string, string>();
            multipartData.Clear();
            multipartData.Add("nonce", _finalizelogin.transfer_info.FirstOrDefault(x => x.url == "https://store.steampowered.com/login/settoken").@params.nonce);
            multipartData.Add("auth", _finalizelogin.transfer_info.FirstOrDefault(x => x.url == "https://store.steampowered.com/login/settoken").@params.auth);
            multipartData.Add("steamID", loginResponse.response.steamid);

            response = SteamWeb.Request("https://store.steampowered.com/login/settoken", "POST", proxy, proxy_type, multipartData, cookies);
            if (response == null) return LoginResult.GeneralFailure;


            var readableCookies = cookies.GetCookies(new Uri("https://steamcommunity.com"));

            if (readableCookies["steamLoginSecure"] == null || readableCookies["steamLoginSecure"].Value == null)
                return LoginResult.GeneralFailure;


            this.refresh_token = _PollAuthSessionStatus.response.refresh_token;


            //var transfer_parameters = loginResponse.transfer_parameters;

            SessionData session = new SessionData(proxy, proxy_type);
            session.OAuthToken = _PollAuthSessionStatus.response.access_token;
            session.SteamID = ulong.Parse(loginResponse.response.steamid);

            //session.SteamLogin = session.SteamID + "%7C%7C" + transfer_parameters.SteamLogin;
            //session.steamRememberLogin = readableCookies["steamRememberLogin"].Value;
            //session.WebCookie = transfer_parameters.webcookie;

            session.SteamLoginSecure = readableCookies["steamLoginSecure"].Value;
            session.SessionID = readableCookies["sessionid"].Value;
            this.Session = session;
            this.LoggedIn = true;
            return LoginResult.LoginOkay;
        }


        public LoginResult DoLogin()
        {
            var postData = new NameValueCollection();
            var cookies = _cookies;
            string response = null;

            if (cookies.Count == 0)
            {
                //Generate a SessionID
                cookies.Add(new Cookie("mobileClientVersion", "0 (2.1.3)", "/", ".steamcommunity.com"));
                cookies.Add(new Cookie("mobileClient", "android", "/", ".steamcommunity.com"));
                cookies.Add(new Cookie("Steam_Language", "english", "/", ".steamcommunity.com"));

                NameValueCollection headers = new NameValueCollection();
                headers.Add("X-Requested-With", "com.valvesoftware.android.steam.community");

                SteamWeb.MobileLoginRequest("https://steamcommunity.com/login?oauth_client_id=DE45CD61&oauth_scope=read_profile%20write_profile%20read_client%20write_client", "GET", proxy, proxy_type, null, cookies, headers);
            }

            postData.Add("donotcache", (TimeAligner.GetSteamTime() * 1000).ToString());
            postData.Add("username", this.Username);
            response = SteamWeb.MobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/getrsakey", "POST", proxy, proxy_type, postData, cookies);
            if (response == null || response.Contains("<BODY>\nAn error occurred while processing your request.")) return LoginResult.GeneralFailure;

            var rsaResponse = JsonConvert.DeserializeObject<RSAResponse>(response);

            if (!rsaResponse.Success)
            {
                return LoginResult.BadRSA;
            }

            Thread.Sleep(350); //Sleep for a bit to give Steam a chance to catch up??

            RNGCryptoServiceProvider secureRandom = new RNGCryptoServiceProvider();
            byte[] encryptedPasswordBytes;
            using (var rsaEncryptor = new RSACryptoServiceProvider())
            {
                var passwordBytes = Encoding.ASCII.GetBytes(this.Password);
                var rsaParameters = rsaEncryptor.ExportParameters(false);
                rsaParameters.Exponent = Util.HexStringToByteArray(rsaResponse.Exponent);
                rsaParameters.Modulus = Util.HexStringToByteArray(rsaResponse.Modulus);
                rsaEncryptor.ImportParameters(rsaParameters);
                encryptedPasswordBytes = rsaEncryptor.Encrypt(passwordBytes, false);
            }

            string encryptedPassword = Convert.ToBase64String(encryptedPasswordBytes);

            postData.Clear();
            postData.Add("donotcache", (TimeAligner.GetSteamTime() * 1000).ToString());

            postData.Add("password", encryptedPassword);
            postData.Add("username", this.Username);
            postData.Add("twofactorcode", this.TwoFactorCode ?? "");

            postData.Add("emailauth", this.RequiresEmail ? this.EmailCode : "");
            //postData.Add("loginfriendlyname", "");
            postData.Add("captchagid", this.RequiresCaptcha ? this.CaptchaGID : "-1");
            postData.Add("captcha_text", this.RequiresCaptcha ? this.CaptchaText : "");
            postData.Add("emailsteamid", (this.Requires2FA || this.RequiresEmail) ? this.SteamID.ToString() : "");

            postData.Add("rsatimestamp", rsaResponse.Timestamp);
            postData.Add("remember_login", "true");
            //postData.Add("oauth_client_id", "DE45CD61");
            //postData.Add("oauth_scope", "read_profile write_profile read_client write_client");

            response = SteamWeb.MobileLoginRequest(APIEndpoints.COMMUNITY_BASE + "/login/dologin", "POST", proxy, proxy_type, postData, cookies);
            if (response == null) return LoginResult.GeneralFailure;

            var loginResponse = JsonConvert.DeserializeObject<DoLoginResult>(response);

            if (loginResponse.message != null)
            {
                if (loginResponse.message.Contains("There have been too many login failures"))
                    return LoginResult.TooManyFailedLogins;

                if (loginResponse.message.Contains("Incorrect login"))
                    return LoginResult.BadCredentials;
            }

            if (loginResponse.captcha_needed)
            {
                this.RequiresCaptcha = true;
                //this.CaptchaGID = loginResponse.CaptchaGID;
                return LoginResult.NeedCaptcha;
            }

            if (loginResponse.emailauth_needed)
            {
                this.RequiresEmail = true;
                this.SteamID = loginResponse.emailsteamid;
                return LoginResult.NeedEmail;
            }

            if (loginResponse.requires_twofactor && !loginResponse.success)
            {
                this.Requires2FA = true;
                return LoginResult.Need2FA;
            }

            /*if (loginResponse.OAuthData == null || loginResponse.OAuthData.OAuthToken == null || loginResponse.OAuthData.OAuthToken.Length == 0)
            {
                return LoginResult.GeneralFailure;
            }*/

            if (!loginResponse.login_complete)
            {
                return LoginResult.BadCredentials;
            }
            else
            {
                var readableCookies = cookies.GetCookies(new Uri("https://steamcommunity.com"));
                var transfer_parameters = loginResponse.transfer_parameters;

                SessionData session = new SessionData(proxy, proxy_type);
                //session.OAuthToken = oAuthData.OAuthToken;
                session.SteamID = ulong.Parse(transfer_parameters.steamid);
                //session.SteamLogin = session.SteamID + "%7C%7C" + transfer_parameters.SteamLogin;

                session.steamRememberLogin = readableCookies["steamRememberLogin"].Value;

                session.SteamLoginSecure = session.SteamID + "%7C%7C" + transfer_parameters.token_secure;
                session.WebCookie = transfer_parameters.webcookie;
                session.SessionID = readableCookies["sessionid"].Value;
                this.Session = session;
                this.LoggedIn = true;
                return LoginResult.LoginOkay;
            }
        }

        public class DoLoginResult
        {
            public bool success { get; set; }
            public bool requires_twofactor { get; set; }
            public bool login_complete { get; set; }
            public bool emailauth_needed { get; set; }
            public ulong emailsteamid { get; set; }


            public string message { get; set; }
            public bool clear_password_field { get; set; }
            public bool captcha_needed { get; set; }
            //public int captcha_gid { get; set; }

            public TransferParameters transfer_parameters { get; set; }

            public class TransferParameters
            {
                public string steamid { get; set; }
                public string token_secure { get; set; }
                public string auth { get; set; }
                public bool remember_login { get; set; }
                public string webcookie { get; set; }
            }
        }



        /*private class LoginResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("login_complete")]
            public bool LoginComplete { get; set; }

            [JsonProperty("oauth")]
            public string OAuthDataString { get; set; }

            public OAuth OAuthData
            {
                get
                {
                    return OAuthDataString != null ? JsonConvert.DeserializeObject<OAuth>(OAuthDataString) : null;
                }
            }

            [JsonProperty("captcha_needed")]
            public bool CaptchaNeeded { get; set; }

            [JsonProperty("captcha_gid")]
            public string CaptchaGID { get; set; }

            [JsonProperty("emailsteamid")]
            public ulong EmailSteamID { get; set; }

            [JsonProperty("emailauth_needed")]
            public bool EmailAuthNeeded { get; set; }

            [JsonProperty("requires_twofactor")]
            public bool TwoFactorNeeded { get; set; }

            [JsonProperty("message")]
            public string Message { get; set; }

            internal class OAuth
            {
                [JsonProperty("steamid")]
                public ulong SteamID { get; set; }

                [JsonProperty("oauth_token")]
                public string OAuthToken { get; set; }
                
                [JsonProperty("wgtoken")]
                public string SteamLogin { get; set; }

                [JsonProperty("wgtoken_secure")]
                public string SteamLoginSecure { get; set; }

                [JsonProperty("webcookie")]
                public string Webcookie { get; set; }
            }
        }*/



        public class BeginAuthSessionViaCredentials
        {
            public class AllowedConfirmation
            {
                public int confirmation_type { get; set; }
            }

            public class Response
            {
                public string client_id { get; set; }
                public string request_id { get; set; }
                //public object interval { get; set; }
                public List<AllowedConfirmation> allowed_confirmations { get; set; }
                public string steamid { get; set; }
                public string weak_token { get; set; }
                public string extended_error_message { get; set; }
            }

            public Response response { get; set; }
        }

        public class PollAuthSessionStatus
        {
            public Response response { get; set; }

            public class Response
            {
                public string refresh_token { get; set; }
                public string access_token { get; set; }
                public bool had_remote_interaction { get; set; }
                public string account_name { get; set; }
            }
        }

        public class finalizelogin
        {
            public string steamID { get; set; }
            public string redir { get; set; }
            public List<TransferInfo> transfer_info { get; set; }
            public string primary_domain { get; set; }

            public class TransferInfo
            {
                public string url { get; set; }
                public Params @params { get; set; }
            }

            public class Params
            {
                public string nonce { get; set; }
                public string auth { get; set; }
            }
        }



        public class GetPasswordRSAPublicKey
        {
            public Response response { get; set; }

            public class Response
            {
                public string publickey_mod { get; set; }
                public string publickey_exp { get; set; }
                public string timestamp { get; set; }
            }
        }


        private class RSAResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("publickey_exp")]
            public string Exponent { get; set; }

            [JsonProperty("publickey_mod")]
            public string Modulus { get; set; }

            [JsonProperty("timestamp")]
            public string Timestamp { get; set; }

            [JsonProperty("steamid")]
            public ulong SteamID { get; set; }
        }
    }

    public enum LoginResult
    {
        LoginOkay,
        GeneralFailure,
        BadRSA,
        BadCredentials,
        NeedCaptcha,
        Need2FA,
        NeedEmail,
        TooManyFailedLogins,
    }
}
