using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SteamAuth
{
    public class SteamGuardAccount
    {
        [JsonProperty("error_sch")]
        public int error_sch { get; set; } = 0;

        [JsonProperty("shared_secret")]
        public string SharedSecret { get; set; }

        [JsonProperty("serial_number")]
        public string SerialNumber { get; set; }

        [JsonProperty("revocation_code")]
        public string RevocationCode { get; set; }

        [JsonProperty("uri")]
        public string URI { get; set; }

        [JsonProperty("server_time")]
        public long ServerTime { get; set; }

        [JsonProperty("account_name")]
        public string AccountName { get; set; }

        [JsonProperty("token_gid")]
        public string TokenGID { get; set; }

        [JsonProperty("identity_secret")]
        public string IdentitySecret { get; set; }

        [JsonProperty("secret_1")]
        public string Secret1 { get; set; }

        [JsonProperty("status")]
        public int Status { get; set; }

        [JsonProperty("device_id")]
        public string DeviceID { get; set; }

        /// <summary>
        /// Set to true if the authenticator has actually been applied to the account.
        /// </summary>
        [JsonProperty("fully_enrolled")]
        public bool FullyEnrolled { get; set; }

        public SessionData Session { get; set; }

        private static byte[] steamGuardCodeTranslations = new byte[] { 50, 51, 52, 53, 54, 55, 56, 57, 66, 67, 68, 70, 71, 72, 74, 75, 77, 78, 80, 81, 82, 84, 86, 87, 88, 89 };

        public bool DeactivateAuthenticator(int scheme = 2)
        {
            var postData = new NameValueCollection();
            postData.Add("steamid", this.Session.SteamID.ToString());
            postData.Add("steamguard_scheme", scheme.ToString());
            postData.Add("revocation_code", this.RevocationCode);
            postData.Add("access_token", this.Session.OAuthToken);

            try
            {
                string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/RemoveAuthenticator/v0001", "POST", Session.proxy, Session.proxy_type, postData);
                var removeResponse = JsonConvert.DeserializeObject<RemoveAuthenticatorResponse>(response);

                if (removeResponse == null || removeResponse.Response == null || !removeResponse.Response.Success) return false;
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        public string GenerateSteamGuardCode()
        {
            return GenerateSteamGuardCodeForTime(TimeAligner.GetSteamTime());
        }

        public string GenerateSteamGuardCodeForTime(long time)
        {
            if (this.SharedSecret == null || this.SharedSecret.Length == 0)
            {
                return "";
            }

            string sharedSecretUnescaped = Regex.Unescape(this.SharedSecret);
            byte[] sharedSecretArray = Convert.FromBase64String(sharedSecretUnescaped);
            byte[] timeArray = new byte[8];

            time /= 30L;

            for (int i = 8; i > 0; i--)
            {
                timeArray[i - 1] = (byte)time;
                time >>= 8;
            }

            HMACSHA1 hmacGenerator = new HMACSHA1();
            hmacGenerator.Key = sharedSecretArray;
            byte[] hashedData = hmacGenerator.ComputeHash(timeArray);
            byte[] codeArray = new byte[5];
            try
            {
                byte b = (byte)(hashedData[19] & 0xF);
                int codePoint = (hashedData[b] & 0x7F) << 24 | (hashedData[b + 1] & 0xFF) << 16 | (hashedData[b + 2] & 0xFF) << 8 | (hashedData[b + 3] & 0xFF);

                for (int i = 0; i < 5; ++i)
                {
                    codeArray[i] = steamGuardCodeTranslations[codePoint % steamGuardCodeTranslations.Length];
                    codePoint /= steamGuardCodeTranslations.Length;
                }
            }
            catch (Exception)
            {
                return null; //Change later, catch-alls are bad!
            }
            return Encoding.UTF8.GetString(codeArray);
        }

        public Confirmation[] FetchConfirmations()
        {
            string url = this.GenerateConfirmationURL();

            CookieContainer cookies = new CookieContainer();
            this.Session.AddCookies(cookies);

            string response = SteamWeb.Request(url, "GET", Session.proxy, Session.proxy_type, "", cookies);
            return FetchConfirmationInternal(response);
        }



        private Confirmation[] FetchConfirmationInternal(string response)
        {

            /*So you're going to see this abomination and you're going to be upset.
              It's understandable. But the thing is, regex for HTML -- while awful -- makes this way faster than parsing a DOM, plus we don't need another library.
              And because the data is always in the same place and same format... It's not as if we're trying to naturally understand HTML here. Just extract strings.
              I'm sorry. */
            if (string.IsNullOrEmpty(response))
                return null;

            //try
            //{
                var _conf_json = JsonConvert.DeserializeObject<GetListJson>(response);

                if (_conf_json == null || _conf_json.success == false || _conf_json.needauth)
                {
                    throw new WGTokenInvalidException();
                }

                if (_conf_json.success && _conf_json.conf == null)
                {
                    //странная фигня, ну ок
                    return new Confirmation[0];
                }

                List<Confirmation> ret = new List<Confirmation>();

                if (_conf_json.conf != null)
                    foreach (var confirmation in _conf_json.conf)
                    {
                        ret.Add(new Confirmation(ulong.Parse(confirmation.id), ulong.Parse(confirmation.nonce), confirmation.type, ulong.Parse(confirmation.creator_id))
                        { headline = confirmation.headline, icon = confirmation.icon, summary = confirmation.summary, type_name = confirmation.type_name, creation_time = confirmation.creation_time });
                    }

                return ret.ToArray();
            //}
            //catch (Exception ex) { return null; }
        }

        /// <summary>
        /// Deprecated. Simply returns conf.Creator.
        /// </summary>
        /// <param name="conf"></param>
        /// <returns>The Creator field of conf</returns>
        public long GetConfirmationTradeOfferID(Confirmation conf)
        {
            if (conf.ConfType != Confirmation.ConfirmationType.Trade)
                throw new ArgumentException("conf must be a trade confirmation.");

            return (long)conf.Creator;
        }

        public bool AcceptMultipleConfirmations(Confirmation[] confs)
        {
            return _sendMultiConfirmationAjax(confs, "allow");
        }

        public bool DenyMultipleConfirmations(Confirmation[] confs)
        {
            return _sendMultiConfirmationAjax(confs, "cancel");
        }

        public bool AcceptConfirmation(Confirmation conf)
        {
            return _sendConfirmationAjax(conf, "allow");
        }

        public bool DenyConfirmation(Confirmation conf)
        {
            return _sendConfirmationAjax(conf, "cancel");
        }


        //public int error_sch { get; set; } = 0;
        /// <summary>
        /// Refreshes the Steam session. Necessary to perform confirmations if your session has expired or changed.
        /// </summary>
        /// <returns></returns>
        public bool RefreshSession()
        {
            //throw new Exception("Refresh exeption");

            string url = APIEndpoints.MOBILEAUTH_GETWGTOKEN;
            NameValueCollection postData = new NameValueCollection();
            postData.Add("access_token", this.Session.OAuthToken);

            string response = null;
            try
            {
                response = SteamWeb.Request(url, "POST", Session.proxy, Session.proxy_type, postData);
            }
            catch (WebException)
            {
                return false;
            }

            if (response == null) return false;

            try
            {
                var refreshResponse = JsonConvert.DeserializeObject<RefreshSessionDataResponse>(response);
                if (refreshResponse == null || refreshResponse.Response == null || String.IsNullOrEmpty(refreshResponse.Response.Token))
                    return false;

                string token = this.Session.SteamID + "%7C%7C" + refreshResponse.Response.Token;
                string tokenSecure = this.Session.SteamID + "%7C%7C" + refreshResponse.Response.TokenSecure;

                //this.Session.SteamLogin = token;
                this.Session.SteamLoginSecure = tokenSecure;
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        private ConfirmationDetailsResponse _getConfirmationDetails(Confirmation conf)
        {
            string url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/details/" + conf.ID + "?";
            string queryString = GenerateConfirmationQueryParams("details");
            url += queryString;

            CookieContainer cookies = new CookieContainer();
            this.Session.AddCookies(cookies);
            string referer = GenerateConfirmationURL();

            string response = SteamWeb.Request(url, "GET", Session.proxy, Session.proxy_type, "", cookies, null);
            if (String.IsNullOrEmpty(response)) return null;

            var confResponse = JsonConvert.DeserializeObject<ConfirmationDetailsResponse>(response);
            if (confResponse == null) return null;
            return confResponse;
        }

        private bool _sendConfirmationAjax(Confirmation conf, string op)
        {
            string url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/ajaxop";
            string queryString = "?op=" + op + "&";
            queryString += GenerateConfirmationQueryParams(op);
            queryString += "&cid=" + conf.ID + "&ck=" + conf.Key;
            url += queryString;

            CookieContainer cookies = new CookieContainer();
            this.Session.AddCookies(cookies);
            string referer = GenerateConfirmationURL();

            string response = SteamWeb.Request(url, "GET", Session.proxy, Session.proxy_type, "", cookies, null);
            if (response == null) return false;

            SendConfirmationResponse confResponse = JsonConvert.DeserializeObject<SendConfirmationResponse>(response);
            return confResponse.Success;
        }

        private bool _sendMultiConfirmationAjax(Confirmation[] confs, string op)
        {
            string url = APIEndpoints.COMMUNITY_BASE + "/mobileconf/multiajaxop";

            string query = "op=" + op + "&" + GenerateConfirmationQueryParams(op);
            foreach (var conf in confs)
            {
                query += "&cid[]=" + conf.ID + "&ck[]=" + conf.Key;
            }

            CookieContainer cookies = new CookieContainer();
            this.Session.AddCookies(cookies);
            string referer = GenerateConfirmationURL();

            string response = SteamWeb.Request(url, "POST", Session.proxy, Session.proxy_type, query, cookies, null);
            if (response == null) return false;

            SendConfirmationResponse confResponse = JsonConvert.DeserializeObject<SendConfirmationResponse>(response);
            return confResponse.Success;
        }

        public string GenerateConfirmationURL(string tag = "conf")
        {
            string endpoint = APIEndpoints.COMMUNITY_BASE + "/mobileconf/getlist?";
            string queryString = GenerateConfirmationQueryParams(tag);
            return endpoint + queryString;
        }

        public string GenerateConfirmationQueryParams(string tag)
        {
            if (String.IsNullOrEmpty(DeviceID))
                throw new ArgumentException("Device ID is not present");

            var queryParams = GenerateConfirmationQueryParamsAsNVC(tag);

            return "p=" + queryParams["p"] + "&a=" + queryParams["a"] + "&k=" + queryParams["k"] + "&t=" + queryParams["t"] + "&m=android&tag=" + queryParams["tag"];
        }

        public NameValueCollection GenerateConfirmationQueryParamsAsNVC(string tag)
        {
            if (String.IsNullOrEmpty(DeviceID))
                throw new ArgumentException("Device ID is not present");

            long time = TimeAligner.GetSteamTime();

            var ret = new NameValueCollection();
            ret.Add("p", this.DeviceID);
            ret.Add("a", this.Session.SteamID.ToString());
            ret.Add("k", _generateConfirmationHashForTime(time, tag));
            ret.Add("t", time.ToString());
            ret.Add("m", "android");
            ret.Add("tag", tag);

            return ret;
        }

        private string _generateConfirmationHashForTime(long time, string tag)
        {
            byte[] decode = Convert.FromBase64String(this.IdentitySecret);
            int n2 = 8;
            if (tag != null)
            {
                if (tag.Length > 32)
                {
                    n2 = 8 + 32;
                }
                else
                {
                    n2 = 8 + tag.Length;
                }
            }
            byte[] array = new byte[n2];
            int n3 = 8;
            while (true)
            {
                int n4 = n3 - 1;
                if (n3 <= 0)
                {
                    break;
                }
                array[n4] = (byte)time;
                time >>= 8;
                n3 = n4;
            }
            if (tag != null)
            {
                Array.Copy(Encoding.UTF8.GetBytes(tag), 0, array, 8, n2 - 8);
            }

            try
            {
                HMACSHA1 hmacGenerator = new HMACSHA1();
                hmacGenerator.Key = decode;
                byte[] hashedData = hmacGenerator.ComputeHash(array);
                string encodedData = Convert.ToBase64String(hashedData, Base64FormattingOptions.None);
                string hash = WebUtility.UrlEncode(encodedData);
                return hash;
            }
            catch
            {
                return null;
            }
        }

        public class WGTokenInvalidException : Exception
        {
        }

        public class WGTokenExpiredException : Exception
        {
        }

        private class RefreshSessionDataResponse
        {
            [JsonProperty("response")]
            public RefreshSessionDataInternalResponse Response { get; set; }
            internal class RefreshSessionDataInternalResponse
            {
                [JsonProperty("token")]
                public string Token { get; set; }

                [JsonProperty("token_secure")]
                public string TokenSecure { get; set; }
            }
        }

        private class RemoveAuthenticatorResponse
        {
            [JsonProperty("response")]
            public RemoveAuthenticatorInternalResponse Response { get; set; }

            internal class RemoveAuthenticatorInternalResponse
            {
                [JsonProperty("success")]
                public bool Success { get; set; }
            }
        }

        private class SendConfirmationResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }
        }

        private class ConfirmationDetailsResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }

            [JsonProperty("html")]
            public string HTML { get; set; }
        }
    }
}
