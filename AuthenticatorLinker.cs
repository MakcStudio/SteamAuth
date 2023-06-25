using Newtonsoft.Json;
using System;
using System.Collections.Specialized;
using System.Net;
using System.Security.Cryptography;
using System.Threading;

namespace SteamAuth
{
    /// <summary>
    /// Handles the linking process for a new mobile authenticator.
    /// </summary>
    public class AuthenticatorLinker
    {
        /// <summary>
        /// Set to register a new phone number when linking. If a phone number is not set on the account, this must be set. If a phone number is set on the account, this must be null.
        /// </summary>
        public string PhoneNumber = null;

        /// <summary>
        /// Randomly-generated device ID. Should only be generated once per linker.
        /// </summary>
        public string DeviceID { get; private set; }

        /// <summary>
        /// After the initial link step, if successful, this will be the SteamGuard data for the account. PLEASE save this somewhere after generating it; it's vital data.
        /// </summary>
        public SteamGuardAccount LinkedAccount { get; private set; }

        /// <summary>
        /// True if the authenticator has been fully finalized.
        /// </summary>
        public bool Finalized = false;

        private SessionData _session;
        private CookieContainer _cookies;
        private bool confirmationEmailSent = false;

        public AuthenticatorLinker(UserLogin userLogin)
        {
            this._session = userLogin.Session;
            this.DeviceID = GenerateDeviceID();

            this._cookies = userLogin._cookies;
            //session.AddCookies(_cookies);
        }

        public LinkResult AddAuthenticator()
        {
            bool hasPhone = _hasPhoneAttached();
            /*if (hasPhone && PhoneNumber != null)
                return LinkResult.MustRemovePhoneNumber;*/
            if (!hasPhone && PhoneNumber == null)
                return LinkResult.MustProvidePhoneNumber;

            /*if (!hasPhone) {
                if (confirmationEmailSent) {
                    if (!_checkEmailConfirmation()) {
                    return LinkResult.GeneralFailure;
                }
                } else if (!_get_phone_number()) {
                    return LinkResult.GeneralFailure;
                } else {
                    confirmationEmailSent = true;
                    return LinkResult.MustConfirmEmail;
                }
            }*/

            var postData = new NameValueCollection();
            postData.Add("access_token", _session.OAuthToken);
            postData.Add("steamid", _session.SteamID.ToString());
            postData.Add("authenticator_type", "1");
            postData.Add("device_identifier", this.DeviceID);
            postData.Add("sms_phone_id", "1");

            string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001", "POST", _session.proxy, _session.proxy_type, postData);
            if (response == null) return LinkResult.GeneralFailure;

            var addAuthenticatorResponse = JsonConvert.DeserializeObject<AddAuthenticatorResponse>(response);
            if (addAuthenticatorResponse == null || addAuthenticatorResponse.Response == null)
            {
                return LinkResult.GeneralFailure;
            }

            if (addAuthenticatorResponse.Response.Status == 29)
            {
                return LinkResult.AuthenticatorPresent;
            }

            if (addAuthenticatorResponse.Response.Status != 1)
            {
                return LinkResult.GeneralFailure;
            }

            this.LinkedAccount = addAuthenticatorResponse.Response;
            LinkedAccount.Session = this._session;
            LinkedAccount.DeviceID = this.DeviceID;

            return LinkResult.AwaitingFinalization;
        }

       /* public LinkResult AddAuthenticator()
        {
            bool hasPhone = _hasPhoneAttached();
            if (hasPhone && PhoneNumber != null)
                return LinkResult.MustRemovePhoneNumber;
            if (!hasPhone && PhoneNumber == null)
                return LinkResult.MustProvidePhoneNumber;

            if (!hasPhone) {
                if (confirmationEmailSent) {
                    if (!_checkEmailConfirmation()) {
                    return LinkResult.GeneralFailure;
                }
                } else if (!_get_phone_number()) {
                    return LinkResult.GeneralFailure;
                } else {
                    confirmationEmailSent = true;
                    return LinkResult.MustConfirmEmail;
                }
            }

            var postData = new NameValueCollection();
            postData.Add("access_token", _session.OAuthToken);
            postData.Add("steamid", _session.SteamID.ToString());
            postData.Add("authenticator_type", "1");
            postData.Add("device_identifier", this.DeviceID);
            postData.Add("sms_phone_id", "1");

            string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/AddAuthenticator/v0001", "POST", _session.proxy, _session.proxy_type, postData);
            if (response == null) return LinkResult.GeneralFailure;

            var addAuthenticatorResponse = JsonConvert.DeserializeObject<AddAuthenticatorResponse>(response);
            if (addAuthenticatorResponse == null || addAuthenticatorResponse.Response == null)
            {
                return LinkResult.GeneralFailure;
            }

            if (addAuthenticatorResponse.Response.Status == 29)
            {
                return LinkResult.AuthenticatorPresent;
            }

            if (addAuthenticatorResponse.Response.Status != 1)
            {
                return LinkResult.GeneralFailure;
            }

            this.LinkedAccount = addAuthenticatorResponse.Response;
            LinkedAccount.Session = this._session;
            LinkedAccount.DeviceID = this.DeviceID;

            return LinkResult.AwaitingFinalization;
        }
       */
        public FinalizeResult FinalizeAddAuthenticator(string smsCode)
        {
            //The act of checking the SMS code is necessary for Steam to finalize adding the phone number to the account.
            //Of course, we only want to check it if we're adding a phone number in the first place...

            /*if (!String.IsNullOrEmpty(this.PhoneNumber) && !this._checkSMSCode(smsCode))
            {
                return FinalizeResult.BadSMSCode;
            }*/

            var postData = new NameValueCollection();
            postData.Add("steamid", _session.SteamID.ToString());
            postData.Add("access_token", _session.OAuthToken);
            postData.Add("activation_code", smsCode);
            int tries = 0;
            while (tries <= 30)
            {
                postData.Set("authenticator_code", LinkedAccount.GenerateSteamGuardCode());
                postData.Set("authenticator_time", TimeAligner.GetSteamTime().ToString());

                string response = SteamWeb.MobileLoginRequest(APIEndpoints.STEAMAPI_BASE + "/ITwoFactorService/FinalizeAddAuthenticator/v0001", "POST", _session.proxy, _session.proxy_type, postData);
                if (response == null) return FinalizeResult.GeneralFailure;

                var finalizeResponse = JsonConvert.DeserializeObject<FinalizeAuthenticatorResponse>(response);

                if (finalizeResponse == null || finalizeResponse.Response == null)
                {
                    return FinalizeResult.GeneralFailure;
                }

                if (finalizeResponse.Response.Status == 89)
                {
                    return FinalizeResult.BadSMSCode;
                }

                if (finalizeResponse.Response.Status == 88)
                {
                    if (tries >= 30)
                    {
                        return FinalizeResult.UnableToGenerateCorrectCodes;
                    }
                }

                if (!finalizeResponse.Response.Success)
                {
                    return FinalizeResult.GeneralFailure;
                }

                if (finalizeResponse.Response.WantMore)
                {
                    tries++;
                    continue;
                }

                this.LinkedAccount.FullyEnrolled = true;
                return FinalizeResult.Success;
            }

            return FinalizeResult.GeneralFailure;
        }

        public bool _get_sms_code(string smscode)
        {
            var postData = new NameValueCollection();
            postData.Add("op", "get_sms_code");
            postData.Add("input", smscode);
            postData.Add("sessionID", _cookies.GetCookies(new Uri("https://store.steampowered.com"))["sessionid"].Value);

            postData.Add("confirmed", "1");
            postData.Add("checkfortos", "1");
            postData.Add("bisediting", "0");
            postData.Add("token", "0");


            string response = SteamWeb.Request("https://store.steampowered.com/phone/add_ajaxop", "POST", _session.proxy, _session.proxy_type, postData, _cookies);
            if (response == null) return false;

            var _get_phone_number = JsonConvert.DeserializeObject<get_phone_number>(response);
            return _get_phone_number.success;
        }

        public bool _get_phone_number()
        {
            var postData = new NameValueCollection();
            postData.Add("op", "get_phone_number");
            postData.Add("input", PhoneNumber);
            postData.Add("sessionID", _cookies.GetCookies(new Uri("https://store.steampowered.com"))["sessionid"].Value);

            postData.Add("confirmed", "1");
            postData.Add("checkfortos", "1");
            postData.Add("bisediting", "0");
            postData.Add("token", "0");
            

            string response = SteamWeb.Request("https://store.steampowered.com/phone/add_ajaxop", "POST", _session.proxy, _session.proxy_type, postData, _cookies);
            if (response == null) return false;

            var _get_phone_number = JsonConvert.DeserializeObject<get_phone_number>(response);
            return _get_phone_number.success;
        }

        public bool _email_verification()
        {
            var postData = new NameValueCollection();
            postData.Add("op", "email_verification");
            postData.Add("input", "");
            postData.Add("sessionID", _cookies.GetCookies(new Uri("https://store.steampowered.com"))["sessionid"].Value);

            postData.Add("confirmed", "1");
            postData.Add("checkfortos", "1");
            postData.Add("bisediting", "0");
            postData.Add("token", "0");
            

            string response = SteamWeb.Request("https://store.steampowered.com/phone/add_ajaxop", "POST", _session.proxy, _session.proxy_type, postData, _cookies);
            if (response == null) return false;

            var _get_phone_number = JsonConvert.DeserializeObject<get_phone_number>(response);
            return _get_phone_number.success;
        }

        


        public bool _hasPhoneAttached()
        {
            var postData = new NameValueCollection();
            postData.Add("op", "get_phone_number");
            postData.Add("sessionID", _cookies.GetCookies(new Uri("https://store.steampowered.com"))["sessionid"].Value);

            string response = SteamWeb.Request("https://store.steampowered.com/phone/add_ajaxop", "POST", _session.proxy, _session.proxy_type, postData, _cookies);
            if (response == null) return false;

            var _get_phone_number = JsonConvert.DeserializeObject<get_phone_number>(response);

            if (_get_phone_number.errorText.Contains("Phone number is invalid"))
                return false;
            else
                return true;
        }

        public enum LinkResult
        {
            MustProvidePhoneNumber, //No phone number on the account
            MustRemovePhoneNumber, //A phone number is already on the account
            MustConfirmEmail, //User need to click link from confirmation email
            AwaitingFinalization, //Must provide an SMS code
            GeneralFailure, //General failure (really now!)
            AuthenticatorPresent
        }

        public enum FinalizeResult
        {
            BadSMSCode,
            UnableToGenerateCorrectCodes,
            Success,
            GeneralFailure
        }

        private class AddAuthenticatorResponse
        {
            [JsonProperty("response")]
            public SteamGuardAccount Response { get; set; }
        }

        private class FinalizeAuthenticatorResponse
        {
            [JsonProperty("response")]
            public FinalizeAuthenticatorInternalResponse Response { get; set; }

            internal class FinalizeAuthenticatorInternalResponse
            {
                [JsonProperty("status")]
                public int Status { get; set; }

                [JsonProperty("server_time")]
                public long ServerTime { get; set; }

                [JsonProperty("want_more")]
                public bool WantMore { get; set; }

                [JsonProperty("success")]
                public bool Success { get; set; }
            }
        }

        private class HasPhoneResponse
        {
            [JsonProperty("has_phone")]
            public bool HasPhone { get; set; }
        }

        private class AddPhoneResponse
        {
            [JsonProperty("success")]
            public bool Success { get; set; }
        }

        public class get_phone_number
        {
            public bool success { get; set; }
            public bool showResend { get; set; }
            public string state { get; set; }
            public string errorText { get; set; }
            public string token { get; set; }
            public string phoneNumber { get; set; }
        }

        public static string GenerateDeviceID()
        {
          return "android:" + Guid.NewGuid().ToString();
        }
    }
}
