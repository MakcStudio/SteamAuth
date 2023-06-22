namespace SteamAuth
{
    public static class APIEndpoints
    {
        public const string STEAMAPI_BASE = "https://api.steampowered.com";
        public const string COMMUNITY_BASE = "https://steamcommunity.com";
        public const string LOGIN_STEAMPOWERED_BASE = "https://login.steampowered.com";


        public const string MOBILEAUTH_BASE = STEAMAPI_BASE + "/IMobileAuthService/%s/v0001";
        public static string MOBILEAUTH_GETWGTOKEN = MOBILEAUTH_BASE.Replace("%s", "GetWGToken");
        public const string TWO_FACTOR_BASE = STEAMAPI_BASE + "/ITwoFactorService/%s/v0001";
        public static string TWO_FACTOR_TIME_QUERY = TWO_FACTOR_BASE.Replace("%s", "QueryTime");

        public const string GetPasswordRSAPublicKey = STEAMAPI_BASE + "/IAuthenticationService/GetPasswordRSAPublicKey/v1/";
        public const string BeginAuthSessionViaCredentials = STEAMAPI_BASE + "/IAuthenticationService/BeginAuthSessionViaCredentials/v1/";
        public const string UpdateAuthSessionWithSteamGuardCode = STEAMAPI_BASE + "/IAuthenticationService/UpdateAuthSessionWithSteamGuardCode/v1/";
        public const string PollAuthSessionStatus = STEAMAPI_BASE + "/IAuthenticationService/PollAuthSessionStatus/v1/";

        public const string finalizelogin = LOGIN_STEAMPOWERED_BASE + "/jwt/finalizelogin";
        public const string settoken = COMMUNITY_BASE + "/login/settoken";
    }
}
