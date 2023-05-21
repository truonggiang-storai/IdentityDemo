namespace Identity.Settings
{
    public class JwtSettings
    {
        public string Subject { get; set; }

        public string Issuer { get; set; }

        public string Audience { get; set; }

        public string Key { get; set; }

        public string TokenValidityInSeconds { get; set; }

        public string RefreshTokenValidityInDays { get; set; }
    }
}
