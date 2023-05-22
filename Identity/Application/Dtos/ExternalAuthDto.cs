namespace Identity.Application.Dtos
{
    public class ExternalAuthDto
    {
        public string? Provider { get; set; }

        public string? IdToken { get; set; }
    }
}
