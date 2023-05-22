using System.Net;
using System.Net.Mail;

namespace Identity.Infrastructure.Helpers
{
    public class EmailHelper
    {
        public async Task<bool> SendEmailTwoFactorCodeAsync(string userEmail, string code)
        {
            MailMessage mailMessage = new MailMessage();
            mailMessage.From = new MailAddress("admin@test.com");
            mailMessage.To.Add(new MailAddress(userEmail));

            mailMessage.Subject = "Two Factor Code";
            mailMessage.IsBodyHtml = true;
            mailMessage.Body = code;

            var client = new SmtpClient("sandbox.smtp.mailtrap.io", 2525)
            {
                Credentials = new NetworkCredential("b3763ec6ff4b9d", "0e581a05dbec85"),
                EnableSsl = true
            };
            client.Credentials = new System.Net.NetworkCredential("b3763ec6ff4b9d", "0e581a05dbec85");

            try
            {
                await client.SendAsync(mailMessage);
                return true;
            }
            catch (Exception ex)
            {
                // log exception
            }
            return false;
        }
    }
}
