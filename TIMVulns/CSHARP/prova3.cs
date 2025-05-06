using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Web;
using System.Web.UI;

namespace VulnerableApp
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // 1. Iniezione SQL (CVSS 3.1: 9.8 - Critico)
            if (Request.QueryString["id"] != null)
            {
                string userId = Request.QueryString["id"];
                string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
                string queryString = "SELECT * FROM Users WHERE UserId = " + userId; // Vulnerabile
                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    SqlCommand command = new SqlCommand(queryString, connection);
                    connection.Open();
                    SqlDataReader reader = command.ExecuteReader();
                    // ...
                }
            }

            // 2. Iniezione di comandi (CVSS 3.1: 9.8 - Critico)
            if (Request.QueryString["cmd"] != null)
            {
                string command = Request.QueryString["cmd"];
                Process.Start("cmd.exe", "/c " + command); // Vulnerabile
            }

            // 3. Path Traversal (CVSS 3.1: 7.5 - Alto)
            if (Request.QueryString["file"] != null)
            {
                string filePath = Request.QueryString["file"];
                string content = File.ReadAllText(filePath); // Vulnerabile
                Response.Write(content);
            }

            // 4. Cross-Site Scripting (XSS) (CVSS 3.1: 6.1 - Medio)
            if (Request.QueryString["name"] != null)
            {
                string name = Request.QueryString["name"];
                Response.Write("Hello, " + name); // Vulnerabile
            }

             //5. Deserializzazione non sicura (CVSS 3.1: 9.8 - Critico)
            if (Request.Form["serialized"] != null)
            {
                try {
                string serialized = Request.Form["serialized"];
                byte[] data = Convert.FromBase64String(serialized);
                using (MemoryStream ms = new MemoryStream(data))
                {
                    System.Runtime.Serialization.Formatters.Binary.BinaryFormatter formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                    object obj = formatter.Deserialize(ms); //Vulnerabile
                    Response.Write(obj.ToString());
                }
                } catch (Exception ex) {
                    Response.Write("Errore di deserializzazione: " + ex.Message);
                }
            }

             //6. Server-Side Request Forgery (SSRF) (CVSS 3.1: 9.0 - Critico)
             if (Request.QueryString["url"] != null)
             {
                 string url = Request.QueryString["url"];
                 WebClient client = new WebClient();
                 string content = client.DownloadString(url); // Vulnerabile
                 Response.Write(content);
             }

            // 7. Iniezione di configurazione (CVSS 3.1: 8.8 - Alto)
            if (Request.QueryString["config"] != null)
            {
               string configValue = Request.QueryString["config"];
               // manipolazione diretta di file di configurazione con input utente
               File.WriteAllText("appsettings.json", "{ \"settings\": \"" + configValue + "\"}");

            }

            // 8. Open Redirect (CVSS 3.1: 4.7 - Medio)
            if (Request.QueryString["redirect"] != null)
            {
                string redirectUrl = Request.QueryString["redirect"];
                Response.Redirect(redirectUrl); // Vulnerabile
            }
        }
    }
}
