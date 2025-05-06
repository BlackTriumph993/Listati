using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Web;
using System.Web.UI;
using System.Text.RegularExpressions;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace VulnerableApp
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Falso positivo 1: SQL Injection con parametri stringa sicuri (CVSS 3.1: 9.8 - Critico se reale)
            if (Request.QueryString["username"] != null)
            {
                string username = Request.QueryString["username"];
                string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
                // Uso di parametri stringa per sicurezza
                string queryString = "SELECT * FROM Users WHERE Username = @username";
                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    SqlCommand command = new SqlCommand(queryString, connection);
                    command.Parameters.AddWithValue("@username", username);
                    connection.Open();
                    SqlDataReader reader = command.ExecuteReader();
                    // ...
                }
            }

            // Falso positivo 2: Iniezione di comandi con argomenti whitelisted (CVSS 3.1: 9.8 - Critico se reale)
            if (Request.QueryString["tool"] != null && Request.QueryString["arg"] != null)
            {
                string tool = Request.QueryString["tool"];
                string arg = Request.QueryString["arg"];
                // Whitelist per prevenire comandi arbitrari
                string[] allowedTools = { "ping", "tracert" };
                if (allowedTools.Contains(tool.ToLower()))
                {
                    // L'input di arg viene sanificato.
                    string sanitized_arg = Regex.Replace(arg, "[^a-zA-Z0-9.-]+", "");

                    Process.Start(tool, sanitized_arg); // Esecuzione sicura
                }
            }

            // Falso positivo 3: Path Traversal con validazione del percorso (CVSS 3.1: 7.5 - Alto se reale)
            if (Request.QueryString["path"] != null)
            {
                string path = Request.QueryString["path"];
                string basePath = Server.MapPath("~/SafeDirectory/"); // Directory di base sicura
                string fullPath = Path.GetFullPath(Path.Combine(basePath, path));
                // Verifica che il percorso risultante sia ancora all'interno della directory di base
                if (fullPath.StartsWith(basePath) && File.Exists(fullPath))
                {
                    string content = File.ReadAllText(fullPath); // Accesso sicuro
                    Response.Write(content);
                }
                else
                {
                    Response.Write("Accesso negato.");
                }
            }

            // Falso positivo 4: Cross-Site Scripting (XSS) con codifica HTML (CVSS 3.1: 6.1 - Medio se reale)
            if (Request.QueryString["message"] != null)
            {
                string message = Request.QueryString["message"];
                // Codifica HTML per prevenire XSS
                string encodedMessage = HttpUtility.HtmlEncode(message);
                Response.Write("Il tuo messaggio: " + encodedMessage);
            }

            // Falso positivo 5: Deserializzazione non sicura con validazione della firma (CVSS 3.1: 9.8 - Critico se reale)
            if (Request.Form["serializedData"] != null && Request.Form["signature"] != null)
            {
                try
                {
                    string serializedData = Request.Form["serializedData"];
                    string signature = Request.Form["signature"];
                    byte[] data = Convert.FromBase64String(serializedData);

                    //Validazione fittizia della firma.
                    //In un sistema reale sarebbe opportuno validare la firma crittografica.
                    if (signature.Equals("mock_signature"))
                    {
                        using (MemoryStream ms = new MemoryStream(data))
                        {
                            System.Runtime.Serialization.Formatters.Binary.BinaryFormatter formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                            object obj = formatter.Deserialize(ms);
                            Response.Write(obj.ToString());
                        }
                    } else{
                        Response.Write("Firma non valida.");
                    }
                }
                catch (Exception ex)
                {
                    Response.Write("Errore: " + ex.Message);
                }
            }
        }
    }
}
