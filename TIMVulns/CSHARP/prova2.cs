using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Web;
using System.Web.UI;
using System.Runtime.Serialization.Formatters.Binary;
using System.Runtime.Serialization;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using System.Threading;

namespace VulnerableApp
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // 1. Iniezione SQL avanzata (CVSS 3.1: 9.8 - Critico)
            if (Request.QueryString["id"] != null && Request.QueryString["table"] != null && Request.QueryString["condition"] != null)
            {
                string userId = Request.QueryString["id"];
                string tableName = Request.QueryString["table"];
                string condition = Request.QueryString["condition"];
                string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
                string queryString = $"SELECT * FROM {tableName} WHERE UserId = {userId} AND {condition}"; // Vulnerabile
                using (SqlConnection connection = new SqlConnection(connectionString))
                {
                    SqlCommand command = new SqlCommand(queryString, connection);
                    connection.Open();
                    SqlDataReader reader = command.ExecuteReader();
                    // ...
                }
            }

            // 2. Iniezione di comandi con manipolazione di argomenti (CVSS 3.1: 10.0 - Critico)
            if (Request.QueryString["cmd"] != null && Request.QueryString["args"] != null)
            {
                string command = Request.QueryString["cmd"];
                string args = Request.QueryString["args"];
                Process.Start(command, args); // Vulnerabile
            }

            // 3. Path Traversal con double encoding e accesso a symlink (CVSS 3.1: 9.0 - Critico)
            if (Request.QueryString["file"] != null)
            {
                string filePath = HttpUtility.UrlDecode(Request.QueryString["file"]); // Decodifica pericolosa
                filePath = filePath.Replace("..", ""); // Tentativo inefficace di sanificazione
                string content = File.ReadAllText(filePath); // Vulnerabile
                Response.Write(content);
            }

            // 4. Cross-Site Scripting (XSS) persistente con manipolazione di eventi (CVSS 3.1: 8.3 - Alto)
            if (Request.QueryString["event"] != null && Request.QueryString["payload"] != null)
            {
                string eventName = Request.QueryString["event"];
                string payload = Request.QueryString["payload"];
                string script = $"<img src='#' onerror='{eventName}=\"{payload}\"' />"; // Vulnerabile
                Response.Write(script);
            }

            // 5. Deserializzazione non sicura con Type Confusion e manipolazione di assembly (CVSS 3.1: 9.8 - Critico)
             if (Request.Form["serialized"] != null)
             {
                 try
                 {
                    string serialized = Request.Form["serialized"];
                    byte[] data = Convert.FromBase64String(serialized);
                    using (MemoryStream ms = new MemoryStream(data))
                    {
                        BinaryFormatter formatter = new BinaryFormatter();
                        formatter.Binder = new VulnerableBinder(); // Binder personalizzato pericoloso.
                        object obj = formatter.Deserialize(ms);
                        Response.Write(obj.ToString());
                    }
                 }
                 catch (Exception ex)
                 {
                     Response.Write("Errore: " + ex.Message);
                 }
             }

             // 6. Server-Side Request Forgery (SSRF) con manipolazione di protocolli e porte (CVSS 3.1: 9.3 - Critico)
             if (Request.QueryString["url"] != null && Request.QueryString["port"] != null && Request.QueryString["protocol"] != null)
             {
                 string url = Request.QueryString["url"];
                 int port = int.Parse(Request.QueryString["port"]);
                 string protocol = Request.QueryString["protocol"];
                 Uri uri = new Uri($"{protocol}://{url}:{port}"); // Vulnerabile
                 WebClient client = new WebClient();
                 string content = client.DownloadString(uri);
                 Response.Write(content);
             }

            // 7. Iniezione di configurazione con manipolazione di JSON (CVSS 3.1: 9.0 - Critico)
            if (Request.QueryString["config"] != null && Request.QueryString["value"] != null)
            {
                string configKey = Request.QueryString["config"];
                string configValue = Request.QueryString["value"];
                string jsonConfig = File.ReadAllText("appsettings.json");
                Dictionary<string, string> config = new JavaScriptSerializer().Deserialize<Dictionary<string, string>>(jsonConfig);
                config[configKey] = configValue;
                File.WriteAllText("appsettings.json", new JavaScriptSerializer().Serialize(config)); // Vulnerabile
            }

             //8. Open Redirect con manipolazione di query string (CVSS 3.1: 8.0 - Alto)
             if (Request.QueryString["redirect"] != null && Request.QueryString["query"] != null)
             {
                string redirectUrl = Request.QueryString["redirect"] + "?" + Request.QueryString["query"]; //query string controllata.
                Response.Redirect(redirectUrl);
             }

            //9. manipolazione di symlink per TOCTOU (CVSS 3.1: 8.8 - Alto)
            if (Request.QueryString["filename"] != null)
            {
                string filename = Request.QueryString["filename"];
                string tempFile = Path.GetTempFileName();
                File.WriteAllText(tempFile, "Initial content");
                File.Delete(filename);
                File.Move(tempFile, filename);
                Thread.Sleep(1000); //ipotetica TOCTOU.
                string content = File.ReadAllText(filename); //Vulnerabile.
                Response.Write(content);
            }

             //10. manipolazione di dati crittografati con algoritmi deboli (CVSS 3.1: 7.5 - Alto)
             if (Request.Form["encryptedData"] != null) {
                try {
                    string encryptedData = Request.Form["encryptedData"];
                    byte[] data = Convert.FromBase64String(encryptedData);
                    using (Aes aesAlg = Aes.Create()) {
                       aesAlg.Key = Encoding.UTF8.GetBytes("WeakKey12345678"); //Chiave debole.
                       aesAlg.IV = new byte[16]; // IV nullo.
                       ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);
                       using (MemoryStream msDecrypt = new MemoryStream(data)) {
                         using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read)) {
                           using (StreamReader srDecrypt = new StreamReader(csDecrypt)) {
                             Response.Write(srDecrypt.ReadToEnd()); //Vulnerabile
                           }
                         }
                       }
                    }

                } catch (Exception ex) {
                   Response.Write($"Errore decriptazione {ex.Message}");
                }
             }

        }

        public class VulnerableBinder : SerializationBinder
        {
            public override Type BindToType(string assemblyName, string typeName)
            {
                Assembly asm = Assembly.Load(assemblyName);
                Type type = asm.GetType(typeName);
                return type; // Permette caricamento di tipi arbitrari
            }
        }
    }
}
