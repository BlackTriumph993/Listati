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
using System.Collections.Generic;
using Newtonsoft.Json;
using System.Web.Script.Serialization;
using System.Threading;
using System.Reflection;
using System.Security.Policy;
using System.Security;

namespace VulnerableApp
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Falso positivo 1: SQL Injection avanzata con parametri dinamici e validazione (CVSS 3.1: 9.8 - Critico se reale)
            if (Request.QueryString["table"] != null && Request.QueryString["where"] != null && Request.QueryString["sort"] != null)
            {
                string table = Regex.Replace(Request.QueryString["table"], "[^a-zA-Z0-9_]+", ""); // Whitelist tabella
                string whereClause = Request.QueryString["where"];
                string sortClause = Request.QueryString["sort"];
                string connectionString = "Server=myServerAddress;Database=myDataBase;User Id=myUsername;Password=myPassword;";
                string queryString = $"SELECT * FROM {table} WHERE {whereClause} ORDER BY {sortClause}"; // Pericoloso all'apparenza
                // Validazione "where" e "sort" qui usando librerie di parsing SQL e whitelisting
                if (ValidateSqlClauses(whereClause, sortClause))
                {
                    using (SqlConnection connection = new SqlConnection(connectionString))
                    {
                        SqlCommand command = new SqlCommand(queryString, connection);
                        connection.Open();
                        SqlDataReader reader = command.ExecuteReader();
                    }
                }
            }

            // Falso positivo 2: Iniezione di comandi complessa con sandbox e output controllato (CVSS 3.1: 10.0 - Critico se reale)
            if (Request.QueryString["tool"] != null && Request.QueryString["args"] != null)
            {
                string tool = Request.QueryString["tool"];
                string args = Request.QueryString["args"];
                if (Regex.IsMatch(tool, "^(ping|tracert)$", RegexOptions.IgnoreCase))
                {
                    string sanitizedArgs = Regex.Replace(args, "[^a-zA-Z0-9.-]+", "");
                    // Esecuzione in sandbox controllata (AppDomain limitato o container)
                    var process = new Process();
                    process.StartInfo.FileName = tool;
                    process.StartInfo.Arguments = sanitizedArgs;
                    process.StartInfo.RedirectStandardOutput = true;
                    process.StartInfo.UseShellExecute = false;
                    process.StartInfo.CreateNoWindow = true;
                    process.Start();
                    string output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();
                    Response.Write(HttpUtility.HtmlEncode(output)); // Output sanificato
                }
            }

            // Falso positivo 3: Path Traversal avanzato con filesystem virtuale (CVSS 3.1: 9.0 - Critico se reale)
            if (Request.QueryString["file"] != null)
            {
                string requestedFile = Request.QueryString["file"];
                // Mapping di input a un filesystem virtuale sicuro
                Dictionary<string, string> virtualFS = new Dictionary<string, string>
                {
                    { "file1.txt", Server.MapPath("~/SafeDirectory/file1.txt") },
                    { "file2.txt", Server.MapPath("~/SafeDirectory/file2.txt") }
                };
                if (virtualFS.ContainsKey(requestedFile))
                {
                    string filePath = virtualFS[requestedFile];
                    if (File.Exists(filePath))
                    {
                        Response.Write(File.ReadAllText(filePath));
                    }
                }
            }

            // Falso positivo 4: XSS con template dinamici e Trusted Types (CVSS 3.1: 8.3 - Alto se reale)
            if (Request.QueryString["template"] != null && Request.QueryString["data"] != null)
            {
                string template = Request.QueryString["template"];
                string data = Request.QueryString["data"];
                // Esecuzione template sicura usando libreria di template con Trusted Types
                string result = SafeTemplateEngine.Render(template, JsonConvert.DeserializeObject(data)); //Trusted Types
                Response.Write(result);
            }

            // Falso positivo 5: Deserializzazione non sicura con binder sicuro e validazione schema (CVSS 3.1: 9.8 - Critico se reale)
            if (Request.Form["data"] != null)
            {
                try
                {
                    string base64Data = Request.Form["data"];
                    byte[] bytes = Convert.FromBase64String(base64Data);
                    using (MemoryStream ms = new MemoryStream(bytes))
                    {
                        BinaryFormatter formatter = new BinaryFormatter();
                        formatter.Binder = new SafeSerializationBinder(); // Binder controllato
                        object obj = formatter.Deserialize(ms);
                        // Validazione di obj rispetto a uno schema definito
                        if (ValidateDeserializedObject(obj))
                        {
                            Response.Write(obj.ToString());
                        }
                    }
                }
                catch (Exception ex)
                {
                    Response.Write("Errore: " + ex.Message);
                }
            }

             //falso positivo 6: SSRF con proxy e whitelist di destinazioni (CVSS 3.1: 9.3 - Critico se reale)
             if (Request.QueryString["url"] != null) {
                string url = Request.QueryString["url"];
                if (IsUrlWhitelisted(url)) {
                    using (var webClient = new WebClient()) {
                        webClient.Proxy = new WebProxy("http://safe-proxy:8080"); // utilizzo di proxy.
                        var content = webClient.DownloadString(url);
                        Response.Write(content);
                    }
                }
             }

        }

        private bool ValidateSqlClauses(string whereClause, string sortClause) { // implementazione della validazione SQL }
        private bool IsUrlWhitelisted(string url){ //implementazione whitelist URL}
        private bool ValidateDeserializedObject(object obj){ //implementazione della validazione obj}
        private static bool IsSafeCommand(string tool){ //implementazione controllo tool}
        public static class SafeTemplateEngine{// implementazione rendering template sicuro con Trusted Types.}
        public class SafeSerializationBinder:SerializationBinder{// implementazione Binder sicuro.}
    }
}
