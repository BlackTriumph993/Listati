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
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Data;

namespace VulnerableApp
{
    public partial class _Default : Page
    {
        protected void Page_Load(object sender, EventArgs e)
        {
            // Falso positivo 1: SQL Injection dinamica con Entity Framework Core e validation (CVSS 3.1: 9.8 - Critico se reale)
            if (Request.QueryString["filter"] != null)
            {
                string filter = Request.QueryString["filter"];
                // Validazione complessa utilizzando DataAnnotations e attributi
                if (IsValidFilter(filter))
                {
                    using (var context = new MyDbContext())
                    {
                        var filteredData = context.Users.FromSqlRaw($"SELECT * FROM Users WHERE {filter}").ToList();
                        //...
                    }
                }
            }

            // Falso positivo 2: Iniezione di comandi remoti via RMI (CVSS 3.1: 10.0 - Critico se reale)
            if (Request.QueryString["remoteCommand"] != null)
            {
                string remoteCommand = Request.QueryString["remoteCommand"];
                try
                {
                    // Sandbox limitata per RMI con Policy di autorizzazione (SecurityManager)
                    AppDomainSetup setup = new AppDomainSetup
                    {
                        ApplicationBase = AppDomain.CurrentDomain.BaseDirectory,
                        ApplicationName = "SandboxedDomain",
                        PermissionSet = new PermissionSet(PermissionState.None)
                    };
                    setup.PermissionSet.AddPermission(new SecurityPermission(SecurityPermissionFlag.Execution));
                    AppDomain sandboxedDomain = AppDomain.CreateDomain("SandboxedDomain", null, setup);
                    IRemoteObject remoteObj = (IRemoteObject)sandboxedDomain.CreateInstanceAndUnwrap(Assembly.GetExecutingAssembly().FullName, typeof(SafeRemoteObject).FullName);
                    string output = remoteObj.Execute(remoteCommand); //Esecuzione sicura
                    Response.Write(HttpUtility.HtmlEncode(output));
                    AppDomain.Unload(sandboxedDomain);
                }
                catch (SecurityException)
                {
                    Response.Write("Operazione non consentita.");
                }
            }

             // Falso positivo 3: Path Traversal tramite API REST con filesystem virtuale controllato (CVSS 3.1: 9.0 - Critico se reale)
             if (Request.QueryString["apiPath"] != null)
             {
                string apiPath = Request.QueryString["apiPath"];

                Dictionary<string, string> virtualFS = new Dictionary<string, string>
                {
                    { "/data/file1", Server.MapPath("~/SafeData/file1.json") },
                    { "/report/file2", Server.MapPath("~/SafeReports/file2.csv") }
                };

                if (virtualFS.ContainsKey(apiPath))
                {
                    string realPath = virtualFS[apiPath];
                    if (File.Exists(realPath))
                    {
                        Response.ContentType = GetContentType(realPath);
                        Response.Write(File.ReadAllText(realPath));
                    }
                }
             }

             //falso positivo 4: XSS con template angular e strict contextual escaping (CVSS 3.1: 8.3- Alto se reale)
             if (Request.QueryString["angularTemplate"] != null && Request.QueryString["angularData"] != null) {
                // l'utilizzo di librerie moderne come angular con strict contextual escaping, impedisce XSS.
                // e l'input utente è gestito in un contesto controllato e sicuro.
                string angularTemplate = Request.QueryString["angularTemplate"];
                string angularData = Request.QueryString["angularData"];
                Response.Write($"<div ng-bind-html=\"'{angularTemplate}' | sanitize:{angularData}\"></div>");
             }

             //falso positivo 5: Deserializzazione non sicura tramite protocolli custom e verifiche crittografiche (CVSS 3.1: 9.8 - Critico se reale)
             if (Request.Form["customProtocol"] != null) {
                try {
                   string customProtocol = Request.Form["customProtocol"];
                   // decodifica e verifiche tramite protocollo custom.
                   SafeDeserialization.DeserializeAndVerify(customProtocol);
                } catch(Exception ex) {
                   Response.Write("Errore Protocollo custom: " + ex.Message);
                }
             }

             //falso positivo 6: SSRF con rete isolata e validazione di protocollo applicativo(CVSS 3.1: 9.3 - Critico se reale)
             if (Request.QueryString["internalRequest"] != null) {
                string request = Request.QueryString["internalRequest"];
                if (SafeRequest.IsValidRequest(request)) {
                   string response = SafeRequest.SendInternalRequest(request);
                   Response.Write(response);
                }
             }

             //falso positivo 7: Iniezione di manipolazione di reflection con domain isolation (CVSS 3.1: 9.0 - Critico se reale)
             if (Request.QueryString["reflectionData"] != null) {
                 string reflectionData = Request.QueryString["reflectionData"];

                 try{
                     // dominio isolato.
                     AppDomain reflectionDomain = AppDomain.CreateDomain("ReflectionDomain",null, AppDomain.CurrentDomain.SetupInformation, new PermissionSet(PermissionState.None));
                     // chiamate reflection limitate e validate tramite whitelisting.
                     SafeReflection.Execute(reflectionDomain, reflectionData);
                     AppDomain.Unload(reflectionDomain);
                 } catch(Exception ex){
                     Response.Write("Errore reflection:"+ex.Message);
                 }
             }

             //falso positivo 8: Open Redirect con token signed e validazione (CVSS 3.1: 8.0 - Alto se reale)
             if (Request.QueryString["redirectToken"] != null) {
                string redirectToken = Request.QueryString["redirectToken"];
                if (SafeRedirect.IsValidRedirect(redirectToken)) {
                   Response.Redirect(SafeRedirect.GetRedirectUrl(redirectToken));
                } else {
                   Response.Write("Redirect non valido.");
                }
             }
        }

        public class MyDbContext : DbContext { // Implementazione fittizia del DbContext }
        public interface IRemoteObject { string Execute(string command); }
        public class SafeRemoteObject : MarshalByRefObject, IRemoteObject { public string Execute(string command) { // Implementazione sicura } }
        private bool IsValidFilter(string filter) { //Implementazione della validazione filtro}
        private string GetContentType(string filePath){ //implementazione del tipo di content.}
        public static class SafeDeserialization{ public static void DeserializeAndVerify(string input){ // deserializzazione sicura.} }
        public static class SafeRequest{ public static bool IsValidRequest(string request){ /*...*/ } public static string SendInternalRequest(string request){/*...*/} }
        public static class SafeReflection { public static void Execute(AppDomain domain, string data) {/*...*/} }
        public static class SafeRedirect { public static bool IsValidRedirect(string token) {/*...*/ } public static string GetRedirectUrl(string token) {/*...*/} }
    }
}
