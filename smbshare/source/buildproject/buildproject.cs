using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ConstrainedExecution;
using System.Runtime.Remoting.Lifetime;
using System.Text;

class buildproject
{
    private static TcpListener listener;
    private static string filePath = @"C:\Users\Administrator\Desktop\connect\BuildProject.log";

    static void Main(string[] args)
    {
        int port = 9001;
        IPAddress ipAddress = IPAddress.Parse("10.0.2.20");

        try
        {
            listener = new TcpListener(ipAddress, port);
            listener.Start();

            LogMessage($"Listening on {ipAddress}:{port}...");

            List<string> archs = new List<string> { "x86", "x64" };
            List<string> options = new List<string> { "exec-revshell", "dll-revshell", "dotnet2jscript" };
            while (true)
            {
                TcpClient client = listener.AcceptTcpClient();
                NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[1024];
                int bytesRead = stream.Read(buffer, 0, buffer.Length);
                string receivedString = Encoding.ASCII.GetString(buffer, 0, bytesRead);
                client.Close();

                LogMessage($"Received: {receivedString}");
                if (string.IsNullOrEmpty(receivedString))
                {
                    LogMessage("Received an empty string, waiting for next connection...");
                    continue;
                }

                string[] parts = null;
                try
                {
                    parts = receivedString.Split(':');
                }
                catch
                {
                    LogMessage("Splitting went wrong...");
                    continue;
                }
                
                string arch = null;
                string option = null;
                if (parts.Length == 2)
                {
                    arch = parts[0].Trim();
                    option = parts[1].Trim();
                }
                else
                {
                    LogMessage("Incorrect amount of parts...");
                    continue;
                }

                if (!archs.Contains(arch))
                {
                    LogMessage("Received invalid arch...");
                    continue;
                }
                else if (!options.Contains(option))
                {
                    LogMessage("Received invalid option...");
                    continue;
                }

                try
                {
                    BuildProject(arch, option);
                    LogMessage("Building done");
                }
                catch (Exception ex)
                {
                    LogMessage($"Error: {ex.Message}");
                }
            }
        }
        catch (Exception ex)
        {
            LogMessage($"Error: {ex.Message}");
        }
        finally
        {
            LogMessage("Stopping...");
            listener?.Stop();
        }
    }

    static void BuildProject(string arch, string projectName)
    {
        string msbuildPath = @"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\msbuild.exe";
        if (projectName == "exec-revshell")
        {
            string projectBasePath = @"Y:\source\exec-revshell\exec-revshell.csproj";
            string projectPath = string.Format(projectBasePath, arch, projectName);
            buildRevShell(msbuildPath, arch, projectPath);
            return;
        }
        else if (projectName == "dll-revshell")
        {
            string projectBasePath = @"Y:\source\dll-revshell\dll-revshell.csproj";
            string projectPath = string.Format(projectBasePath, arch, projectName);
            buildRevShell(msbuildPath, arch, projectPath);
            return;
        }
        else if (projectName == "dotnet2jscript")
        {
            projectName = "js-revshell";
            string projectBasePath = @"Y:\source\js-revshell\js-revshell.csproj";
            string projectPath = string.Format(projectBasePath, arch, projectName);
            buildRevShell(msbuildPath, arch, projectPath);

            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = @"C:\Users\Administrator\Desktop\connect\DotNetToJScript.exe",
                Arguments = $"Y:\\source\\js-revshell\\bin\\{arch}\\Release\\js-revshell.dll --lang=Jscript --ver=v4 -o Y:\\DotNetToJscript\\demon.js",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using (Process process = new Process { StartInfo = startInfo })
            {
                process.Start();
                process.WaitForExit();
            }
            
            return;
        }
    }

    static void buildRevShell(string msbuildPath, string arch, string projectPath)
    {
        ProcessStartInfo startInfo = new ProcessStartInfo
        {
            FileName = msbuildPath,
            Arguments = $"/p:Configuration=\"Release\" /p:Platform=\"{arch}\" \"{projectPath}\"",
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using (Process process = new Process { StartInfo = startInfo })
        {
            process.Start();
            process.WaitForExit();
        }

        return;
    }

    static void LogMessage(string message)
    {
        string timestamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string logEntry = $"[{timestamp}] {message}";
        File.AppendAllText(filePath, logEntry + Environment.NewLine);
        Console.WriteLine(logEntry);
    }
}
