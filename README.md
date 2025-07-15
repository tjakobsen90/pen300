# GenPayload
- /genpayload/app.py
    - The main application, running this will generate a payload based on a language and a template
- /genpayload/oneliners.py
    - A script that contains oneliners and valuable pieces of code, that will be copied to your clipboard (xclip)
- /smbshare/source
    - All the C# code and projects
- /smbshare/source/buildproject
    - Important for app.py to generate C# payloads
    - Run this on a Windows system with Visual Studio Community
    - app.py will generate network traffic and sent it to the Windows system
    - Based on the network package a C# project will be compiled and saved to the smbshare
- /tools/tools/webserver.sh
    - A simple webserver to serve all my payloads, tools etc
    - It automagically copies changed executable from /smb/share/source to the webroot
- /tools/msfconsole/handler_setup.rc
    - A resource-file to start metasploit with, it starts with the default values of app.py
- /www
    - The webroot for webserver.sh
    - /pe is for executables
    - /pl is for payloads
    - /ps is for powershell scripts

# Getting it to run
- `git clone git@github.com:tjakobsen90/pen300.git /home/myname/pen300`
- Make sure to replace /home/tijmen in the code to your own name :)
- `sudo rlwrap -n msfconsole -q -r /home/myname/pen300/tools/msfconsole/handler_setup.rc`
- `~/pen300/tools/webserver.sh`
- `~/pen300/genpayload/app.py -i 10.10.10.10 -f ps -t ph`
- `~/pen300/genpayload/oneliners.py -i 10.10.10.10 -c run.txt`
- Run the generate download cradles on your target

# Generating C# stuff
- Host a SMB share on your Kali, link it to ~/pen300/smbshare
- Install a Windows system (10.0.2.20/24) and install Visual Studio Community
- Mount the smbshare (Z:\)
- Run the executable of the buildproject project
- Make sure firewall doesn't block buildproject.exe

# Todo:
- Make PS Proxy-aware by default
- Implement process hollowing for CS projects
- AMSI bypasses in Jscript
- Add PrintSpoofer and ntlmrelay to oneliners
- Fix sqldll to hex to run commands
- Automate VBA to DOC creation
