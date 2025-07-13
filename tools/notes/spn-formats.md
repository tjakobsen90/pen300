A Service Principal Name (SPN) is a unique identifier for a service instance in an Active Directory environment. SPNs are used to associate a service instance with a service logon account. The format for an SPN is generally as follows:

serviceclass/host:port/servicename

Here are some common service classes used in SPNs:
Service Class	Description
ldap	Lightweight Directory Access Protocol
dns	Domain Name System
http	Hypertext Transfer Protocol
https	Hypertext Transfer Protocol Secure
cifs	Common Internet File System
MSSQLSvc	Microsoft SQL Server
nfs	Network File System
iSCSITarget	iSCSI Target
ExchangeRFR	Exchange Replication
ExchangeMDB	Exchange Mailbox Database
ExchangeAB	Exchange Address Book
WSMAN	Windows Remote Management
TERMSRV	Terminal Services
RPC	Remote Procedure Call
HOst	Generic host service
FIMService	Forefront Identity Manager Service

These service classes are used to specify the type of service the SPN is associated with. The host part of the SPN is typically the fully qualified domain name (FQDN) of the server hosting the service, and the port is optional and used if the service is running on a non-standard port.