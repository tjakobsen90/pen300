All GPO's

`Match (n:GPO) RETURN n`


CA servers

`MATCH p = (:Domain)-[:Contains*1..]->(:EnterpriseCA)
RETURN p
LIMIT 1000`


Cleartext password fields

`MATCH p = (:Domain)-[:Contains*1..]->(u:User)
WHERE u.userpassword <> ""
  OR u.unixpassword <> ""
  OR u.sfupassword <> ""
  OR u.unicodepassword <> ""
RETURN p
LIMIT 1000`


Constrained Delegation

`MATCH (c:Computer) WHERE c.allowedtodelegate IS NOT NULL RETURN c`


Groups that can reset passwords

`MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN m.name, n.name ORDER BY m.name`


Local admins

`MATCH p=(m:User)-[r:AdminTo]->(n:Computer) RETURN m.name, n.name ORDER BY m.name`


MSSQL SPN

`MATCH (c:Computer) WHERE ANY (x IN c.serviceprincipalnames WHERE toUpper(x) CONTAINS 'MSSQL') RETURN c`


Other domains and forests

`MATCH (n)-[r]->(m) WHERE NOT n.domain = m.domain RETURN LABELS(n)[0],n.name,TYPE(r),LABELS(m)[0],m.name`


Owned objects and their groups

`MATCH p = allShortestPaths((b1:Base)-[:MemberOf]->(b2:Base))
WHERE "owned" IN split(b1.system_tags, " ")
  AND b1 <> b2
RETURN p
LIMIT 1000`


Password in description

`MATCH (u:User)
WHERE u.description IS NOT NULL AND trim(u.description) <> ""
RETURN u`


Resource Based Constrained Delegation (RBCD)

`MATCH p = (:Base)-[:AllowedToAct*1..]->(:Base)
RETURN p
LIMIT 1000`


Unconstrained Delegation

`MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT c2.name IN domainControllers RETURN c2`


User password not required

`MATCH p = (:Domain)-[:Contains*1..]->(:Base {passwordnotreqd: true})
RETURN p
LIMIT 1000`


Users that can RDP

`match (u1:User) WHERE u1.plaintext=True MATCH p1=(u1)-[:CanRDP*1..]->(c:Computer) RETURN u1`


Weak GPO permissions

`MATCH p=(u:User)-[r:AllExtendedRights|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|GpLink*1..]->(g:GPO) RETURN p`
