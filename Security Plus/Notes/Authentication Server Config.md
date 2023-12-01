### Comparing Authentication Services

**Kerberos

- Network authentication protocol  
- Database of objects such as Active Directory
- Provides mutual authentication
- KDC issues ticket-granting tickets
- Time-stamped tickets that expire
- Requires internal time synchronization
- Uses port 88  

LDAP (Lightweight Directory Access Protocol

  

- X.500 based
    
- Uses specifically formatted strings
    
- LDAP, Lightweight Directory Access Protocol, is an Internet protocol that email and other programs use to look up information from a server. A common use of LDAP is to provide a central place to store usernames and passwords. This allows many different applications and services to connect to the LDAP server to validate users.
    
- LDAP://CN=Homer, CN=Users, DC=GetCertifiedGetAhead, DC=com
    

Secure LDAP (Encrypted Lightweight Directory Access Protocol)

Authenticating Clients

- PAP (Password Authentication Protocol) - Sends pw in plaintext   
- CHAP (Challenge Handshake Authentication Protocol) - uses shared secret
- MS-CHAP - replaced by MS-CHAPv2
- MS-CHAPv2 - provides mutual authentication

  
  
  
  

RADIUS (AAA Server)

  

- Uses UDP
    
- Encrypts only the password
    
- Uses Port 1812
    

  

Remote Authentication Dial-In User Service (RADIUS) is a client/server protocol and software that enables remote access servers to communicate with a central server to authenticate users and authorize their access to the requested system or service.

  

Authenticating Remote Clients

  

- Diameter
    

- Extension of RADIUS
    
- Supports EAP
    

- TACACS+
    

- Uses TCP port 49
    
- Encrypts entire authentication process
    
- Uses multiple challenges and responses
    
- Terminal Access Control Access Control Server