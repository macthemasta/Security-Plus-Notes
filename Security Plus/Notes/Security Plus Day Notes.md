




DHCP - Dynamic Host Configuration Protocol

Dynamic Host Configuration Protocol assigns the IP address to the nodes connecting to the network.



  





Grep - Allows you to search for specific words or phrases inside a large file in Linux.

  

LAMP - Linux, Apache, MySQL, PHP

  



  


    

  

Comparing Access Control Models

  

Role-Based Access Control (RBAC)

  

- Uses roles (often implemented as groups)
    
- Granted access by placing users into roles based on their assigned jobs, functions, or tasks
    
- Often use a matrix
    
- A user account is placed into a role or group
    
- User inherits rights and permissions of the role
    
- Simplifies administration
    
- Helps enforce principle of least privilege
    
- User templates include group membership
    

  

Group Based Access Control

  

- Controls/Roles/Rules made on a group
    

  

Rule Based Access Control (RuBAC)

  

- Based on a set of approved instructions, such as an access control list
    
- Can use triggers to respond to an event
    

  

Discretionary Access Control

  

- Resources identified as objects
    

- Files, folders, shares
    

- Specifies that every object has an owner
    
- Owner has full, explicit control of the object
    
- Microsoft’s NTFS uses the DAC model
    
- DACL (Discretionary ACL)
    

- List of access permissions
    

- SIDS (Security Identifiers)
    

- Uniquely identifies users and groups
    

- Pros
    

- Easy to implement
    
- Great Flexibility
    
- Built-in in most OS
    

- Cons
    

- Doesn’t scale well
    
- Possibility of ACL Explosion
    
- Prone for mistakes
    

  

Mandatory Access Control (MAC)

  

- Uses labels to determine access (no other access control uses labels)
    
- Subjects and objects are assigned labels (classification)
    
- Permissions granted when the labels & clearances math
    
- SELinux (Security-Enhanced Linux)
    

- Uses MAC model
    
- Helps prevent malicious or suspicious code from executing
    

- Pros
    

- Most Secure
    
- Easy to scale
    

- Cons
    

- Not Flexible
    
- Limited user functionality
    
- High admin overhead
    
- Expensive
    

  

Attribute Based Access Control (ABAC)

  

ABAC - uses multiple attributes (location, time, type, object, etc.)

Access control based on the attributes.

  

Single Sign-On (SSO)

  

- Users sign on once
    
- One set of credentials used throughout a user’s entire session
    
- Provides central authentication
    
- Transitive Trusts
    
- Federation
    
- SAML
    

- Can also provide authorization & authentication and allows SSO
    
- Security Assertion Markup Language (SAML) is an open standard that allows identity providers (IdP) to pass authorization credentials to service providers.
    
- SAML pulls your identity across multiple access points
    

  

Federated Identity Management - FIM

  

The key difference between SSO and FIM is that while SSO is designed to authenticate a single credential across various systems within one organization, federated identity management systems offer single access to a number of applications across various enterprises.

  

FIM and SSO are different, but are very often used together. Remember, FIM gives you SSO, but SSO doesn’t necessarily give you FIM.

  

OpenID and OAuth

  

- OpenID is about authentication (ie. proving who you are), OAuth is about authorization (ie. to grant access to functionality/data/etc.. without having to deal with the original authentication).
    
- OAuth could be used in external partner sites to allow access to protected data without them having to re-authenticate a user.
    
- OAuth uses tokens between the identity provider and the service provider to authenticate and authorize users to resources.
    
- OpenID - does Authentication
    
- OAuth - does Authorization
    

  

Onboarding and Offboarding Accounts

  

- Onboarding - Bringing people on
    
- Offboarding - Withdrawing people
    

  
  
  
  
  

Various Security Agreements

  

Organizational Security Agreements

  

- Memorandum of understanding (MOU) - Intent to work together
    
- Business partnership agreement (BPA) - Establish a formal partner relationship
    
- Non-disclosure agreement - Govern use and storage of shared confidential and private information
    
- Service level agreement (SLA) - Establish metrics for service delivery and performance
    
- Measurement systems analysis (MSA) - Evaluate data collection and statistical methods used for quality management
    

  

Microsoft User Account Control (UAC)

  

Prevents applications from installing without authorization

  

Zero Trust Technology

  

- Zero Trust (ZT) is the term for an evolving set of cybersecurity paradigms that move defenses from static, network-based perimeters to focus on users, assets, and resources.  
      
    
- Zero trust assumes there is no implicit trust granted to assets or user accounts based solely on their physical or network location (i.e., local area networks versus the internet) or based on asset ownership (enterprise or personally owned).  
      
    
- Authentication and authorization (both subject and device) are discrete functions performed before a session to an enterprise resource is established.  
      
    
- Zero trust focuses on protecting resources (assets, services, workflows, network accounts, etc.), not network segments, as the network location is no longer seen as the prime component to the security posture of the resource.
    

  
  
  
  
  
  

Protocols

  
  
  

Basic Connectivity Protocols

- TCP
    

- Is a reliable guaranteed delivery
    
- Uses a three-way handshake
    

- Use sends a SYN (Synchronize Packet) 
    
- Receiver then sends a SYN/ACK (Synchronize/Acknowledge)
    
- The sender will then ACK (Acknowledge) this SYN/ACK
    

- Uses acknowledgements for every packet transmitted and delivered.
    
- It’s slow  
      
    

- UDP - User Datagram Protocol
    

- Best effort
    

- It is not reliable
    
- Does not use three-way handshake
    
- Does not guarantee any packet delivery
    
- Fast
    
- Send and pray it gets there
    
- Is connectionless
    

  

Reviewing Protocols

- IPv4 and IPv6
    
- ICMP (Internet Control Message Protocol)
    

- Commonly blocked at firewalls
    
- If ping fails, ICMP may be blocked
    
- ICMP is a troubleshooting protocol. Ping is an ICMP 
    

- ARP (Address Resolution Protocol)
    

- Resolves MAC addresses for IPv4
    

- NDP (Neighbor Discovery Protocol)
    

- Resolves MAC addresses for IPv6 (and more)
    
- Neighbors are the devices connected to your network
    

  

Reviewing Encryption Protocols

- SSH (Secure Shell) - Port 22
    

- It is used for encryption and operates on port 22  
      
    

- SCP (Secure Copy) - Port 22 with SSH  
      
    
- SSL (Secure Sockets Layer)  
      
    
- TLS (Transport Layer Security)
    

- SSL and TLS use port 443 with HTTPS
    
- SSL and TLS use port 636 with LDAP  
      
    

- IPSec (Internet Protocol Security)
    

- Tunneling Protocol used for VPN
    
- Authentication Header (AH) Encapsulating Security Payload (ESP)  
      
    

- The AH protocol provides a mechanism for authentication only.  
      
    
- ESP can be used with confidentiality only, authentication only, or both confidentiality and authentication.  
      
    
- HTTP - Hyper Text Transfer Protocol - Port 80
    

- Web protocol for accessing web server/web traffic. Has no encryption uses TCP 80.  
      
    

- HTTPS - Hyper Text Transfer Protocol Secure - Port 443
    

- Secure HTTP. Used for secure web access, uses SSL or TLS with fill encryption uses TCP 443.  
      
    

- FTP - Port 20 and 21
    

- File Transfer Protocol that operates on port 20 and 21 with no encryption  
      
    

- SFTP - Port 22 (uses SSH)
    

- Secure File Transfer Protocol uses SSH for encryption on TCP 22  
      
    

- FTPS - Port varies - sometimes uses 989 and 990
    

- File Transfer Protocol Secure uses SSL/TLS on TCP 989/990  
      
    

- TFTP - UDP port 69
    

- Lightweight FTP uses TCP or UDP 69  
      
    

- Default TFTP - Default Trivial File Transfer Protocol
    

- Uses UDP 69  
      
    

- Telnet - Port 23
    

- For remote management on TCP 23, has no encryption
    
- SSH on port 22 is more secure alternative
    
- Used for remotely managing devices, systems, routers, switches etc.  
      
    

- SNMP - Simple Network Management Protocol
    

- Messages sent on UDP port 161
    
- Traps (errors) sent on UDP port 162
    
- SNMPv3 provides encryption and is secure  
      
    

- NetBIOS - Ports 137 - 139
    

- NetBIOS provides communication services on local networks. NetBIOS is a non-routable OSI Session Layer 5 Protocol and a service that allows applications on computers to communicate with one another over a local area network (LAN).  
      
    

- sTelnet - Port 22 
    

- For secure remote management on TCP 22 uses SSH  
      
    

- LDAP  - Lightweight Directory Access Protocol - Port TCP 389
    

- Not encrypted uses TCP 389
    
- Port 636 when encrypted with SSL or TLS
    
- Used for accessing AD  
      
    

- sLDAP - Secure Lightweight Directory Access Protocol - Port TCP 636
    

- Is encrypted with SSL/TLS uses TCP 636  
      
    

- Secure Voice & Video uses SRTP (Secure Real-Time Transport Protocol) used for Encrypted Voice over IP (VoIP)  
      
    
- Kerberos - Port 88
    

- Remote Authentication  
      
    

- Microsoft’s SQL Server - Port 1433
    

- Relational Database  
      
    

- Remote Desktop Protocol - Port 3389
    

- Only on Windows  
      
    

  
  
  

Reviewing Email Protocols

  

- SMTP - Simple Mail Transfer Protocol - Port TCP 25/TCP 465
    

- Non-Encrypted TCP 25
    
- Encrypted TCP 465  
      
    

- POP3 - Post Office Protocol - Port TCP 110/TCP 995
    

- Non-Encrypted TCP 110
    
- Encrypted TCP 995  
      
    

- IMAP4 - Internet Message Access Protocol - Port TCP 143/TCP 993
    

- Non-Encrypted TCP 143
    
- Encrypted TCP 993
    

  

IPv4 (Internet Protocol version 4)

  

- IPv4 is 32 bits long (xxx.xxx.xxx.xxx)
    
- 4.3 billion unique addresses
    
- Private IP Address
    

- 10.x.x.x
    

- 10.0.0.0 through 10.255.255.255
    

- 172.16.x.x-172.31.x.x
    

- 172.16.0.0 through 172.31.255.255
    

- 192.168.x.x
    

- 192.168.0.0 through 192.168.255.255
    

- Total number of IPv4 addresses 2^32 or 4.3 billion
    
- It has 4 octets
    

  

Static Network Address Translation (NAT)

  

Network Address Translation which maps multiple private IP addresses to one public address. NAT allows us to conserve and reuse the same private IP addresses over and over.

  

NAT allows us to communicate with other computers.

  

IPv6 (Internet Protocol version 6)

  

- It has a lot of IP addresses don’t think too deep on this
    
- ~340 undecillion
    

  
  
  
  
  

Understanding DNS

  

- Resolves names to IP addresses
    
- Records
    

- A - IPv4 Host
    
- AAAA - IPv6 Host
    
- PTR - Pointer
    
- MX - Mail Server
    
- CNAME - Alias  
      
    

- Internet servers often run BIND or Unix or Linux
    
- Queries to DNS server use UDP port 53
    
- Zone transfers between servers use TCP port 53
    

  

Why are Ports Important

  

- IP address used to locate hosts
    
- Port used to direct traffic to correct protocol/service or application
    

- Server ports
    
- Client ports
    

- Blocking ports blocks protocol traffic
    

  
  
  

Switches

  

- Physical security
    
- Switching Loop
    

- Caused if two ports connected together
    
- STP and RSTP protect against switching loops
    

- VLAN
    

- Logically group computers
    
- Logically separate/segment/isolate computers
    

  

Port Security/Authentication

  

- Disable unused ports
    
- MAC address filtering
    
- 802.1x port security (port authentication)
    

- Provides port-based authentication
    
- Prevents rogue devices from connecting
    
- Layer 2 technology configured on a switch
    

- 802.11 WLAN - Wireless Local Area Network standard
    

  
  
  

Access Control Lists (ACLs)

  

- List of rules to define access
    
- Identify what is allowed and what is not allowed
    
- ACLs often use an implicit deny policy
    

- NTFS uses a Discretionary ACL to identify who is allowed access to a file or a folder
    

- All others blocked
    

- Firewalls define what traffic is allowed
    

- Deny any rule blocks all other traffic
    
- Packet filtering
    

  

Routers

  

- Routers and ACLs
    

- Filter based on
    

- IP addresses and networks
    
- Ports
    
- Protocols
    

  

- Routers and firewalls
    

- Implicit deny (last rule in ACL)  
      
    

WAP (Wireless Access Point)

  

A WAP is a networking hardware device that allows a Wi-Fi device to connect to a wired network. It bridges the gap between the wired and wireless networks, enabling devices like laptops, smartphones, and tablets to connect to the local area network (LAN) without the need for physical cables.  
  

- Key Features:
    

- Wireless connectivity & wired connectivity
    
- SSID (Service Set Identifier):
    

- WAPs broadcast SSIDs, which are unique names that identify individual wireless networks.
    

- Security Features:
    

- WAPs often come with security features such as WPA2/WPA3 encryption, MAC address filtering, and the ability to set up guest networks.
    

- Channel Selection:
    

- WAPs operate on specific radio frequency channels within the 2.4 GHz and 5 GHz bands.  
      
    

- What they use:  
      
    Wireless Access Points use radio waves to transmit and receive data between devices and the wired network. The most common Wi-FI standards include 802.11a, 802.11b, 802.11g, 802.11h, 802.11ac, and 802.11ax (Wi-Fi 6).  
      
    The choice of standard affects factors like data transfer rates, range, and compatibility with devices.  
      
    
- Choosing a Wireless Network Mode:  
      
    

- Infrastructure Mode: In this mode, devices communicate through a central WAP. This is the most common mode and is suitable for most home and business networks.  
      
    
- Ad-Hoc Mode: In this mode, devices communicate directly with each other without the need for a central WAP. This mode is less common and is typically used for peer-to-peer communication.  
      
    
- Mixed Mode: This allows the WAP to support multiple wireless standards simultaneously. It can be useful if you have a variety of devices with different Wi-Fi capabilities.  
      
    
- Wireless Standards (802.11a/b/g/n/ac/ax): Choose the appropriate wireless standard based on the devices you have and the performance you need. Newer standards generally offer higher data transfer rates and better overall performance.  
      
    
- Frequency Band (2.4 GHz vs 5 GHz): WAPs operate on either the 2.4 GHz or 5 GHz bands. The 5 GHz band typically offers higher data transfer rates and less interference buy has a shorter range compared to the 2.4 GHz band.  
    

Screen Subnet new name for (DMZ)

  

DMZ (De Militarized Zone) is the zone between the two firewalls. On one side of the DMZ is the public network. On the other side of the DMZ is the private network. You can put any public facing servers like web server or email server in the DMZ.

  

- You should put the DB server or Sharepoint server behind the DMZ.
    

  

Web Application Firewall (WAF)

  

- Web based Firewall
    

- WAF focuses on the security of web applications, inspecting and filtering hTTP traffic. It is designed to detect and prevent attacks like SQL injection, cross-site scripting (XSS), and other web application vulnerabilities.
    

  

Proxies (Proxy Servers)

  

A basic proxy server provides for protocol-specific outbound traffic. For example, you might deploy a web proxy that enables client computers to connect to websites and secure websites on the Internet.

  

Web proxies are often also described as web security gateways as usually their primary functions are to prevent viruses or Trojans infecting computers from the Internet, block spam, and restrict web use to authorized sites.

  

- Caching content for performance
    
- Using URL filters to restrict access
    

  

UTM - Unified Threat Management

  

- Combines multiple security controls
    
- Reduces administrative workload
    
- Web security gateways
    
- UTM security appliances
    

- Firewall, antivirus protection, anti-spam protection, URL filtering, and content filtering.
    

  

OSI 7 Layer Model (People Dont Network To Simple Presentations Anymore)

  

Physical

- Physical structure
    
- Coax, Fiber, Wireless, Hubs, Repeaters
    

  
Data Link

- Frames
    
- Ethernet, PPP, Switch, Bridge
    

  

Network

- Packets
    
- IP, ICMP, IPSec, IGMP
    

  

Transportation

- End-to-End Connections
    
- TCP, UDP  
      
    

Session

- Synch & send to port
    
- API’s, Sockets, WinSock  
      
    

Presentation

- Syntax layer
    
- SSL, SSH, IMAP, FTP, MPEG, JPEG  
      
    

Application

- End User Later
    
- HTTP, FTP, IRC, SSH, DNS
    

  
  

Understanding IDSs and IPSs

  

- Intrusion Detection System (IDS)
    

- Detective control
    
- Attempts to detect attacks after they occur
    
- Ex: Your system is moving slower than usual after downloading an unreputable file. You can use an IDS such as Norton Antivirus to scan for threats.  
      
    
- IDS Detection Methods
    

- Signature-based
    

- Also called definition based
    
- Use a database of predefined traffic patterns such as a Common Vulnerabilities and Exposures (CVE) list  
      
    

- Firewall is a preventive control
    

- Attempts to prevent the attacks before they occur. Your firewall will alert you to potential threats and block you from accessing a potentially harmful website/file  
      
    

- Intrusion Prevent System (IPS)
    

- A preventive control
    
- Will stop an attack in progress
    
- Can be on network or host
    

  

- Network Intrusion Detection System (NIDS)
    
- Host Intrusion Detections System (HIDS)
    

  
  

There are three things that decide the choice of controls

  

1. Cost
    
2. Risk Appetite (What is acceptable risk)
    
3. Compliance Requirements
    

  

SIEM Security Information and Event Management (Splunk)

  

- It ingests, indexes, correlates, searches and visualizes the log data in real time.  
      
    
- If it is a known intrusion (known attack) go with signature based IDP/IPS.
    

  

- If it is an unknown brand-new attack (no patches, never seen it before) go with anomaly-based IDS/IPS (Behavior based or heuristic based)
    

  

- Brand new attacks for which there is no patch or no signature it is known as a Zero-day attack (Patient Zero Attack)
    

  

- For anomaly-based IDS/IPS to be effective, you need a very good current baseline.  
      
    
- Baseline tells you what is normal at a point in time.  
      
    
- Too many false positives results in alert fatigue.  
      
    
- If your baseline is outdated, you will be flooded with too many false positives and false negatives.
    

  
  
  
  

Packet Sniffing

  
  

- Also called protocol analyzer
    
- Captures and analyzes network traffic
    
- Wireshark - free packet sniffer
    
- IDSs and IPSs include packet sniffing capabilities
    

  

HoneyPots and HoneyNets

  

- A honeypot is a computer system intended to mimic likely targets of cyberattacks.
    
- A honeynet is a group of virtual servers contained within a single physical server, and the servers within this network are honeypots.
    

  

SIEM + SOAR

  

- SIEM collects the data SOAR responds to the incident and threat hunting
    
- SOAR - Security Orchestration, Automation and Response.
    

  

Wireless Standards

  

- 802.11n - uses MIMO (Multiple Input Multiple Output)
    
- There are three channels that do not overlap
    

- Channels 1, 6 and 11 are non overlapping and do not interfere with each other.
    

  

Wireless Antennas

  

- Isotropic - theoretical omnidirectional
    
- Dipole - omnidirectional
    
- Yagi - high gain directions
    
- Antenna power
    

- dBi, dBd, dBm
    

- Wireless footprint
    

  

Securing Wireless Networks

  

- WEP - Don’t use
    

- Multiple weaknesses. Uses weak RC4 40 bit encryption
    

- WPA - Interim replacement for WEP
    

- Uses TKIP and stronger that WEP
    

- WPA2 - Current standard
    

- Provides best security when used with AES/CCMP
    
- Uses AES 128 or 192 for encryption
    

- WPA/WPA2 Modes
    

- Personal
    

- Uses pre-shared key (PSK)
    
-   
    

- 802.1x (Enterprise mode)
    

- More secure than Personal mode
    
- Adds strong authentication
    
- Uses an 802.1x server (implemented as a RADIUS server) to add authentication
    

- WPA3 Personal uses SAE(Simultaneous Authentication of Equals) instead of PSK (Pre-shared Key)
    
- WPA3 Enterprise uses GCMP256 (Galois Counter Mode Protocol) instead of AES256 (Advanced Encryption Standard)
    
- Change default administrator password
    
- Consider MAC filtering
    
- Disable SSID Broadcast
    

  

EAP, PEAP, and LEAP

  

EAP-TLS is the most secure

LEAP - No certificate is required

  

Wireless Attacks

  

Wardriving

- Searching for open hotspots
    

  

Encryption Attacks

- WEP, TKIP, WPS
    

  

Rogue AP

- Unauthorized hotspot
    

  

Evil Twin

  

Evil Twin is a wireless attack in which they (hackers) stand up another WAP and they use the same name (SSID) as the original legitimate WAP. They jam the original one. And the clients start connecting to the fake one.

  

Disassociation

- Packet w/ spoofed address
    

  

Jamming

- Radio interference
    

  
  

Bluejacking

- Sends unsolicited messages  
      
    

Bluesnarfing

- Theft of information
    

  

NFC (Near Field Communications)

- Steal information or money
    

  

RFID (Radio Freq Identification)

- Longer range in some cases
    

  

Other Wireless Security Concerns

  

- Change the default Admin password
    
- Enable MAC Filtering
    

- MAC addresses can be spoofed
    

  

SSID

  

- SSID stands for Service Set IDentifier and is your wireless network’s name
    
- Change the default SSID
    
- Disabling SSID broadcast
    

- Hides from some devices
    
- Does not hide from attackers
    

  

OSI Model (Please Do Not Throw Sausage Pizza Away)

  

The OSI should be built from the group up. Everything works in Layers.

  

Application - Layer 7

- End User Layer
    
- HTTP, FTP, IRC, SSH, DNS  
      
    

Presentation - Layer 6

- Syntax Layer
    
- SSL, SSH, IMAP, FTP, MPEG, JPEG  
      
    

Session - Layer 5

- Synch & send to port
    
- API’s, Sockets, WinSock  
      
    

Transport - Layer 4

- End-to-end connections
    
- TCP, UDP  
      
    

Network - Layer 3

- Packets
    
- IP, ICMP, IPSec (VPN), IGMP  
      
    

Data Link - Layer 2

- Frames
    
- Ethernet, PPP, Switch, Bridge  
      
    

Physical - Layer 1

- Physical structure
    
- Coax, Fiber, Wireless, Hubs, Repeaters
    

  
  
  
  

Cyber Kill Chain

  

MITRE ATT&CK

  

Recon

- Research, identification, and selection of targets
    

  
Weaponization

- Pairing remote access malware with exploit into a deliverable payload (e.g. Adobe PDF and Microsoft Office files)
    

  
Delivery

- Transmission of weapon to target (e.g. via email attachments, websites, or USB drives)  
      
    

Exploitation

- Once delivered, the weapon’s code is triggered, exploiting vulnerable applications or systems.  
      
    

Installation

- The weapon installs a backdoor on a target’s system allowing persistent access.  
      
    

Command & Controls

- Outside server communicates with the weapons providing “hands on keyboard access” inside the target’s network.  
      
    

Exfiltration

- The attacker works to achieve the objective of the intrusion, which can include exfiltration or destruction of data, or intrusion of another target.
    

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

Securing Hosts and Data

  
  

EDR (Endpoint Detection and Response

  

It is the software that you install on your endpoint that will protect your device from malware or any zero day attacks.

  

Eg. McAfee HBSS, Crowdstrike, Sentinel1, Carbon Black (VMware)

  

Implementing Host Security

  

- Hardening systems
    

- Disabling unnecessary services
    

- Improves security posture
    
- Reduce attack surface
    
- Reduces risks from open ports
    

- Disabling unneeded applications
    
- Disabling unnecessary accounts do not delete
    
- Protecting management interfaces and applications
    

  

Using Baselines

  
Baselines tell you what is normal at any point in time.

- Improve overall security posture
    
- Three steps:
    

1. Initial baseline configuration  
    Start in secure state
    
2. Continuous security monitoring  
    Scan for and detect changes
    
3. Remediation  
    Isolate or quarantine modified systems  
      
    

Security Baselines

  

- Enforce with Group Policy Objects (GPO)
    

- Standardize system configuration
    
- Standardize security settings
    
- Enforce strict company guidelines
    
- Easily apply security settings to multiple computers
    

  
  
  
  

Configuration Baselines

  

- Identifies and documents configuration settings
    

- OS and application settings
    
- Network settings
    

- Must be kept up-to-date
    

- Update documentation when the system is updated
    

- CMDB
    

- Allows you to track and manage all the changes centrally
    

  

Host and Application Baselines

  

- Host software baseline
    

- Provide a list of approved software and a list of installed software
    
- Can be used to identify unauthorized software  
      
    

- Application configuration baselines
    

- Identifies proper settings for applications
    
- Can be used for auditing  
      
    

Baselines

  

- Performance Baselines
    

- Documents normal system performance
    
- Compare current performance against a baseline
    

  
  

Imaging

  

- Provides secure starting point
    

- Reduces costs
    
- Allows you to provision multiple computers' performance against a baseline report to determine abnormal activity.  
      
    

- Baseline Reporting
    

- Provides a report after comparing baselines
    
- Administrators use baseline reporting for multiple types of baseline comparisons  
      
    

Whitelisting vs Blacklisting

  

- Application whitelisting
    

- Identifies authorized software for workstations, servers, and mobile devices
    
- Prevents users from installing or running software that isn’t on the list.
    

  

- Application blacklisting
    

- A list of prohibited applications
    
- Prevents users from installing or running software on the list
    

  

Patch Management

  

- Ensure that systems are up-to-date
    
- Protects system against known vulnerabilities
    
- Test patches in a test environment that mirror the production environment
    
- Automated deployment
    
- Controlled deployment
    
- Scheduling patch management
    
- Testing, deploying and verifying updates
    
- Sandbox is a staging environment. 
    

  

Operational Technology (OT)

  

- Operational Technology refers to commuting systems that are used to manage industrial operations. Operational systems include production line management, mining operations control, oil & gas monitoring etc.
    

  

- Industrial control systems (ICS) is a major segment within the operational technology sector. It comprises systems that are used to monitor and control industrial processes. This could be mine site conveyor belts, oil refinery cracking towers, power grid etc.  
      
    
- Most ICSs fall into either a continuous process control system, typically managed via programmable logic controllers (PLCs), or discrete process control systems (DPC), that might use a PLC or some other batch process control device.  
      
    
- Industrial control systems (ICS) are often managed via a Supervisory Control and Data Acquisition (SCADA) system that provides a graphical user interface for operators to easily observe the status of a system, receive any alarms indicating out-of-band operation, or to enter system adjustments to manage the process under control.
    

  
  
  
  
  
  
  
  
  
  
  

SoC, RTOS, SCADA

  

System on a Chip (SoC)

  

A tiny computer that has everything it needs to work right on a single chop, like a mini-brain with memory, processors, and other essential components all packed together.  
  

- Raspberry-Pi  
      
    

  

Real Time Operating Systems (RTOS)

  

A RTOS as a super organized traffic cop for a computer. It makes sure tasks are done on time, like stopping at a red light in traffic, ensuring things happen when then should.

  

SCADA (Supervisory Control and Data Acquisition System) / HVAC Control

  

Picture a master controller overseeing a big factory. SCADA helps monitor and control everything, like temperature, pressure, and machines, so the factory runs smoothly.

  

Securing Mobile Devices

  

- Full disk encryption
    
- Authentication and device access control
    
- GPS tracking
    
- Removable storage
    
- Storage segmentation
    
- Screen locks
    
- Lockout
    
- Remote wiping
    
- Disabling unused features
    

  

BYOD Concerns

  

- Bring your own device (Employee-owned)
    

- Asset tracking and inventory control
    
- Architecture/infrastructure considerations
    
- Forensics
    
- Legal Concerns
    
- On-boarding/off-boarding
    
- On-board camera/video
    

  
  
  

Mobile Device Management (MDM)

  

- Ensure mobile systems are up to date
    

- Current patches
    
- Up-to-date antivirus
    

- Block devices that are not up to date
    
- Include:
    

- Patch management
    
- Antivirus management
    
- Application control
    

- Mobile Containerization
    
- Capable of Remote Wiping
    

  

Mobile Application Security

  

- Authentication
    
- Credential management
    
- Geo-tagging
    

- Adds geographical info to pictures
    

- Geofence
    

- A virtual geographic boundary, defined by GPS or RFID technology.
    

  

Mobile Device Deployment Models

  

Bring Your Own Device (BYOD)

  

- The mobile is owned by the employee.  
      
    

Corporate Owned, Business Only (COBO)

  

- The device is the property of the company and may only be used for company business.
    

  

Corporate Owned, Personally-Enabled (COPE)

  

- The device is chosen and supplied by the company and remains its property.
    

  

Choose Your Own Device (CYOD)

  

- The employee gets to choose what device they want from the organization.
    

  

Rooting, Jailbreaking and Sideloading

  

- Rooting: This term is associated with Android devices
    
- Jailbreaking: iOS is more restrictive than Android. Jailbreaking allows the user to obtain root privileges, sideload apps, change or add carriers, and customize the interface.  
      
    
- Carrier unlocking: For either iOS or Android. Removes carrier restrictions.
    

  

Hardware-Based Encryption

  

- TPM
    

- Trusted Platform Module
    
- Chip in motherboard (included with many laptops
    
- Full disk encryption
    

- HSM
    

- Removable or external hardware device.
    
- For high-end mission-critical servers
    

  

Data Leakage (Loss) Prevention (DLP)

  

- Data-in-motion
    

- Scans emails and attachments
    
- Detects outgoing confidential company data
    

- Endpoint Protection
    

- Scans for content going to devices
    
- Prevents users from copying certain data to USB drives
    
- Prevents users from sending certain data to printers
    

  

Viruses

- Replication mechanism
    
- Activation mechanism
    
- Payload
    
- Armored virus
    

- Difficult to reverse engineer
    
- Use complex code, encrypt the code, or hide their location
    

- Polymorphic malware
    

- Morphs or mutates when it replicates
    

  

Understanding Malware

  

Worms

- Self replication
    

  

Logic Bombs

- Executes in response to an event
    

  
  

Fileless Malware in Memory

- Characteristics of a Fileless Attack
    

- Has no identifiable code or signature and particular behavior that traditional security software detects.
    
- Is a memory-based threat, residing in the computer’s RAM.
    
- Takes advantage of processes in the system to facilitate an attack
    
- Could be used with other kinds of malware
    
- Could bypass whitelisting
    

  

PUP

- Potentially Unwanted Produced
    
- PUPs may include features or functionalities that users didn’t explicitly request or that may not be transparent during the installation process
    

  

Backdoors

- Provides an alternate method of access
    
- Many types of malware create backdoors
    

  

Logic Bomb Attack

  

Some viruses do not trigger automatically. Having infected a system, they wait for a preconfigured time or date (time bomb) or a system or user event (logic bomb).

  

Trojan Horse

- Appears to be useful but is malicious
    
- Pirated software, rogueware, or games
    
- Also infect systems via USB drives
    

  

Drive-by downloads

1. Attackers comprise a website to gain control of it
    
2. Attackers install a Trojan embedded in the website’s code
    
3. Attackers attempt to trick users into visiting the site
    
4. When users visit, the web site attempts to download the Trojan onto the users systems
    

  

Backdoors

  

A backdoor is a remote access method that is installed without the user’s knowledge.

  

Botnets

- Controlled by criminals called bot herders
    

- Manage command and control centers
    
- Malware joins computers to robotic network
    

- Zombies or clones
    

- Computers within botnet
    
- Join after becoming infected with malware
    

  

Ransomware

- Takes control of user’s system
    
- Attempts to extort payment
    
- The Police Virus
    
- CryptoLocker
    

  

Cryptomining/Cryptojacking

- Hijack resources to mine cryptocurrency
    

  

Keylogger

- Software and hardware
    

  

Rootkits

- System level or kernel access
    
- Can modify system files and system access
    
- Hide their running processes to avoid detection with hooking techniques
    
- File integrity checker can detect modified files
    
- Inspection of RAM can discover hooked processes
    

  

Downgrade attack

- Forces server into using weak protocol versions and ciphers (POODLE Attack - Downgrading SSL)
    

  

Spyware

- Can access a users private data and result in loss of confidentiality  
      
    

Adware

- Pop-ups that market products to users
    
- Blocked with pop-up blockers  
      
    

Social Engineering

  

- Flattery and conning
    
- Assuming a position of authority  
      
    
- Encouraging someone to:
    

- Perform a risky action
    
- Reveal sensitive information  
      
    

- Impersonating
    
- Tailgating
    
- Dumpster Diving
    
- Shoulder Surfing
    
- Tricking users with hoaxes
    

  

Spoofing

  

- IP address
    
- MAC address
    
- Email address
    
- Caller ID
    

  

Redirection

  

- ARP (Address Resolution Protocol)
    

- Usually performed by inside attackers
    

- DNS poisoning
    

- More difficult but works on large networks
    

- Pharming
    

- Similar to phishing put with compromised DNS
    

- Domain hijacking
    

- Redirects traffic for site to an imitator
    

- VLAN hopping
    

- Bypasses VLAN segmentation
    

  

Common Attacks

  

- Spoofing
    

- Impersonating or masquerading as someone or something else
    

- Denial-of-Service (DoS)
    

- Comes from one system
    

- Distributed Denial-of-Service (DDoS)
    

- Multiple attacking computers
    
- Typically include sustained, abnormally high network traffic 
    
- You can use a IPS to prevent
    
- Blackhole:
    

- Drop packets for the affected IP address(es).
    

- Sinkhole:
    

- Traffic flooding an IP can be routed to another network for review.
    

- Smurf
    

- A ping is normally unicast
    
- Smurf attack sends the ping out as a broadcast
    
- Smurf attack spoofs the source IP
    
- Directed broadcast through an amplifying network
    
- Disable directed broadcasts on border routers
    

- SYN flood attack
    

- Common attack against internet servers
    
- disrupts the TCP three-way handshake
    
- Withholds 3rd packet
    
- Flood guards protect against SYN flood attack
    

- XMAS Attack
    

- Christmas Tree Exam is a very well known attack, designed to send a very specifically crafted TCP packet to a device on the network.
    
- Turns on the Urgent, Push & Fin flags
    
- Certain sections of a TCP packet are lit up like a Christmas Tree
    

  

Password Attacks

  

- Brute force
    

- Prevent with account lockout policies
    

- Dictionary
    

- Prevent with complex passwords
    

- Birthday
    

- Prevent with strong hashing
    

- Rainbow table
    

- Prevent with salted hashes
    
- Salting
    

- Add a random value to each password when hashing it for storage
    
- Prevents use of pre-computed hash tables
    

- Hybrid
    

  

Pass The Hash Attack

- Exploiting cached credentials to perform lateral movement
    
- Windows hosts cache credentials in memory as NTLM hashes
    
- Local malicious process with administrator privileges can dump these hashes
    

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

Managing Risk

  
  
  

Identifying Risk

  

- Risk
    

- Likelihood that a threat will exploit a vulnerability
    

- Vulnerabilities
    

- Weaknesses
    

- Threats
    

- Potential danger
    

- Impact
    

- Magnitude of harm
    
- Risk = T * V * I
    

  

Threat

- Event that compromises confidentiality, integrity, or availability
    
- Natural threats
    
- Human threats
    

- Malicious
    
- Accidental  
      
    

- Environmental threats
    
- Malicious insider threats  
      
    

Threat Vector

- Also called attack vector
    

- Refers to the method used to activate the threat
    

- External (outsiders)
    
- Internal (Insiders)
    
- Supply chain  
      
    

- Threat Assessments
    

- Identify and categorize threats
    

  

Risk Management

- Practice of identifying, monitoring, and limiting risks to a manageable level
    
- Cannot eliminate risks
    
- Amount of risk that remains after managing risk is residual risk
    

  
  
  
  

ARO (Annualized Rate of Occurrence)  
  

- ARO represents the estimated frequency at which a specific risk event is expected to occur in a year.  
      
    
- Calculation:
    

- ARO is calculated as the reciprocal of the mean time between occurrences (MTBF - Mean Time Between Failures). If an event occurs on average once every X years, the ARO is 1/X.  
      
    

ALE (Annualized Loss Expectancy)  
  

- ALE is a measure of the expected financial loss from a specific risk in a year, considering the potential impact and the ARO.  
      
    
- Calculation:
    

- ALE is calculated by multiplying the Single Loss Expectancy (SLE) by the ARO. It helps organizations quantify the potential financial impact of a risk over time.  
      
    

SLE (Single Loss Expectancy)

  

- SLE represents the estimated financial loss associated with a single occurrence of a specific risk event.  
      
    
- Calculation:
    

- SLE is calculated by multiplying the asset value (AV) by the exposure factor (EF). Mathematically, SLE = AV*EF  
      
    

AV (Asset Value)

  

- The total value of the asset that is at risk. This could be tangible assets (e.g., hardware) or intangible assets (e.g., data).  
      
    

EF (Exposure Factor)  
  

- The percentage of the asset value that would be lost if a specific risk event occurs. It is expressed as a percentage.  
      
    

  
  
  
  
  
  

Risk Assessments

  

- Documenting the assessment
    
- Results valuable
    

- Help organization evaluate threats and vulnerabilities
    
- Should be protected
    
- Only accessible to management and security professionals
    

  

Cyber Security Risk Register

  

A risk register is a document showing the results of risk assessments in a comprehensible format.

  

Automated security tools

  

- Device or system config tools
    
- COntinuous monitoring and alert systems
    
- Configuration validations tools
    
- Vulnerability scanners
    
- Remediation tools
    
- Patch management software
    
- Automated troubleshooters
    
- Application testers
    

  

Passive & Active Recon

  

- Passive Recon involves acquiring information without directly interacting with the target.  
      
    
- Active reconnaissance involves interacting with the target directly by any means.
    

  

Nation State Attacks / APT Attacks

  

Security + 11/18/2023 - 11/25/2023

  

Books to Read

This is how they tell me the world ends

  

Certs to get

CCIE

CCNP

CGRC ISC2

CMMC

  

Acronyms  
  
ARO - Annualized Rate of Occurrence

ALE - Annualized Loss Expectancy

SLE - Single Loss Expectancy

MDM - Mobile Device Management

FDE - Full Disk Encryption

SED - Self Encrypting Device

CMDB - Configuration Management Database

GPO - Group Policy Object  
MITRE ATT&CK - MIT Research and Engineering Adversarial Tactics, Techniques & Common Knowledge

RSTP - Rapid Spanning Tree

EAP - Extensible Authentication Protocol

SAE - Simultaneous Authentication of Equals

SOC - Security Operations Center

CSO - Chief Security Officer

CISO - Chief Information Security Officer

STIX - Structured Threat Information eXpression

TAXII - Trusted Automated eXchange of Indicator Information

PII - Personal Identifiable Information

PHI - Personal Health Information

SIEM - Security Information and Event Management

UPS - Uninterruptible Power Supply

CIA - Confidentiality, Integrity, Availability

TTP - Tactics, Techniques & Procedures

MDM - Mobile Device Management

BYOD - Bring Your Own Device

VDI - Virtual Desktop Environment

STIG - Security Technical Implementation Guides

DHCP - Dynamic Host Configuration Protocol

DNS - Domain Name Service

ICMP - Internet Control Message Protocol

ARP - Address Resolution Protocol

HTTP - Hyper Text Transfer Protocol

MFA - Multi Factor Authentication

SHA - Secure Hash Algorithm

MD5 - Message Digest v5

EDR - Endpoint Detection and Response

MAC - Media Access Control

GDPR - General Data Protection Regulation

PCI DSS - Payment Card Industry Data Security Standard

HIPAA - Health Insurance Portability and Accountability Act

FISMA - Federal Information Security Management Act

FedRAMP - Government Cloud

SOX - Sarbanes Oxley

AAA - Authentication, Authorization, Accounting

TOTP - Time-based One Time Password

HOTP - HMAC-based One Time Password

HMAC - Hash-based Message Authentication Code

FAR - False Acceptance Rate

FRR - False Rejection Rate

SAML - Security Assertion Markup Language

FIM - Federated Identity Management  
SP - Service Provider

CER - Crossover Rejection Rate

LDAP - Lightweight Directory Access Protocol

Secure LDAP - Encrypted Lightweight Directory Access Protocol

MOU - Memorandum of Understanding

BPA - Business Partnership Agreement

NDA - Non-Disclosure Agreement

SLA - Service Level Agreement

MSA - Measure Systems Analysis

UAC - Microsoft User Account Control

UDP - User Datagram Protocol

TCP - Transmission Control Protocol

SSL - Secure Socket Layer

TLS - Transport Layer Security

UTM - Unified Threat Management

DLL Injection - Dynamic Link Library

SSID - Service Set Identifier

EDR - Endpoint Detection and Response

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

The CIA Triad

  

Confidentiality:

  

Information should only be known to certain people

  

Confidentiality Breach > is when some authorized person has access to your data or can view your PII data.

  

- Least privilege
    

- Users are given only the permissions they need to perform their actual duties
    

- Need to know
    

- Data access is restricted to those who need it
    

- Separation of duties
    

- Tasks broken into components performed by different people  
      
    

- Encryption Types:  
      
    

- Symmetric: Symmetric keys use a single shared key for both the encryption and decryption of data, where the same key is used by both the sender and the recipient.  
      
    
- Think PSK.
    
- Generally faster and more computationally efficient for large-scale data encryption.  
      
    Examples:
    

- AES (Advanced Encryption Standard)
    

- Fast, efficient, strong symmetric block cipher
    
- 128-bit block cipher
    
- Uses 128-bit, 192-bit, or 256-bit keys
    

- Blowfish & Twofish
    

- Blowfish
    

- 64-bit block cipher
    
- Faster than AES in some situations
    

- TwoFish
    

- 128-bit block cipher
    

- DES & 3DES
    

- Data Encryption Stand (DES)
    

- 64-bit block cipher
    
- Uses 56-bit keys and should not be used today
    

- 3DES
    

- 64-bit block cipher
    
- Originally designed as a replacement for DES
    
- Uses multiple keys and multiple passes
    
- Not as efficient as AES
    
- 3DES is still used in some applications, such as when hardware doesn't support AES  
      
    

- Asymmetric: Asymmetric encryption provides a more secure solution for key distribution and enables secure communication between parties without the need to share a secret key.  
      
    Examples:
    

- RSA
    

- Rivest, Shamir, Adleman
    
- Widely used to protect Internet traffic and e-mail
    
- Relies on mathematical properties of prime numbers when creating public and private keys
    
- Public and private keys created as a matched pair
    
- Keys commonly used with asymmetric encryption.
    

- Deffie Hellman
    

- Diffie-Hellman Ephemeral (DHE)
    
- Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)
    

- ECC
    

- Elliptic curve cryptography (ECC)
    

- Commonly used with small wireless devices
    
- Uses smaller key sizes requires less processing power
    

  

Integrity:  
  

- Encryption Types:
    

- Hashing: Hashing is primarily used for data integrity verification.
    
- It produces a fixed-output (hash value) based on the input data.
    
- Commonly used to verify the integrity of data by comparing hash values.  
      
    Examples:
    

- MD5 & SHA1
    

- Message Digest 5
    

- Hashing - Integrity Creates 128-bit hashes
    

- Secure Hash Algorithm (SHA) Family
    

- SHA512
    

- Secure Hash Algorithm 512
    

- NTLM
    

- Improvements over LANMAN
    
- Prone to Pass the HAsh Vulnerability. Do not use it
    

  

Data is stored and transferred as intended and that any modification is authorized

  

- Access controls
    

- Access restricted to authorized users
    

- Encryption
    

- Data made unreadable without proper key  
      
    

- Stegnaography
    

- Secret messages concealed inside of ordinary ones
    

  

- Decryption is taking cipher text and converting it back into plain text.
    
- Encryption obfuscates/scrambles the plain text data and converts it into cipher text that is unreadable.
    

- Encryption protects the confidentiality of the data. Encryption has nothing to do with integrity of the data.
    
- Encryption is a two-way function.
    
- Encrypted Text is called Ciphertext  
      
    

- Integrity protects the data from unauthorized change/alteration/deletion/modification  
      
    
- Hashing is the process of calculating the hash of the data/ Has is a unique representation or number that changes when the data is altered.
    

- Hashing helps us detect the integrity of the data. It is a one way function. Hashed value cannot be decrypted. Hashing has nothing to do with the confidentiality of the data.
    
- Hashing is a one-way function  
      
    

- Steganography is hiding data inside pictures or multimedia files.  
      
    
- There is NO WAY to eliminate the risk, Risk cannot be zero.  
      
    
- Security Logs are the best source of evidence and non-repudiation.
    

- Logs are machine data.  
      
    

- SIEM - Security Information and Event Management
    

- SIEM allows you to ingest the logs, index them, aggregate, search and visualize to find the right incident and event.
    
- SIEM is a tool that allows you to collect, index and analyze the log data to detect anomalies and events/incidents of importance using visual dashboards.
    
- SPLUNK is one of the best SIEM tools.
    

- Code signing:
    

- Code signing is a security practice used in software development to verify the integrity and authenticity of a piece of code.  
      
    

- Key stretching
    

- Use additional rounds to strengthen keys
    
- Makes attacker do more work so slows down brute force  
      
    

- Salting
    

- Add a random value to each password when hashing it for storage
    
- Prevents use of pre-computed hash tables
    
- Use BCRYPT & PBKDF
    

  

Availability:

Information is accessible to those authorized to view or modify it.

  

- Availability of data protects the data/servers from unplanned outages. The way to deal with availability challenges is to have:
    

- Redundancy
    
- Load Balancing 
    
- Active-Active or Active-Passive
    
- High Availability creates Fault Tolerance
    
- RAID
    

- RAID 0 (Striping) - Distributes data across multiple disk to enhance performance, offers no data redundancy,meaning the failure of one drive results in the loss of all data  
      
    

Ex: We have 2 disks, if Disk1 fails so will every other disk.  
Disk1  Disk2  
  A   B      
  C   D      
  E   F        
  

- RAID 1 (Mirroring) - Mirror data on two or more drives to provide redundancy, ensuring that if one drive fails, the data is still accessible from the mirrored drive(s).  
      
    Ex: We have 2 disks. If Disk1 fails a copy is available on Disk2 to pick up the slack.  
    Disk1  Disk2  
      A   A      
      B   B      
      C   C        
      
    
- RAID 5 (Striping and Parity) - Stripes data across multiple drives like RAID 0, but also includes distributed parity for fault tolerance, allowing the array to withstand the failure of one drive without data loss.  
      
    Ex: We have 3 disks although they are different they have the parity so that failure at each level is reduced.  
    Disk1  Disk2  Disk3  
      A   B   p1  
      C   p2   D  
      p3   E   F  
      
    
- RAID 1+0/10 (Mirrored Stripes) - Combines mirroring and striping by creating a mirrored set of striped drives, offering both performance improvement and data redundancy, requiring a minimum of four drives.  
      
    Ex: We have 4 disks two of which are mirrored to provide data redundancy and two which are striped to provide enhanced performance.  
    Disk1  Disk2  Disk3 Disk4  
      A   A   B   B  
      C   C   D   D  
      E   E   F   F      
      
    

- Generators/UPS
    
- Patching - Software updates to close vulnerabilities or bugs that may be found
    

  

Non-repudiation:

  

Subjects cannot deny creating or modifying data

  

- Data is the new OIL
    
- Ignorance is not a strategy  
      
    

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

Attack Vectors & Threat Sources

  

Types of Attacks

  

- Cross Site Scripting (XSS):
    

- XSS is a web security vulnerability where attackers inject malicious scripts into web pages viewed by other users, often leading to the theft of sensitive information.  
     
    

- DNS Poisoning:
    

- DNS poisoning is an attack that corrupts the DNS cache, leading to the redirection of legitimate traffic to malicious websites.  
      
    

- Botnet:
    

- A botnet is a network of compromised computers (bots) controlled by a single entity (botmaster) for malicious purposes, such as launching coordinated attacks or sending spam.  
      
    

- Ping of Death:
    

- Ping of Death is a type of denial-of-service (DoS) attack where an attacker sends oversized or malformed ping packets to a target, causing system or network instability.  
      
    

- Smurf Attack:
    

- In a Smurf attack, an attacker sends a large number of ICMP echo requests (pings) to a network’s broadcast address, causing a flood of responses that can overwhelm and disrupt the targeted network.  
      
    

- RAT (Remote Access Trojan): 
    

- A RAT is a malicious software that allows unauthorized remote access and control of a computer, often used for spying, data theft, or facilitating other cyber attacks.  
      
    

- Rainbow Table:
    

- A Rainbow Table is a precomputed table for reversing cryptographic hash functions, usually for cracking password hashes.  
      
    

- Buffer Overflow:
    

- A Buffer Overflow occurs when too much data is put into a storage area, and it spills into nearby memory.  
      
    

- DLL Injection:
    

- A DLL (Dynamic Link Language) is a file that contains code and data that multiple programs can use simultaneously.
    

  
  
  
  

Attack Surface & Vectors

  

- Attack surface
    

- Ponts where an attacker can discover/exploit vulnerabilities in a network or application
    

- Vectors
    

- Direct access
    
- Removable media
    
- Email
    
- Remote and wireless
    
- Supply chain
    
- Web and social media
    
- Cloud
    

  
Threat Research Sources

  

- Counterintelligence
    
- Tactics, techniques, and procedures (TTPs)
    
- Threat research sources
    

- Academic research
    
- Analysis of attacks on customer systems
    
- Honeypots/honeynets
    
- Dark nets and the dark web
    


GDPR - General Data Protection Regulation. It is a privacy law from the EU. If a US company is collecting European citizen data, they have to comply with GDPR.

  

PCI DSS - Payment Card Industry Data Security Standard. Applies to companies dealing with credit card transactions.

  

HIPAA - Health Insurance Portability and Accountability Act. Protecting Electronic medical records.

  

FISMA - Federal Information Security Management Act. Protecting the federal IT systems with proper controls.

  

FedRAMP - Is for cloud controls to use in Federal Govt.

  

SOX - Sarbanes Oxley - Protection against accounting fraud.

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  



  

VDI Desktop Infrastructure (VDI)

  

VDI - Virtual Desktop Infrastructure: It’s a technology that allows desktop operating systems to run and be managed in a virtualized environment on a centralized server. Instead of running on individual physical computers, each user’s desktop environment is hosted on a virtual machine in a data center.

  

Simply put, VDI lets you access your desktop, complete with all your applications and files, from a remote server using a device like a thin client, laptop, or even a tablet. It provides flexibility, scalability, and centralized management for organizations, making it easier to deploy, maintain, and secure desktop environment

  
  
  

User Experience Virtual Desktop OS, Data, Apps

This Client Availability & Backup Os, Provisioning & Update

Desktop Disaster Recovery User Data & Personalization

Laptop Security Application Virtualization

  

STIG - A list of requirements to harden a system 

  

Cloud Computing

  

IaaS - Infrastructure as a Service

SaaS - Software as a Service

PaaS - Platform as a Service

  

Understanding Cloud Computing

  

Public - Available to anyone

Private - Only available within a company (behind your company firewall)

Hybrid - Combination of public and private

Community - Cloud shared by two or more organizations (AWS GovCloud) Shared between a group.

  
  

Elasticity and Scalability

  

Scalability means that the costs involved in supplying the service to more users are linear. For example, if the number of users doubles in a scalable system, the costs to maintain the same level of service would also double (or less than double). If it costs me than double, the system is less scalable.

  

Elasticity refers to the system’s ability to handle changes in demand in real time. A system with high elasticity will not experience loss of service or performance if demand suddenly doubles (or triples, or quadruples). Conversely it may be important for the system to be able to reduce costs when demand is lose.

  

Cloud Access Security Brokers (CASB)

  

A Cloud Access Security Broker (CASB) is enterprise management software designed to mediate access to cloud services by enterprise users across all types of devices. CASB vendors include Blue Coat (now owned by Symantec) and SkyHigh Networks.

  

IPConfig

  

The ipconfig (Windows) command can be used to report the configuration assigned to the network adapter. In Linux this is ifconfig.

  

DNS - Domain Name Service

  

Converts Domain name to an IP address and vice versa

  

DNS Poisoning

  

DNS Poisoning is a Pharming Attack is a type of DNS attack in which the hackers change the DNS entries to redirect you to a fake site in order to harvest your credentials.

  

The hacker is altering or changing the entries inside the DNS cache such that it redirects you to a fake site and harvest your credentials.

  

Remote Access Trojan (RAT)

  

The attacker gets unauthorized access to the computer and can now control it from a remote location.

  

DHCP - Dynamic Host Configuration Protocol

  

Dynamic Host Configuration Protocol assigns the IP address to the nodes connecting to the network.

  

Mantrap

  

Mantrap is called Access Control Vestibule. It is very effective at preventing Tailgating.

  

Air Gap

  

Air Gap is a physically separate network and does not connect to any other public networks. Is more secure than Logical

  

Tracert

  

Tracert (short for "trace route") is a command-line tool used to trace the route that data takes from one computer to another over a network, such as the internet. It shows the sequence of intermediate devices (like routers) that the data passes through, helping to identify any network issues or delays along the way.

  

ARP - Address Resolution Protocol

  

It maps the MAC address to the IP address.

  

ICMP - Internet Control Message Protocol

  

Ping uses ICMP

  

Whois 

  

You can use whois to see who owns the domain.

  

Netstat -a

  

Allows you to see active connections and listening ports on your network

  

NMAP - Network Mapper

  

- Allows you to see all open ports on a network
    
- Can be used with OS Fingerprinting to find out details of the OS
    

  

Netcat

  

- Tells you what ports are open and what applications are running on the machine a.k.a Banner Grabbing
    

  

Wireshark

  

Wireshark is a free open-source protocol analyzer or packet 

  

Grep - Allows you to search for specific words or phrases inside a large file in Linux.

  

LAMP - Linux, Apache, MySQL, PHP

  

IAM - Identity & Access Management  
  

Exploring Authentication Concepts

  

- Identification - User professes an identity
    
- Authentication - User proves identity
    
- Authorization - Access to resources grated based on proven identity
    
- Non-Repudiation - Something you cannot deny. It is Proof of Origin. The evidence can be tracked to the source and the source cannot deny/dispute.
    
- Accounting - Logging all the activities to ensure there is clear evidence.
    

  

AAA - Authentication, Authorization, Accounting

  

- Authentication - will ensure you are the right person.
    
- Authorization - will grant the right permissions between subjects and objects
    
- Accounting - is keeping track of what you are doing once you are given the access. (log data)
    

- Logs keep track of all the activity and events on the system (windows, linux, vm, firewalls, IDS
    

- Logs are read only
    

  
  
  
  
  
  
  
  
  
  
  
  

Factors of Authentication

  

- Something you should know - Such as username & password
    

      Passwords

  

- Should be strong
    
- Should be changed regularly
    
- Validate identities before resetting
    
- Prevent password reuse with password history
    
- Protect with account lockout policies
    
- Default passwords should be changed
    
- Previous logon notification
    
- Passwords should not be written down
    
- Passwords should not be shared
    
- Provide training to users
    

  

- Something you have - Such as a smart card  
      
    

- Smart cards - CACs and PIVs
    
- Tokens or Key fobs - Commonly combined with something you know (MFA)
    
- HOTP and TOTP used in hardware tokens
    
- HOTP: HMAC-based one-time password algorithm
    

- HMAC-based One-Time Password
    

- TOTP: Time-based One-Time Password Algorithm
    

- Time-based One-Time Password
    
- Expire after 30 seconds
    

  

The main difference between HOTP and TOTP is that the HOTP passwords can be valid for an unknown amount of time, while the TOTP passwords keep on changing and are only valid for a short window in time. Because of this difference generally speaking the TOTP is considered as a more secure ONe-Time Password.

  

- Something you are - Such as a fingerprint or other biometric identification  
      
    

- Biometrics Methods
    

- Fingerprint, thumbprint, or handprints
    
- Retinal scanners (scans the retina of one or both eyes)
    
- Iris scanners (scans the iris of one or both eyes)
    

- Issues with Biometrics
    

- False acceptance - Allows the wrong person
    
- False rejection - Rejects the correct person
    
- Crossover error rate - This measures the accuracy and the inaccuracy. The lower the CER the better the accuracy.
    

- CER measures the overall accuracy of the biometric systems including the false positive and the false negative.  
      
    

- Somewhere you are - Such as your location obtained using geolocation
    
- Something you do - Such as gestures on a touch screen
    

  

Impossible Travel Time Policy - Logs show a user in a location that is too far to find

  

Comparing Authentication Services

  

Kerberos

  

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
    

  

Comparing Access Control Models

  

Role-Based Access Control (RBAC)

  

- Uses roles (often implemented as groups)
    
- Granted access by placing users into roles based on their assigned jobs, functions, or tasks
    
- Often use a matrix
    
- A user account is placed into a role or group
    
- User inherits rights and permissions of the role
    
- Simplifies administration
    
- Helps enforce principle of least privilege
    
- User templates include group membership
    

  

Group Based Access Control

  

- Controls/Roles/Rules made on a group
    

  

Rule Based Access Control (RuBAC)

  

- Based on a set of approved instructions, such as an access control list
    
- Can use triggers to respond to an event
    

  

Discretionary Access Control

  

- Resources identified as objects
    

- Files, folders, shares
    

- Specifies that every object has an owner
    
- Owner has full, explicit control of the object
    
- Microsoft’s NTFS uses the DAC model
    
- DACL (Discretionary ACL)
    

- List of access permissions
    

- SIDS (Security Identifiers)
    

- Uniquely identifies users and groups
    

- Pros
    

- Easy to implement
    
- Great Flexibility
    
- Built-in in most OS
    

- Cons
    

- Doesn’t scale well
    
- Possibility of ACL Explosion
    
- Prone for mistakes
    

  

Mandatory Access Control (MAC)

  

- Uses labels to determine access (no other access control uses labels)
    
- Subjects and objects are assigned labels (classification)
    
- Permissions granted when the labels & clearances math
    
- SELinux (Security-Enhanced Linux)
    

- Uses MAC model
    
- Helps prevent malicious or suspicious code from executing
    

- Pros
    

- Most Secure
    
- Easy to scale
    

- Cons
    

- Not Flexible
    
- Limited user functionality
    
- High admin overhead
    
- Expensive
    

  

Attribute Based Access Control (ABAC)

  

ABAC - uses multiple attributes (location, time, type, object, etc.)

Access control based on the attributes.

  

Single Sign-On (SSO)

  

- Users sign on once
    
- One set of credentials used throughout a user’s entire session
    
- Provides central authentication
    
- Transitive Trusts
    
- Federation
    
- SAML
    

- Can also provide authorization & authentication and allows SSO
    
- Security Assertion Markup Language (SAML) is an open standard that allows identity providers (IdP) to pass authorization credentials to service providers.
    
- SAML pulls your identity across multiple access points
    

  

Federated Identity Management - FIM

  

The key difference between SSO and FIM is that while SSO is designed to authenticate a single credential across various systems within one organization, federated identity management systems offer single access to a number of applications across various enterprises.

  

FIM and SSO are different, but are very often used together. Remember, FIM gives you SSO, but SSO doesn’t necessarily give you FIM.

  

OpenID and OAuth

  

- OpenID is about authentication (ie. proving who you are), OAuth is about authorization (ie. to grant access to functionality/data/etc.. without having to deal with the original authentication).
    
- OAuth could be used in external partner sites to allow access to protected data without them having to re-authenticate a user.
    
- OAuth uses tokens between the identity provider and the service provider to authenticate and authorize users to resources.
    
- OpenID - does Authentication
    
- OAuth - does Authorization
    

  

Onboarding and Offboarding Accounts

  

- Onboarding - Bringing people on
    
- Offboarding - Withdrawing people
    

  
  
  
  
  

Various Security Agreements

  

Organizational Security Agreements

  

- Memorandum of understanding (MOU) - Intent to work together
    
- Business partnership agreement (BPA) - Establish a formal partner relationship
    
- Non-disclosure agreement - Govern use and storage of shared confidential and private information
    
- Service level agreement (SLA) - Establish metrics for service delivery and performance
    
- Measurement systems analysis (MSA) - Evaluate data collection and statistical methods used for quality management
    

  

Microsoft User Account Control (UAC)

  

Prevents applications from installing without authorization

  

Zero Trust Technology

  

- Zero Trust (ZT) is the term for an evolving set of cybersecurity paradigms that move defenses from static, network-based perimeters to focus on users, assets, and resources.  
      
    
- Zero trust assumes there is no implicit trust granted to assets or user accounts based solely on their physical or network location (i.e., local area networks versus the internet) or based on asset ownership (enterprise or personally owned).  
      
    
- Authentication and authorization (both subject and device) are discrete functions performed before a session to an enterprise resource is established.  
      
    
- Zero trust focuses on protecting resources (assets, services, workflows, network accounts, etc.), not network segments, as the network location is no longer seen as the prime component to the security posture of the resource.
    

  
  
  
  
  
  

Protocols

  
  
  

Basic Connectivity Protocols

- TCP
    

- Is a reliable guaranteed delivery
    
- Uses a three-way handshake
    

- Use sends a SYN (Synchronize Packet) 
    
- Receiver then sends a SYN/ACK (Synchronize/Acknowledge)
    
- The sender will then ACK (Acknowledge) this SYN/ACK
    

- Uses acknowledgements for every packet transmitted and delivered.
    
- It’s slow  
      
    

- UDP - User Datagram Protocol
    

- Best effort
    

- It is not reliable
    
- Does not use three-way handshake
    
- Does not guarantee any packet delivery
    
- Fast
    
- Send and pray it gets there
    
- Is connectionless
    

  

Reviewing Protocols

- IPv4 and IPv6
    
- ICMP (Internet Control Message Protocol)
    

- Commonly blocked at firewalls
    
- If ping fails, ICMP may be blocked
    
- ICMP is a troubleshooting protocol. Ping is an ICMP 
    

- ARP (Address Resolution Protocol)
    

- Resolves MAC addresses for IPv4
    

- NDP (Neighbor Discovery Protocol)
    

- Resolves MAC addresses for IPv6 (and more)
    
- Neighbors are the devices connected to your network
    

  

Reviewing Encryption Protocols

- SSH (Secure Shell) - Port 22
    

- It is used for encryption and operates on port 22  
      
    

- SCP (Secure Copy) - Port 22 with SSH  
      
    
- SSL (Secure Sockets Layer)  
      
    
- TLS (Transport Layer Security)
    

- SSL and TLS use port 443 with HTTPS
    
- SSL and TLS use port 636 with LDAP  
      
    

- IPSec (Internet Protocol Security)
    

- Tunneling Protocol used for VPN
    
- Authentication Header (AH) Encapsulating Security Payload (ESP)  
      
    

- The AH protocol provides a mechanism for authentication only.  
      
    
- ESP can be used with confidentiality only, authentication only, or both confidentiality and authentication.  
      
    
- HTTP - Hyper Text Transfer Protocol - Port 80
    

- Web protocol for accessing web server/web traffic. Has no encryption uses TCP 80.  
      
    

- HTTPS - Hyper Text Transfer Protocol Secure - Port 443
    

- Secure HTTP. Used for secure web access, uses SSL or TLS with fill encryption uses TCP 443.  
      
    

- FTP - Port 20 and 21
    

- File Transfer Protocol that operates on port 20 and 21 with no encryption  
      
    

- SFTP - Port 22 (uses SSH)
    

- Secure File Transfer Protocol uses SSH for encryption on TCP 22  
      
    

- FTPS - Port varies - sometimes uses 989 and 990
    

- File Transfer Protocol Secure uses SSL/TLS on TCP 989/990  
      
    

- TFTP - UDP port 69
    

- Lightweight FTP uses TCP or UDP 69  
      
    

- Default TFTP - Default Trivial File Transfer Protocol
    

- Uses UDP 69  
      
    

- Telnet - Port 23
    

- For remote management on TCP 23, has no encryption
    
- SSH on port 22 is more secure alternative
    
- Used for remotely managing devices, systems, routers, switches etc.  
      
    

- SNMP - Simple Network Management Protocol
    

- Messages sent on UDP port 161
    
- Traps (errors) sent on UDP port 162
    
- SNMPv3 provides encryption and is secure  
      
    

- NetBIOS - Ports 137 - 139
    

- NetBIOS provides communication services on local networks. NetBIOS is a non-routable OSI Session Layer 5 Protocol and a service that allows applications on computers to communicate with one another over a local area network (LAN).  
      
    

- sTelnet - Port 22 
    

- For secure remote management on TCP 22 uses SSH  
      
    

- LDAP  - Lightweight Directory Access Protocol - Port TCP 389
    

- Not encrypted uses TCP 389
    
- Port 636 when encrypted with SSL or TLS
    
- Used for accessing AD  
      
    

- sLDAP - Secure Lightweight Directory Access Protocol - Port TCP 636
    

- Is encrypted with SSL/TLS uses TCP 636  
      
    

- Secure Voice & Video uses SRTP (Secure Real-Time Transport Protocol) used for Encrypted Voice over IP (VoIP)  
      
    
- Kerberos - Port 88
    

- Remote Authentication  
      
    

- Microsoft’s SQL Server - Port 1433
    

- Relational Database  
      
    

- Remote Desktop Protocol - Port 3389
    

- Only on Windows  
      
    

  
  
  

Reviewing Email Protocols

  

- SMTP - Simple Mail Transfer Protocol - Port TCP 25/TCP 465
    

- Non-Encrypted TCP 25
    
- Encrypted TCP 465  
      
    

- POP3 - Post Office Protocol - Port TCP 110/TCP 995
    

- Non-Encrypted TCP 110
    
- Encrypted TCP 995  
      
    

- IMAP4 - Internet Message Access Protocol - Port TCP 143/TCP 993
    

- Non-Encrypted TCP 143
    
- Encrypted TCP 993
    

  

IPv4 (Internet Protocol version 4)

  

- IPv4 is 32 bits long (xxx.xxx.xxx.xxx)
    
- 4.3 billion unique addresses
    
- Private IP Address
    

- 10.x.x.x
    

- 10.0.0.0 through 10.255.255.255
    

- 172.16.x.x-172.31.x.x
    

- 172.16.0.0 through 172.31.255.255
    

- 192.168.x.x
    

- 192.168.0.0 through 192.168.255.255
    

- Total number of IPv4 addresses 2^32 or 4.3 billion
    
- It has 4 octets
    

  

Static Network Address Translation (NAT)

  

Network Address Translation which maps multiple private IP addresses to one public address. NAT allows us to conserve and reuse the same private IP addresses over and over.

  

NAT allows us to communicate with other computers.

  

IPv6 (Internet Protocol version 6)

  

- It has a lot of IP addresses don’t think too deep on this
    
- ~340 undecillion
    

  
  
  
  
  

Understanding DNS

  

- Resolves names to IP addresses
    
- Records
    

- A - IPv4 Host
    
- AAAA - IPv6 Host
    
- PTR - Pointer
    
- MX - Mail Server
    
- CNAME - Alias  
      
    

- Internet servers often run BIND or Unix or Linux
    
- Queries to DNS server use UDP port 53
    
- Zone transfers between servers use TCP port 53
    

  

Why are Ports Important

  

- IP address used to locate hosts
    
- Port used to direct traffic to correct protocol/service or application
    

- Server ports
    
- Client ports
    

- Blocking ports blocks protocol traffic
    

  
  
  

Switches

  

- Physical security
    
- Switching Loop
    

- Caused if two ports connected together
    
- STP and RSTP protect against switching loops
    

- VLAN
    

- Logically group computers
    
- Logically separate/segment/isolate computers
    

  

Port Security/Authentication

  

- Disable unused ports
    
- MAC address filtering
    
- 802.1x port security (port authentication)
    

- Provides port-based authentication
    
- Prevents rogue devices from connecting
    
- Layer 2 technology configured on a switch
    

- 802.11 WLAN - Wireless Local Area Network standard
    

  
  
  

Access Control Lists (ACLs)

  

- List of rules to define access
    
- Identify what is allowed and what is not allowed
    
- ACLs often use an implicit deny policy
    

- NTFS uses a Discretionary ACL to identify who is allowed access to a file or a folder
    

- All others blocked
    

- Firewalls define what traffic is allowed
    

- Deny any rule blocks all other traffic
    
- Packet filtering
    

  

Routers

  

- Routers and ACLs
    

- Filter based on
    

- IP addresses and networks
    
- Ports
    
- Protocols
    

  

- Routers and firewalls
    

- Implicit deny (last rule in ACL)  
      
    

WAP (Wireless Access Point)

  

A WAP is a networking hardware device that allows a Wi-Fi device to connect to a wired network. It bridges the gap between the wired and wireless networks, enabling devices like laptops, smartphones, and tablets to connect to the local area network (LAN) without the need for physical cables.  
  

- Key Features:
    

- Wireless connectivity & wired connectivity
    
- SSID (Service Set Identifier):
    

- WAPs broadcast SSIDs, which are unique names that identify individual wireless networks.
    

- Security Features:
    

- WAPs often come with security features such as WPA2/WPA3 encryption, MAC address filtering, and the ability to set up guest networks.
    

- Channel Selection:
    

- WAPs operate on specific radio frequency channels within the 2.4 GHz and 5 GHz bands.  
      
    

- What they use:  
      
    Wireless Access Points use radio waves to transmit and receive data between devices and the wired network. The most common Wi-FI standards include 802.11a, 802.11b, 802.11g, 802.11h, 802.11ac, and 802.11ax (Wi-Fi 6).  
      
    The choice of standard affects factors like data transfer rates, range, and compatibility with devices.  
      
    
- Choosing a Wireless Network Mode:  
      
    

- Infrastructure Mode: In this mode, devices communicate through a central WAP. This is the most common mode and is suitable for most home and business networks.  
      
    
- Ad-Hoc Mode: In this mode, devices communicate directly with each other without the need for a central WAP. This mode is less common and is typically used for peer-to-peer communication.  
      
    
- Mixed Mode: This allows the WAP to support multiple wireless standards simultaneously. It can be useful if you have a variety of devices with different Wi-Fi capabilities.  
      
    
- Wireless Standards (802.11a/b/g/n/ac/ax): Choose the appropriate wireless standard based on the devices you have and the performance you need. Newer standards generally offer higher data transfer rates and better overall performance.  
      
    
- Frequency Band (2.4 GHz vs 5 GHz): WAPs operate on either the 2.4 GHz or 5 GHz bands. The 5 GHz band typically offers higher data transfer rates and less interference buy has a shorter range compared to the 2.4 GHz band.  
    

Screen Subnet new name for (DMZ)

  

DMZ (De Militarized Zone) is the zone between the two firewalls. On one side of the DMZ is the public network. On the other side of the DMZ is the private network. You can put any public facing servers like web server or email server in the DMZ.

  

- You should put the DB server or Sharepoint server behind the DMZ.
    

  

Web Application Firewall (WAF)

  

- Web based Firewall
    

- WAF focuses on the security of web applications, inspecting and filtering hTTP traffic. It is designed to detect and prevent attacks like SQL injection, cross-site scripting (XSS), and other web application vulnerabilities.
    

  

Proxies (Proxy Servers)

  

A basic proxy server provides for protocol-specific outbound traffic. For example, you might deploy a web proxy that enables client computers to connect to websites and secure websites on the Internet.

  

Web proxies are often also described as web security gateways as usually their primary functions are to prevent viruses or Trojans infecting computers from the Internet, block spam, and restrict web use to authorized sites.

  

- Caching content for performance
    
- Using URL filters to restrict access
    

  

UTM - Unified Threat Management

  

- Combines multiple security controls
    
- Reduces administrative workload
    
- Web security gateways
    
- UTM security appliances
    

- Firewall, antivirus protection, anti-spam protection, URL filtering, and content filtering.
    

  

OSI 7 Layer Model (People Dont Network To Simple Presentations Anymore)

  

Physical

- Physical structure
    
- Coax, Fiber, Wireless, Hubs, Repeaters
    

  
Data Link

- Frames
    
- Ethernet, PPP, Switch, Bridge
    

  

Network

- Packets
    
- IP, ICMP, IPSec, IGMP
    

  

Transportation

- End-to-End Connections
    
- TCP, UDP  
      
    

Session

- Synch & send to port
    
- API’s, Sockets, WinSock  
      
    

Presentation

- Syntax layer
    
- SSL, SSH, IMAP, FTP, MPEG, JPEG  
      
    

Application

- End User Later
    
- HTTP, FTP, IRC, SSH, DNS
    

  
  

Understanding IDSs and IPSs

  

- Intrusion Detection System (IDS)
    

- Detective control
    
- Attempts to detect attacks after they occur
    
- Ex: Your system is moving slower than usual after downloading an unreputable file. You can use an IDS such as Norton Antivirus to scan for threats.  
      
    
- IDS Detection Methods
    

- Signature-based
    

- Also called definition based
    
- Use a database of predefined traffic patterns such as a Common Vulnerabilities and Exposures (CVE) list  
      
    

- Firewall is a preventive control
    

- Attempts to prevent the attacks before they occur. Your firewall will alert you to potential threats and block you from accessing a potentially harmful website/file  
      
    

- Intrusion Prevent System (IPS)
    

- A preventive control
    
- Will stop an attack in progress
    
- Can be on network or host
    

  

- Network Intrusion Detection System (NIDS)
    
- Host Intrusion Detections System (HIDS)
    

  
  

There are three things that decide the choice of controls

  

4. Cost
    
5. Risk Appetite (What is acceptable risk)
    
6. Compliance Requirements
    

  

SIEM Security Information and Event Management (Splunk)

  

- It ingests, indexes, correlates, searches and visualizes the log data in real time.  
      
    
- If it is a known intrusion (known attack) go with signature based IDP/IPS.
    

  

- If it is an unknown brand-new attack (no patches, never seen it before) go with anomaly-based IDS/IPS (Behavior based or heuristic based)
    

  

- Brand new attacks for which there is no patch or no signature it is known as a Zero-day attack (Patient Zero Attack)
    

  

- For anomaly-based IDS/IPS to be effective, you need a very good current baseline.  
      
    
- Baseline tells you what is normal at a point in time.  
      
    
- Too many false positives results in alert fatigue.  
      
    
- If your baseline is outdated, you will be flooded with too many false positives and false negatives.
    

  
  
  
  

Packet Sniffing

  
  

- Also called protocol analyzer
    
- Captures and analyzes network traffic
    
- Wireshark - free packet sniffer
    
- IDSs and IPSs include packet sniffing capabilities
    

  

HoneyPots and HoneyNets

  

- A honeypot is a computer system intended to mimic likely targets of cyberattacks.
    
- A honeynet is a group of virtual servers contained within a single physical server, and the servers within this network are honeypots.
    

  

SIEM + SOAR

  

- SIEM collects the data SOAR responds to the incident and threat hunting
    
- SOAR - Security Orchestration, Automation and Response.
    

  

Wireless Standards

  

- 802.11n - uses MIMO (Multiple Input Multiple Output)
    
- There are three channels that do not overlap
    

- Channels 1, 6 and 11 are non overlapping and do not interfere with each other.
    

  

Wireless Antennas

  

- Isotropic - theoretical omnidirectional
    
- Dipole - omnidirectional
    
- Yagi - high gain directions
    
- Antenna power
    

- dBi, dBd, dBm
    

- Wireless footprint
    

  

Securing Wireless Networks

  

- WEP - Don’t use
    

- Multiple weaknesses. Uses weak RC4 40 bit encryption
    

- WPA - Interim replacement for WEP
    

- Uses TKIP and stronger that WEP
    

- WPA2 - Current standard
    

- Provides best security when used with AES/CCMP
    
- Uses AES 128 or 192 for encryption
    

- WPA/WPA2 Modes
    

- Personal
    

- Uses pre-shared key (PSK)
    
-   
    

- 802.1x (Enterprise mode)
    

- More secure than Personal mode
    
- Adds strong authentication
    
- Uses an 802.1x server (implemented as a RADIUS server) to add authentication
    

- WPA3 Personal uses SAE(Simultaneous Authentication of Equals) instead of PSK (Pre-shared Key)
    
- WPA3 Enterprise uses GCMP256 (Galois Counter Mode Protocol) instead of AES256 (Advanced Encryption Standard)
    
- Change default administrator password
    
- Consider MAC filtering
    
- Disable SSID Broadcast
    

  

EAP, PEAP, and LEAP

  

EAP-TLS is the most secure

LEAP - No certificate is required

  

Wireless Attacks

  

Wardriving

- Searching for open hotspots
    

  

Encryption Attacks

- WEP, TKIP, WPS
    

  

Rogue AP

- Unauthorized hotspot
    

  

Evil Twin

  

Evil Twin is a wireless attack in which they (hackers) stand up another WAP and they use the same name (SSID) as the original legitimate WAP. They jam the original one. And the clients start connecting to the fake one.

  

Disassociation

- Packet w/ spoofed address
    

  

Jamming

- Radio interference
    

  
  

Bluejacking

- Sends unsolicited messages  
      
    

Bluesnarfing

- Theft of information
    

  

NFC (Near Field Communications)

- Steal information or money
    

  

RFID (Radio Freq Identification)

- Longer range in some cases
    

  

Other Wireless Security Concerns

  

- Change the default Admin password
    
- Enable MAC Filtering
    

- MAC addresses can be spoofed
    

  

SSID

  

- SSID stands for Service Set IDentifier and is your wireless network’s name
    
- Change the default SSID
    
- Disabling SSID broadcast
    

- Hides from some devices
    
- Does not hide from attackers
    

  

OSI Model (Please Do Not Throw Sausage Pizza Away)

  

The OSI should be built from the group up. Everything works in Layers.

  

Application - Layer 7

- End User Layer
    
- HTTP, FTP, IRC, SSH, DNS  
      
    

Presentation - Layer 6

- Syntax Layer
    
- SSL, SSH, IMAP, FTP, MPEG, JPEG  
      
    

Session - Layer 5

- Synch & send to port
    
- API’s, Sockets, WinSock  
      
    

Transport - Layer 4

- End-to-end connections
    
- TCP, UDP  
      
    

Network - Layer 3

- Packets
    
- IP, ICMP, IPSec, IGMP  
      
    

Data Link - Layer 2

- Frames
    
- Ethernet, PPP, Switch, Bridge  
      
    

Physical - Layer 1

- Physical structure
    
- Coax, Fiber, Wireless, Hubs, Repeaters
    

  
  
  
  

Cyber Kill Chain

  

MITRE ATT&CK

  

Recon

- Research, identification, and selection of targets
    

  
Weaponization

- Pairing remote access malware with exploit into a deliverable payload (e.g. Adobe PDF and Microsoft Office files)
    

  
Delivery

- Transmission of weapon to target (e.g. via email attachments, websites, or USB drives)  
      
    

Exploitation

- Once delivered, the weapon’s code is triggered, exploiting vulnerable applications or systems.  
      
    

Installation

- The weapon installs a backdoor on a target’s system allowing persistent access.  
      
    

Command & Controls

- Outside server communicates with the weapons providing “hands on keyboard access” inside the target’s network.  
      
    

Exfiltration

- The attacker works to achieve the objective of the intrusion, which can include exfiltration or destruction of data, or intrusion of another target.
    

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

Securing Hosts and Data

  
  

EDR (Endpoint Detection and Response

  

It is the software that you install on your endpoint that will protect your device from malware or any zero day attacks.

  

Eg. McAfee HBSS, Crowdstrike, Sentinel1, Carbon Black (VMware)

  

Implementing Host Security

  

- Hardening systems
    

- Disabling unnecessary services
    

- Improves security posture
    
- Reduce attack surface
    
- Reduces risks from open ports
    

- Disabling unneeded applications
    
- Disabling unnecessary accounts do not delete
    
- Protecting management interfaces and applications
    

  

Using Baselines

  
Baselines tell you what is normal at any point in time.

- Improve overall security posture
    
- Three steps:
    

4. Initial baseline configuration  
    Start in secure state
    
5. Continuous security monitoring  
    Scan for and detect changes
    
6. Remediation  
    Isolate or quarantine modified systems  
      
    

Security Baselines

  

- Enforce with Group Policy Objects (GPO)
    

- Standardize system configuration
    
- Standardize security settings
    
- Enforce strict company guidelines
    
- Easily apply security settings to multiple computers
    

  
  
  
  

Configuration Baselines

  

- Identifies and documents configuration settings
    

- OS and application settings
    
- Network settings
    

- Must be kept up-to-date
    

- Update documentation when the system is updated
    

- CMDB
    

- Allows you to track and manage all the changes centrally
    

  

Host and Application Baselines

  

- Host software baseline
    

- Provide a list of approved software and a list of installed software
    
- Can be used to identify unauthorized software  
      
    

- Application configuration baselines
    

- Identifies proper settings for applications
    
- Can be used for auditing  
      
    

Baselines

  

- Performance Baselines
    

- Documents normal system performance
    
- Compare current performance against a baseline
    

  
  

Imaging

  

- Provides secure starting point
    

- Reduces costs
    
- Allows you to provision multiple computers' performance against a baseline report to determine abnormal activity.  
      
    

- Baseline Reporting
    

- Provides a report after comparing baselines
    
- Administrators use baseline reporting for multiple types of baseline comparisons  
      
    

Whitelisting vs Blacklisting

  

- Application whitelisting
    

- Identifies authorized software for workstations, servers, and mobile devices
    
- Prevents users from installing or running software that isn’t on the list.
    

  

- Application blacklisting
    

- A list of prohibited applications
    
- Prevents users from installing or running software on the list
    

  

Patch Management

  

- Ensure that systems are up-to-date
    
- Protects system against known vulnerabilities
    
- Test patches in a test environment that mirror the production environment
    
- Automated deployment
    
- Controlled deployment
    
- Scheduling patch management
    
- Testing, deploying and verifying updates
    
- Sandbox is a staging environment. 
    

  

Operational Technology (OT)

  

- Operational Technology refers to commuting systems that are used to manage industrial operations. Operational systems include production line management, mining operations control, oil & gas monitoring etc.
    

  

- Industrial control systems (ICS) is a major segment within the operational technology sector. It comprises systems that are used to monitor and control industrial processes. This could be mine site conveyor belts, oil refinery cracking towers, power grid etc.  
      
    
- Most ICSs fall into either a continuous process control system, typically managed via programmable logic controllers (PLCs), or discrete process control systems (DPC), that might use a PLC or some other batch process control device.  
      
    
- Industrial control systems (ICS) are often managed via a Supervisory Control and Data Acquisition (SCADA) system that provides a graphical user interface for operators to easily observe the status of a system, receive any alarms indicating out-of-band operation, or to enter system adjustments to manage the process under control.
    

  
  
  
  
  
  
  
  
  
  
  

SoC, RTOS, SCADA

  

System on a Chip (SoC)

  

A tiny computer that has everything it needs to work right on a single chop, like a mini-brain with memory, processors, and other essential components all packed together.  
  

- Raspberry-Pi  
      
    

  

Real Time Operating Systems (RTOS)

  

A RTOS as a super organized traffic cop for a computer. It makes sure tasks are done on time, like stopping at a red light in traffic, ensuring things happen when then should.

  

SCADA (Supervisory Control and Data Acquisition System) / HVAC Control

  

Picture a master controller overseeing a big factory. SCADA helps monitor and control everything, like temperature, pressure, and machines, so the factory runs smoothly.

  

Securing Mobile Devices

  

- Full disk encryption
    
- Authentication and device access control
    
- GPS tracking
    
- Removable storage
    
- Storage segmentation
    
- Screen locks
    
- Lockout
    
- Remote wiping
    
- Disabling unused features
    

  

BYOD Concerns

  

- Bring your own device (Employee-owned)
    

- Asset tracking and inventory control
    
- Architecture/infrastructure considerations
    
- Forensics
    
- Legal Concerns
    
- On-boarding/off-boarding
    
- On-board camera/video
    

  
  
  

Mobile Device Management (MDM)

  

- Ensure mobile systems are up to date
    

- Current patches
    
- Up-to-date antivirus
    

- Block devices that are not up to date
    
- Include:
    

- Patch management
    
- Antivirus management
    
- Application control
    

- Mobile Containerization
    
- Capable of Remote Wiping
    

  

Mobile Application Security

  

- Authentication
    
- Credential management
    
- Geo-tagging
    

- Adds geographical info to pictures
    

- Geofence
    

- A virtual geographic boundary, defined by GPS or RFID technology.
    

  

Mobile Device Deployment Models

  

Bring Your Own Device (BYOD)

  

- The mobile is owned by the employee.  
      
    

Corporate Owned, Business Only (COBO)

  

- The device is the property of the company and may only be used for company business.
    

  

Corporate Owned, Personally-Enabled (COPE)

  

- The device is chosen and supplied by the company and remains its property.
    

  

Choose Your Own Device (CYOD)

  

- The employee gets to choose what device they want from the organization.
    

  

Rooting, Jailbreaking and Sideloading

  

- Rooting: This term is associated with Android devices
    
- Jailbreaking: iOS is more restrictive than Android. Jailbreaking allows the user to obtain root privileges, sideload apps, change or add carriers, and customize the interface.  
      
    
- Carrier unlocking: For either iOS or Android. Removes carrier restrictions.
    

  

Hardware-Based Encryption

  

- TPM
    

- Trusted Platform Module
    
- Chip in motherboard (included with many laptops
    
- Full disk encryption
    

- HSM
    

- Removable or external hardware device.
    
- For high-end mission-critical servers
    

  

Data Leakage (Loss) Prevention (DLP)

  

- Data-in-motion
    

- Scans emails and attachments
    
- Detects outgoing confidential company data
    

- Endpoint Protection
    

- Scans for content going to devices
    
- Prevents users from copying certain data to USB drives
    
- Prevents users from sending certain data to printers
    

  

Viruses

- Replication mechanism
    
- Activation mechanism
    
- Payload
    
- Armored virus
    

- Difficult to reverse engineer
    
- Use complex code, encrypt the code, or hide their location
    

- Polymorphic malware
    

- Morphs or mutates when it replicates
    

  

Understanding Malware

  

Worms

- Self replication
    

  

Logic Bombs

- Executes in response to an event
    

  
  

Fileless Malware in Memory

- Characteristics of a Fileless Attack
    

- Has no identifiable code or signature and particular behavior that traditional security software detects.
    
- Is a memory-based threat, residing in the computer’s RAM.
    
- Takes advantage of processes in the system to facilitate an attack
    
- Could be used with other kinds of malware
    
- Could bypass whitelisting
    

  

PUP

- Potentially Unwanted Produced
    
- PUPs may include features or functionalities that users didn’t explicitly request or that may not be transparent during the installation process
    

  

Backdoors

- Provides an alternate method of access
    
- Many types of malware create backdoors
    

  

Logic Bomb Attack

  

Some viruses do not trigger automatically. Having infected a system, they wait for a preconfigured time or date (time bomb) or a system or user event (logic bomb).

  

Trojan Horse

- Appears to be useful but is malicious
    
- Pirated software, rogueware, or games
    
- Also infect systems via USB drives
    

  

Drive-by downloads

5. Attackers comprise a website to gain control of it
    
6. Attackers install a Trojan embedded in the website’s code
    
7. Attackers attempt to trick users into visiting the site
    
8. When users visit, the web site attempts to download the Trojan onto the users systems
    

  

Backdoors

  

A backdoor is a remote access method that is installed without the user’s knowledge.

  

Botnets

- Controlled by criminals called bot herders
    

- Manage command and control centers
    
- Malware joins computers to robotic network
    

- Zombies or clones
    

- Computers within botnet
    
- Join after becoming infected with malware
    

  

Ransomware

- Takes control of user’s system
    
- Attempts to extort payment
    
- The Police Virus
    
- CryptoLocker
    

  

Cryptomining/Cryptojacking

- Hijack resources to mine cryptocurrency
    

  

Keylogger

- Software and hardware
    

  

Rootkits

- System level or kernel access
    
- Can modify system files and system access
    
- Hide their running processes to avoid detection with hooking techniques
    
- File integrity checker can detect modified files
    
- Inspection of RAM can discover hooked processes
    

  

Downgrade attack

- Forces server into using weak protocol versions and ciphers (POODLE Attack - Downgrading SSL)
    

  

Spyware

- Can access a users private data and result in loss of confidentiality  
      
    

Adware

- Pop-ups that market products to users
    
- Blocked with pop-up blockers  
      
    

Social Engineering

  

- Flattery and conning
    
- Assuming a position of authority  
      
    
- Encouraging someone to:
    

- Perform a risky action
    
- Reveal sensitive information  
      
    

- Impersonating
    
- Tailgating
    
- Dumpster Diving
    
- Shoulder Surfing
    
- Tricking users with hoaxes
    

  

Spoofing

  

- IP address
    
- MAC address
    
- Email address
    
- Caller ID
    

  

Redirection

  

- ARP (Address Resolution Protocol)
    

- Usually performed by inside attackers
    

- DNS poisoning
    

- More difficult but works on large networks
    

- Pharming
    

- Similar to phishing put with compromised DNS
    

- Domain hijacking
    

- Redirects traffic for site to an imitator
    

- VLAN hopping
    

- Bypasses VLAN segmentation
    

  

Common Attacks

  

- Spoofing
    

- Impersonating or masquerading as someone or something else
    

- Denial-of-Service (DoS)
    

- Comes from one system
    

- Distributed Denial-of-Service (DDoS)
    

- Multiple attacking computers
    
- Typically include sustained, abnormally high network traffic 
    
- You can use a IPS to prevent
    
- Blackhole:
    

- Drop packets for the affected IP address(es).
    

- Sinkhole:
    

- Traffic flooding an IP can be routed to another network for review.
    

- Smurf
    

- A ping is normally unicast
    
- Smurf attack sends the ping out as a broadcast
    
- Smurf attack spoofs the source IP
    
- Directed broadcast through an amplifying network
    
- Disable directed broadcasts on border routers
    

- SYN flood attack
    

- Common attack against internet servers
    
- disrupts the TCP three-way handshake
    
- Withholds 3rd packet
    
- Flood guards protect against SYN flood attack
    

- XMAS Attack
    

- Christmas Tree Exam is a very well known attack, designed to send a very specifically crafted TCP packet to a device on the network.
    
- Turns on the Urgent, Push & Fin flags
    
- Certain sections of a TCP packet are lit up like a Christmas Tree
    

  

Password Attacks

  

- Brute force
    

- Prevent with account lockout policies
    

- Dictionary
    

- Prevent with complex passwords
    

- Birthday
    

- Prevent with strong hashing
    

- Rainbow table
    

- Prevent with salted hashes
    
- Salting
    

- Add a random value to each password when hashing it for storage
    
- Prevents use of pre-computed hash tables
    

- Hybrid
    

  

Pass The Hash Attack

- Exploiting cached credentials to perform lateral movement
    
- Windows hosts cache credentials in memory as NTLM hashes
    
- Local malicious process with administrator privileges can dump these hashes
    

  
  
  
  
  
  
  
  
  
  
  
  
  
  
  

Managing Risk

  
  
  

Identifying Risk

  

- Risk
    

- Likelihood that a threat will exploit a vulnerability
    

- Vulnerabilities
    

- Weaknesses
    

- Threats
    

- Potential danger
    

- Impact
    

- Magnitude of harm
    
- Risk = T * V * I
    

  

Threat

- Event that compromises confidentiality, integrity, or availability
    
- Natural threats
    
- Human threats
    

- Malicious
    
- Accidental  
      
    

- Environmental threats
    
- Malicious insider threats  
      
    

Threat Vector

- Also called attack vector
    

- Refers to the method used to activate the threat
    

- External (outsiders)
    
- Internal (Insiders)
    
- Supply chain  
      
    

- Threat Assessments
    

- Identify and categorize threats
    

  

Risk Management

- Practice of identifying, monitoring, and limiting risks to a manageable level
    
- Cannot eliminate risks
    
- Amount of risk that remains after managing risk is residual risk
    

  
  
  
  

ARO (Annualized Rate of Occurrence)  
  

- ARO represents the estimated frequency at which a specific risk event is expected to occur in a year.  
      
    
- Calculation:
    

- ARO is calculated as the reciprocal of the mean time between occurrences (MTBF - Mean Time Between Failures). If an event occurs on average once every X years, the ARO is 1/X.  
      
    

ALE (Annualized Loss Expectancy)  
  

- ALE is a measure of the expected financial loss from a specific risk in a year, considering the potential impact and the ARO.  
      
    
- Calculation:
    

- ALE is calculated by multiplying the Single Loss Expectancy (SLE) by the ARO. It helps organizations quantify the potential financial impact of a risk over time.  
      
    

SLE (Single Loss Expectancy)

  

- SLE represents the estimated financial loss associated with a single occurrence of a specific risk event.  
      
    
- Calculation:
    

- SLE is calculated by multiplying the asset value (AV) by the exposure factor (EF). Mathematically, SLE = AV*EF  
      
    

AV (Asset Value)

  

- The total value of the asset that is at risk. This could be tangible assets (e.g., hardware) or intangible assets (e.g., data).  
      
    

EF (Exposure Factor)  
  

- The percentage of the asset value that would be lost if a specific risk event occurs. It is expressed as a percentage.  
      
    

  
  
  
  
  
  

Risk Assessments

  

- Documenting the assessment
    
- Results valuable
    

- Help organization evaluate threats and vulnerabilities
    
- Should be protected
    
- Only accessible to management and security professionals
    

  

Cyber Security Risk Register

  

A risk register is a document showing the results of risk assessments in a comprehensible format.

  

Automated security tools

  

- Device or system config tools
    
- COntinuous monitoring and alert systems
    
- Configuration validations tools
    
- Vulnerability scanners
    
- Remediation tools
    
- Patch management software
    
- Automated troubleshooters
    
- Application testers
    

  

Passive & Active Recon

  

- Passive Recon involves acquiring information without directly interacting with the target.  
      
    
- Active reconnaissance involves interacting with the target directly by any means.
    

  

Nation State Attacks / APT Attacks

  

Vulnerability Assessment

  

- Determines the security posture of a system
    
- Identifies vulnerabilities and weaknesses
    

- Identify assets and capabilities
    
- Prioritize assets based on value
    
- Identify vulnerabilities and prioritize them based on severity
    
- Recommend controls to mitigate serious vulnerabilities
    

  

Types of Scanning

  

Credentialed vs Non-Credentialed Scanning

  

- Non-credentialed
    

- Anonymous or guest access to host only
    
- Might test default passwords
    

- Credentialed
    

- Scan configured with logon
    
- Can allow privileged access to configuration settings/logs/registry
    
- use dedicated account for scanning
    

  

Pen Testing

  

- Black box testing
    

- Testers have zero knowledge of the environment prior to the test
    
- Often use fuzzing
    

- White box testing
    

- Testers have full knowledge of the environment
    

- Gray box testing
    

- Testers have some knowledge of the environment
    

  

Server Redundancy

  

- Active - Active Clustering for Load balancing for high availability
    
- Increases overall processing power
    
- Shares load among multiple servers
    

  

Business Impact Analysis

  

- Recovery Time Objective (RTO)
    

- Identifies maximum amount of time it should take to restore a system after an outage
    
- Derived from maximum allowable outage time identified in the BIA
    

- Recovery Point Objective (RPO)
    

- Refers to the amount of data an organization can afford to lose
    

- BIA does not identify solutions
    
- BIA helps an organization develop the BCP (Business Continuity Plan)
    

- Drives decisions to create redundancies such as failover clusters or alternate sites
    

  

Fire Suppression

  

- HVAC systems
    

- Should be integrated with the fire alarm systems
    
- Have dampers or the ability to be turned off in the event of a fire
    

- Extinguish Fire
    

- Remove the heat
    
- Remove the oxygen
    
- Remove the fuel
    
- Disrupt chain reaction
    

  

FM-200 and FE-13 are Safe

  

- Dry-pipe
    

- These are used in areas where freezing is possible; water only enters this part of the system if sprinklers elsewhere are triggered.
    

- Pre-action
    

- A pre-action system only fill with water when an alarm is triggered
    

- Halon
    

- Gas-based systems have the advantage of not short circuiting electrical systems and leaving no residue. Up until a few years ago, most systems used Halon 1301. It has now been banned for depleting the ozone.  
      
    

- Clean agent
    

- Alternatives to Halon are referred to as “clean agents”. As well as not being environmentally damaging, these gasses are considered non-toxic to humans.
    
- Examples:
    

- INERGEN (a mixture of CO2, Argon, and Nitrogen)
    
- FM-200
    
- HFC-227
    
- FE-13
    

  

Providing Confidentiality with Encryption

  

- Encryption provides confidentiality
    

- Helps ensure only authorized users can view data
    
- Applies to any type of data
    

- Data at rest/Data stored in a database
    
- Data in motion sent over a network
    
- Data in Use  
      
    

- Two basic components of encryption
    

- Algorithm
    

- Performs mathematical calculations of data
    
- Algorithm always the same
    

- Key
    

- A number that provides variability
    
- Either kept private and/or changed frequently
    

  

Cryptography Concepts - Confidentiality

  

- Ensures only authorized users can view data
    
- Encryption protects the confidentiality of data
    
- Encryption ciphers data to make it unreadable
    
- Encryption normally includes algorithm and key  
      
    
- Symmetric encryption
    

- Uses the same key to encrypt and decrypt data
    

- Can cause issues as anyone with the key can encrypt/decrypt  
      
    

- Advanced Encryption Standard (AES)
    

- Fast, efficient, strong symmetric block cipher
    
- 128-bit block cipher
    
- Uses 128-bit, 192-bit, 256-bit keys  
      
    

- Widely used
    

- Provides a high level of confidentiality
    
- Selected in NIST competition
    
- Adopted by U.S. Government  
      
    

- Data Encryption Standard (DES)
    

- 64-bit block cipher
    
- Uses 56-bit keys and should not be used today  
      
    

- 3DES (3 Data Encryption Standard)
    

- 64-bit block cipher
    
- Originally designed as a replacement for DES  
      
    

- Asymmetric encryption
    

- Uses two keys (public and private) created as a matched pair
    

  

Digital Signature

  

- Encrypted hash of a message
    

- The sender’s private key encrypts the hash
    
- Recipient decrypts hash with sender’s public key
    
- Does not provide confidentiality
    
- Provides:
    

- Authentication - Identifies the sender
    
- Integrity - verifies the message has not been modified
    
- Non-repudiation - prevents the sender from denying the action
    

  

Protecting Email

  

- S/MIME (Secure Multipurpose Mail Extensions)
    
- PGP (Pretty Good Privacy)
    
- Both:
    

- Use RSA algorithm
    
- Use public and private keys for encryption and decryption
    
- Depend on a Public Key Infrastructure (PKI) for certificates
    
- S/MIME helps with encryption of data at rest as well as data in motion.
    
- Can digitally sign and encrypt email
    

- Including email encryption at rest and in transit
    
- Ensures integrity of original email message
    

  

Exploring PKI Components

  

- Public Key Infrastructure (PKI)
    

- Includes components required for certificates
    
- Allows two entities to privately share symmetric keys without any prior communication  
      
    

- Certificate Authority (CA)
    

- Issues, manages, validates, and revokes certificates  
      
    

Digital Certificates

  

- Used for encryption, authentication and digital signature
    
- Includes:
    

- Serial number
    
- Issuer
    
- Validity dates
    
- Subject
    
- Public Key
    
- Usage
    

  

Certificate Signing Request

  

- A CSR or Certificate Signing Request is a block of encoded text that is given to a Certificate Authority when applying for an SSL Certificate.
    

  

- A Private Key is usually created at the same time that you create the CSR, making a key pair.  
      
    
- A CA will use a CSR to create your SSL certificate, but it does not need your private key.
    

  

CSR - Subject Alternate Name (SAN)

  

- SubjectAltName specifies additional subject identities. Subject Alternative Name (SAN) is an extension to X.509 that allows various values to be associated with a security certificate using a subjectAltName field. These values are called SUbject Alternative Names (SANs).  
      
    Names include:
    

- Email addresses
    
- IP addresses
    
- URLs
    
- DNS names: this is usually also provided as the Common Name RDN within the SUbject field of the main certificate.
    
- Directory names: alternative Distinguished Names to that given in the Subject.  
      
    

CSR - CommonName & ExtendedKeyUsage  
  

- CommonName:  
      
    

- The fully qualified domain name (FQDN) of your server. This must match exactly what you type in your web browser or you will receive a name mismatch error.  
      
    

- ExtendedKeyUsage (EKU) is a method of enforcing the public key of a certificate to be used for a predetermined set of key purposes.  
      
    
- There can be one or more such key purposes defined. This extension is usually defined by the end entity systems in their certificates to support their security design constraints.  
      
    
- When EKU is present in a certificate, it implies that the public key can be used in addition to or in place of the basic purposes listed in the key usage extension. The EKU extension is always tagged as critical.
    

  

Certificate Signing Request (CSR) - Extensions and Values

  

Extension Value

extendedKeyUsage serverAuth

commonName ws01.comptia.org

policyIdentifier URL=[http://homesite.comptia.org/home.aspx](http://homesite.comptia.org/home.aspx)

subjAltName DNS Name=homesite.comptia.org

  

Revoking Certificates

  

- Reasons
    

- Key or CA Compromise Employee Leaves
    
- Change of Affiliation Superseded
    
- Cease of Operation Certificate Hold  
      
      
    

- Revoked certificates
    

- Revoked by serial number
    
- Published in Certificate Revocation List (CRL)
    
- Publicly available
    

  

Certificate Pinning

  

- Certificate pinning is when an application has hard-oded the server’s certificate into the application itself. An application which pins a certificate or public key no longer needs to depend on others - such as DNS or CAs = when making security decisions relating to a peer’s identity.
    

  
  

Wildcard vs SAN Certificate

  

Wildcard SSL SAN (UCC) SSL

[www.domain.com www.domain.com](http://www.domain.com)

news.domain.com domain.org

blog.domain.com blog.domain.com

pic.domain.com www.domain.co.uk

  

Passwordless Authentication 

  

1. Generate a Public/Private Keypair on your Linux Desktop
    

1. Run the following command to generate RSA public and private keys for the first node. -t stands for type. The below command generates a RSA type keypair. RSA is the default type, so you can also type ssh-keygen in the terminal. By default the key is 2048 bits long.
    
2. ssh -keygen -t rsa
    
3. You will now have two files in ~/.ssh: id_rsa & id_rsa.pub
    
4. The file: id_rsa.pub is your public key and it is that which will be sent to the server and put into the authorized_keys file.
    
5. The file: id_rsa is your private key and must NOT be sent up to the server.  
      
    

3. Upload your Public Key to Remote Linux Server.
    

1. This can be easily done with the ssh-copy-id command, which is shipped by the openssh-client package.
    
2. The quickest way to copy your public key to the Ubuntu host is to use a utility called ssh-copy-id. Now copy the authorized keys.
    
3. ssh-copy-id -i ~/.ssh/id_rsa.pub user@server
    
4. After entering your password, the content of your id_rsa.pub key will be copied to the end of the authorized_keys file of the remote user’s account.
    
5. The public key is stored in .ssh/authorized_keys file under the remote user’s home directory.  
      
    

5. Verify that you can login and everything works okay.
    

1. Now ssh into the remote server and verify that you are able to login.
    
2. ssh -i ~/.ssh/id_rsa user@server
    

  

Recording Time Offset using NTP Network Time Protocol

  

- Uses UTC Coordinated Universal Time
    

  

SDLC - Waterfall vs Agile

  
  
  

Confidentiality         Integrity

  

RED fishES

  

A     S H

RSA AES MD5 & SHA1

ECC Blowfish & Twofish SHA512

Diffie Hellman DES & 3DES NTLM

  
**