#acronyms 
1. A security expert is performing a risk assessment. She is seeking information to identify the number of times a specific type of incident occurs per year. Which of the following BEST identifies this?

	**ARO**
		The annual rate of occurrence
	
	- ALE - Annual Loss Expectancy
		- Identifies the expected monetary loss for a year and SLE 
	
	- SLE - Single Loss Expectancy
		- Identifies the expected monetary loss for a single incident
	
	- WORM - Write Or Read Many
		- A WORM is a term sometimes used with archived logs indicating they cannot be modified

2. Lis needs to calculate the ALE for a group of servers used in the network. During the past two years, five of the servers failed. The hardware cost to repair or replace each server was $3500 and the downtime resulted in $2500 of additional losses for each outage. What is the ALE?

	**$15000**
	
	The ALE is 15000. The single loss expectancy is $6000 ($3500 to repair or replace each server plus $2500 in additional losses for each outage). The ARO is 2.5 (five failures in two years or 5/2). You calculate the ALE as SLE x ARO ($6000 x 2.5)
	
	The amount of failures / the year(s)  

3. Martin is performing a risk assessment on an ecommerce web server. While doing so, he created a document showing all the known risks to this server, along with the risk score for each risk. What is the name of this document?  

	**Risk register  
	
	A risk register lists all known risks for an asset, such as a web server, and it typically includes a risk score (the combination of the likelihood of occurrence and the impact of the risk).  
	
	Risk assessments (including quantitative and qualitative risk assessments) might use a risk register, but they aren't risk registers.  
	
	Residual risk refers to the remaining risk after applying security controls to mitigate a risk.  


4. Your organization includes an ecommerce web site used to sell digital products. You are tasked with evaluating all the elements used to support this web site. What are you performing?  

	**Supply chain assessment  


5. A penetration tester is running several tests on a server within your organization's DMZ. The tester wants to identify the operating system of the remote host. Which of the following tools or methods are MOST likely to provide this information?  

	**Banner grabbing  


6. You need to perform tests on your network to identify missing security controls. However, you want to have the least impact on systems that users are accessing. Which of the following tools is the BEST to meet this need?  

	**Vulnerability scan  


7. You periodically run vulnerability scans on your network, but have been receiving many false positives. Which of the following actions can help reduce the false positives?  

	**Run the scans as credentialed scans  
	
	Running the scan as credentialed scans (within the context of a valid account) allows the scan to see more information and typically results in fewer false positives.  
	
	Non-credentialed scans run without any user credentials and can be less accurate.  
	
	Passive reconnaissance collects information on a target using open-source intelligence.  
	
	All vulnerability scans use active reconnaissance techniques.  


8. Your organization has a legacy server running within the DMZ. It is running older software that is not compatible with current patches, so management has decided to let it remain unpatched. Management wants to know if attackers can access the internal network if they successfully compromise this server. Which of the following is the MOST appropriate action?  

	**Perform a penetration test  

9. A penetration tester has successfully attacked a single computer within the network. The tester is now attempting to access other systems within the network via this computer. Which of the following BEST describes the tester’s current actions?  

	**Pivoting  
	
	Pivoting is the process of accessing other systems through a single compromised system. Reconnaissance techniques are done before attacking a system.  
	
	A successful attack on a single computer is the initial exploitation.  
	
	Escalating privileges attempts to gain higher privileges on a target.  


10. You are troubleshooting issues between two servers on your network and need to analyze the network traffic. Of the following choices, what is the BEST tool to capture and analyze this traffic?  

	**Protocol analyzer  
	
	A protocol analyzer (also called a sniffer) is the best choice to capture and analyze network traffic.  
	
	A network mapper can detect all the devices on a network.  
	
	A network scanner can detect more information about these devices.  
	
	Neither of these tools is the best choice to capture and analyze traffic for troubleshooting purposes.  
	
	A Security Information and Event Management (SIEM) system aggregates and correlates logs from multiple sources, but does NOT capture network traffic.  


11. A penetration tester is tasked with gaining information on one of your internal servers and he enters the following command:  

	**echo “l nc -vv -n -w1 72.52.206.134 80** 
	
	What is the purpose of this command?  
	
	Identify if a server is running a service using port 80 and is reachable.  

12. You suspect that an attacker has been sending specially crafted TCP packers to a server trying to exploit a vulnerability. You decide to capture TCP packets being sent to this server for later analysis and you want to use a command-line tool to do so. Which of the following tools will BEST meet your needs?  

	**tcpdump

	The tcpdump command-line tool is the best choice of the given answers. tcpdump is a powerful command-line packet analyzer tool used in Unix-like operating systems (including Linux and macOS) to capture and display network traffic in real-time, filter packets based on various criteria, and save the captured data for later analysis. tcpdump is particularly useful for troubleshooting network issues, monitoring network activity, and security analysis.  


13. You suspect someone has been trying a brute force password attack on a Linux system. Which of the following logs should you check to view failed authentication attempts by users?  

	**/var/log/btmp  
	
	The /var/log/btmp log contains information on user failed login attempts. While not available as an answer, /var/log/auth also includes information on failed login attempts. While the /var/log/faillog log includes information on failed logins, /var/log/fail isn’t a valid name in Linux.  
	
	The /var/log/http directory includes logs from the Apache web server, when it’s installed.  
	
	The /var/log/kern log contains information logged by the system kernel.  


14. An organization has a large network with dozens of servers. Administrators are finding it difficult to review and analyze the logs from all the network devices. They are looking for a solution to aggregate and correlate the logs. Which of the following choices BEST meets this need?  

	**SIEM (Security Information and Event Management) [[C.I.A Triad#^SIEM]]
	
	A security information and event management system provides a centralized solution for collecting, analyzing, and managing data from multiple sources and can aggregate and correlate logs.  

15. Lisa has recently transferred from the HR department to payroll. While browsing file shares, Lisa notices she can access the HR files related to her new coworkers. Which of the following could prevent this scenario from occurring?  

	**Permission auditing and review  

16. After a recent attack on your organization’s network, the CTO is insisting that the DMZ uses two firewalls and they are purchased from different companies. Which of the following BEST describes this practice?  

	**Vendor diversity  

17. Management within your organization wants to create a small network used by executives only. They want to ensure that this network is completely isolated from the main network. Which of the following choices BEST meets this need?  

	**Airgap  

	An airgap ensures that a computer or network is physically isolated from another computer or network.  

	A mantrap helps prevent unauthorized entry and is useful for preventing tailgating.  
	
	Control diversity is the use of different controls such as technical, administrative, and physical, but it doesn’t necessarily isolate networks.  
	
	Infrared motion detectors sense motion from infrared light, but they don’t isolate networks.  

18. A security professional has reported an increase in the number of tailgating violations into a secure data center. Which of the following can prevent this?  

	**Mantrap  

19. Lisa is the new chief technology officer (CTO) at your organization. She wants to ensure that critical business systems are protected from isolated outages. Which of the following would let her know how often these systems will experience outages?  

	**MTBF  
	
	The Mean Time Between Failures (MTBF) provides a measure of a system’s reliability and would provide an estimate of how often the systems will experience outages.  
	
	The Mean Time To Recover (MTTR) refers to the time it takes to restore a system, not the time between failures.  
	
	The Recovery Time Objective (RTO) identifies the maximum amount of time it can take to restore a system after an outage.  
	
	The Recovery Point Objective (RPO) identifies a point in time where data loss is acceptable.  

20. Thieves recently rammed a truck through the entrance of your company’s main building. During the chaos, their partners proceeded to steal a significant amount of IT equipment. Which of the following choices can you use to prevent this from happening again?  

	**Bollards  
	
	Bollards are effective barricades that can block vehicles. Guards can restrict access for personnel, but they cannot stop trucks from ramming through buildings.  


21. You are a technician at a small organization. You need to add fault-tolerance capabilities within the business to increase the availability of data. However, you need to keep costs as low as possible. Which of the following is the BEST choice to meet these needs?  

	**RAID-10 [[RAID#^RAID10]]  

22. Flancrest Enterprises recently set up a web site utilizing several web servers in a web farm. The web farm spreads the load among the different web servers. Visitor IP addresses are used to ensure that clients always return to the same server during a web session. Which of the following BEST describes this configuration?  

	**Affinity  
	
	Source address IP affinity scheduling allows a load balancer to direct client request to the same server during a web session.  
	
	Round-robin scheduling simply sends each request to the next server.  
	
	Load balancers can use a virtual IP, but this refers to the IP address of the web server, not the IP address of a visitor.  
	
	An active-passive configuration has at least one server that is not actively serving clients.  
	
	The scenario doesn’t indicate any of the servers are in a passive mode.  


23. Your organization is planning to deploy a new ecommerce web site. Management anticipates heavy processing requirements for a back-end application. The current design will use one web server and multiple application servers. Which of the following BEST describes the application servers?  

	**Load balancing

24. Flancrest Enterprises recently set up a web site utilizing several web servers in a web farm.The web farm spreads the load among the different web servers by sending the first request to one server, the next request to the second server, and so on. Which of the following BEST describes this configuration?  

	**Round-Robin  

25. Flancrest Enterprises recently set up a website utilizing several web servers in a web farm. The web servers access a back-end database. The database is hosted by a database application configured on two database servers. Web servers can access either of the database servers. Which of the following BEST describes the configuration of the database?  

	**Active-Active  

26. Your organization has decided to increase the amount of customer data it maintains and use it for targeted sales. However, management is concerned that they will need to comply with existing laws related to PII. Which of the following should be completed to determine if the customer data is PII?  

	**Privacy threshold assessment  

	A privacy threshold assessment helps an organization identify PII within a system, and in this scenario it would help the organization determine if the customer data is PII.  
	
	A privacy impact assessment is done after you have verified that the system is processing PII, not to determine if the data is PII.  

27. Your backup policy for a database server dictates that the amount of time needed to perform backs should be minimized. Which of the following backup plans would BEST meet this need?  

	**Full backups on Sunday and incremental backups on the other six days of the week  
	
	Differential backups become steadily larger as the week progresses and take more time to back up then incremental backups.  
	
	Backups must start with a full backup, so a differential/incremental backup strategy is not possible.  


28. You are helping implement your company’s business continuity plan. For one system, the plan requires an RTO of five hours and an RPO of one day. Which of the following would meet this requirement?  

	**Ensure the system can be restored within five hours and ensure it does not lose more than one day of data.  

29. A security analyst is creating a document that includes the expected monetary loss from a major outage. She is calculating the potential impact on life, property, finances, and the organization’s reputation. Which of the following documents is she MOST likely creating?  

	**BIA  

	A Business Impact Analysis (BIA) includes information on potential monetary losses along with the impact on life, property, and the organization's reputation.  


30. A security expert at your organization is leading an on-site meeting with key disaster recovery personnel. The purpose of the meeting is to perform a test. Which of the following BEST describes this test?  

	**Tabletop exercise  

31. Bart recently sent out confidential data via email to potential competitors. Management suspects he did so accidentally, but Bart denied sending the data. Management wants to implement a method that would prevent Bart from denying accountability in the future. Which of the following are they trying to enforce?  

	**Non-repudiation  

32. A software company occasionally provides application updates and patches via its web site. It also provides a checksum for each update and patch. Which of the following BEST describes the purpose of the checksum?  

	**Integrity of updates and patches  

33. A one-way function converts data into a string of characters. It is not possible to convert this string of characters back to the original state. What type of function is this?  

	**[[Hashing]]**

34. An application developer is working on the cryptographic elements of an application. Which of the following cipher modes should NOT be used in this application?  

	**ECB  

	The Electronic Cookbook (ECB) mode of operation encrypts blocks with the same key, making it easier for attackers to crack.  

	CTM, CBC & GCM are secure and can be used  

35. Which of the following is a symmetric encryption algorithm that encrypts data 1 bit at a time?  

Stream Cipher  

A stream cipher encrypts data a single bit or a single byte at a time and is more efficient when the size of the data is unknown, such as streaming audio or video.  

A block cipher encrypts data in specific-sized blocks, such as 64-bit blocks or 128-bit blocks,  

AES  and DES are block ciphers.  

MD5 is a hashing algorithm  


36. A supply company has several legacy systems connected within a warehouse. An external security audit discovered the company is using DES for data-at-rest. It mandated the company upgrade DES to meet minimum security requirements. THe company plans to replace the legacy systems next year, but needs to meet the requirements from the audit. Which of the following is MOST likely to be the simplest upgrade for these systems?  

3DES  

3DES is considered a better choice than DES for symmetric encryption because it provides stronger security through a more robust encryption process.  

DES is susceptible to brute force attacks.  


37. Bart wants to send a secure email to Lisa, so he decides to encrypt it. Bart want to ensure that Lisa can verify that he sent it. Which of the following does Lisa need to meet this requirement?  

Bart’s Public Key  


38. Bart wants to send a secure email to Lisa, so he decides to encrypt it. He wants to ensure that only Lisa can decrypt it. Which of the following does Lisa need to decrypt Bart’s email?  

Lisa’s Private Key  


39. An organization requested bids for a contract and asked companies to submit their bids via email. After winning the bid, Acme realized it couldn’t meet the requirements of the contract. Acme instead stated that it never submitted the bid. Which fo the following would provide proof to the organization that Acme did submit the bid?  

Digital Signature  


40. Application developers are creating an application that requires users to log on with strong passwords. The developers want to store the passwords in such a way that it will thwart brute force attacks. Which of the following is the BEST solution?  

PBKDF2  

Password-Based Key Derivation Function 2 is a key stretching technique designed to protect against brute force attempts and is the best choice of the given answers.  

Another alternative is bcrypt. Both salt the password with additional bits.  

3DES is an encryption protocol.  

Passwords stored using MD5 are easier to crack because they don’t use salts.  

Storing the passwords in an encrypted database field is a possible solution, but just storing them in encrypted database fields does not protect them at all.  


41. Administrators have noticed a significant amount of OCSP traffic sent to an intermediate CA. They want to reduce this traffic. Which of the following is the BEST choice to meet this need?  

Stapling  

Online Certificate Status Protocol stapling reduces OCSP traffic sent to a Certificate Authority (CA). Certificate presenters append a timestamped, digitally signed OCSP response to a certificate.  

Public key pinning includes a list of public key hashes in HTTPS responses from the web server. While pinning helps validate certificates, it is unrelated to OCSP.  

Digital signatures won’t reduce traffic.  

Hashing is used for integrity and it won’t reduce OCSP traffic  


42. A web site is using a certificate. Users have recently been receiving errors from the web site indicating that the web site’s certificate is revoked. Which of the following includes a list of certificates that have been revoked?  

CRL  

A certificate revocation list (CRL) is a list of certificates that a CA has revoked.  

The CA stores a database repository of revoked certificates and issues the CRL to anyone who requests it.  

The OCSP validates trust with certificates, but only returns short responses such as good, unknown, or revoked.  

A certificate signing request (CSR) is used to request certificates.  



An organization recently updated its security policy. One change is a requirement for all internal web servers to only support HTTPS traffic. However, the organization does not have funds to pay for this. Which of the following is the BEST solution?  

Create certificates signed by an internal private CA.  

The best solution is to use certificates signed by an internal private CA. This ensures connections use HTTPS instead of HTTP. Even if the organization doesn’t have an internal CA, it is possible to create one on an existing server without incurring any additional costs.**

Rodney, a security engineer, is viewing this record from the firewall logs:  
  
UTC 04/05/2018 03:09:15809 AV Gateway Alert 136.127.92.171 80 -> 10.16.10.14 60818 Gateway Anti-Virus Alert: XPACK.A_7854 (Trojan) blocked.  
  
Which of the following can be observed from this log information?