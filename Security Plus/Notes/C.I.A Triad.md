### The Confidentiality, Integrity, Availability Triad

#### Confidentiality:

When it comes to Confidentiality, information should only be known to certain people.

A **Confidentiality Breach** is when some authorized person has access to your data or can view your PII data. Ways to reduce this is by:

##### **Least privilege:**
- Users are given only the permissions they need to perform their actual duties.
##### **Need to know:**
- Data access is restricted to those who need it.
##### **Separation of duties:
- Tasks broken into components performed by different people.
##### **Encryption/Decryption**
- Makes sure data is made unreadable without proper key
- Decryption is taking cipher text and converting it back into plain text.
- Encryption obfuscates/scrambles the plain text data and converts it into cipher text that is unreadable.
- Encryption protects the confidentiality of the data. Encryption has nothing to do with integrity of the data.
- Encryption is a two-way function.
- Encrypted Text is called Ciphertext  

##### **Encryption Types:**
- **Symmetric:** Symmetric keys use a single shared key for both the encryption and decryption of data, where the same key is used by both the sender and the recipient.
- Think PSK [[Acronyms#^PSK]]. 
- Generally faster and more computationally efficient for large-scale data encryption.  

  ###### **Encryption Examples:**
	**AES (Advanced Encryption Standard):**
		- Fast, efficient, strong symmetric block cipher
		- 128-bit block cipher
		- Uses 128-bit, 192-bit, or 256-bit keys
		  
	**Blowfish & Twofish**
		- **Blowfish:**
			- 64-bit block cipher
			- Faster than AES in some situations
		- **TwoFish:**
			- 128-bit block cipher
			  
	**DES & 3DES:**
		- **DES (Data Encryption Standard):**
			- 64-bit block cipher
			- Uses 56-bit keys and should not be used today
		- **3DES (Triple Data Encryption Standard):**   
			- 64-bit block cipher
			- Originally designed as a replacement for DES
			- Uses multiple keys and multiple passes
			- Not as efficient as AES
			- 3DES is still used in some applications, such as when hardware doesn't support AES
			- It is an encryption protocol.
			  
- **Asymmetric:** Asymmetric encryption provides a more secure solution for key distribution and enables secure communication between parties without the need to share a secret key. Sender and Receiver have their own Private & Public Keys.
	  
  ###### Encryption Examples:
	**RSA (Rivest, Shamir, Adleman):**
		- Widely used to protect Internet traffic and e-mail.
		- Relies on mathematical properties of prime numbers when creating public and private keys.
		- *Public* and *Private keys* created as a matched pair.
		- Keys commonly used with asymmetric encryption.
	
	**Deffie Hellman
	Diffie-Hellman Ephemeral (DHE)
	Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)**
	
	**ECC:**
		- Elliptic curve cryptography (ECC)
		- Commonly used with small wireless devices
		- Uses smaller key sizes requires less processing power
	
	- **Steganography**
		- Secret messages concealed inside of ordinary ones
#### Integrity: 
	
###### **Hashing:** 
- Hashing is primarily used for data integrity verification. It produces a fixed-output (hash value) based on the input data.  

- Commonly used to verify the integrity of data by comparing hash values.
 
- It makes sure data is stored and transferred as intended and, that any modification is authorized.
 
- Hashing is the process of calculating the hash of the data/ Has is a unique representation or number that changes when the data is altered.
 
- Hashing helps us detect the integrity of the data. It is a one way function. Hashed value cannot be decrypted. Hashing has nothing to do with the confidentiality of the data.

- Hashing is a one-way function

- Hash collision is when two different inputs produce the same hash value from a hash function. In other words, the hash function maps two distinct inputs to the same output hash. This is inherent in hash functions due to the finite range of possible hash values and the infinite number of potential inputs.

###### **Hashing Types:**
- **MD5 & SHA1:**
	Message Digest 5
		- Easier to crack because it doesn't use salts.
	Secure Hash Algorithm (SHA) Family
	- Hashing - Integrity Creates 128-bit hashes
	  
- **Secure Hash Algorithm 512**
  
- **NTLM:**
	- Improvements over LANMAN
	- Prone to Pass the Hash Vulnerability. Do not use it [[Types of Attacks#^PTH]] 

**Access controls:**
	- Access restricted to authorized users Integrity protects the data from unauthorized change/alteration/deletion/modification  





- Steganography is hiding data inside pictures or multimedia files.  


- There is NO WAY to eliminate the risk, Risk cannot be zero.  


- Security Logs are the best source of evidence and non-repudiation.


- Logs are machine data.  


###### **SIEM - Security Information and Event Management

- SIEM allows you to ingest the logs, index them, aggregate, search and visualize to find the right incident and event.
   ^SIEM
- SIEM is a tool that allows you to collect, index and analyze the log data to detect anomalies and events/incidents of importance using visual dashboards.
  
- SPLUNK is one of the best SIEM tools.

###### **Code signing

- Code signing is a security practice used in software development to verify the integrity and authenticity of a piece of code.  

###### Key stretching


- Use additional rounds to strengthen keys

- Makes attacker do more work so slows down brute force  

- Salting


- Add a random value to each password when hashing it for storage

- Prevents use of pre-computed hash tables

- Use BCRYPT & PBKDF

#### Availability:

- Availability means information is accessible to those authorized to view or modify it.
- High Availability creates Fault Tolerance.
  
- Availability of data protects the data/servers from unplanned outages. The way to deal with availability challenges is to have:
	- Redundancy
	- Load Balancing 
	- Active-Active or Active-Passive
##### RAID

- **RAID 0 (Striping)** - Distributes data across multiple disk to enhance performance, offers no data redundancy, meaning the failure of one drive results in the loss of all data  

	- Ex: We have 2 disks, if Disk1 fails so will every other disk.  
		- ![[Raid 0.png]]

- **RAID 1 (Mirroring)** - Mirror data on two or more drives to provide redundancy, ensuring that if one drive fails, the data is still accessible from the mirrored drive(s).  

	- Ex: We have 2 disks. If Disk1 fails a copy is available on Disk2 to pick up the slack.  
		- ![[Raid 1.png]]

- **RAID 5 (Striping and Parity)** - Stripes data across multiple drives like RAID 0, but also includes distributed parity for fault tolerance, allowing the array to withstand the failure of one drive without data loss.  

	- Ex: We have 3 disks although they are different they have the parity so that failure at each level is reduced. 
	-       ![[Raid 5.png]]

- **RAID 1+0/10 (Mirrored Stripes)** - Combines mirroring and striping by creating a mirrored set of striped drives, offering both performance improvement and data redundancy, requiring a minimum of four drives.  

	- Ex: We have 4 disks two of which are mirrored to provide data redundancy and two which are striped to provide enhanced performance.  
##### Generators/UPS
##### Patching
- Software updates to close vulnerabilities or bugs that may be found
##### Non-repudiation:
- Subjects cannot deny creating or modifying data
- Ignorance is not a strategy  
