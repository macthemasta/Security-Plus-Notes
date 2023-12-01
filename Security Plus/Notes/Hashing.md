#hashing
###### **Hashing** 
- Hashing is primarily used for data integrity verification. It produces a fixed-output (hash value) based on the input data.  

- Commonly used to verify the integrity of data by comparing hash values.
 
- It makes sure data is stored and transferred as intended and, that any modification is authorized.
 
- Hashing is the process of calculating the hash of the data/ Has is a unique representation or number that changes when the data is altered.
 
- Hashing helps us detect the integrity of the data. It is a one way function. Hashed value cannot be decrypted. Hashing has nothing to do with the confidentiality of the data.

- Hashing is a one-way function

- Hash collision is when two different inputs produce the same hash value from a hash function. In other words, the hash function maps two distinct inputs to the same output hash. This is inherent in hash functions due to the finite range of possible hash values and the infinite number of potential inputs.
##### **Hashing Types:**
- **MD5 & SHA1:**
	Message Digest 5
		- Easier to crack because it doesn't use salts.
	Secure Hash Algorithm (SHA) Family
	- Hashing - Integrity Creates 128-bit hashes
	  
- **Secure Hash Algorithm 512**
  
- **NTLM:**
	- Improvements over LANMAN
	- Prone to Pass the Hash Vulnerability. Do not use it [[Types of Attacks#^PTH]] 