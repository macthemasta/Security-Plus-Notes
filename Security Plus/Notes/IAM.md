#security #access
#### IAM - Identity & Access Management  

#### Exploring Authentication Concepts

- **Identification** - User professes an identity 
- **Authentication** - User proves identity
- **Authorization** - Access to resources grated based on proven identity
- **Non-Repudiation** - Something you cannot deny. It is Proof of Origin. The evidence can be tracked to the source and the source cannot deny/dispute.
- **Accounting** - Logging all the activities to ensure there is clear evidence.
#### AAA - Authentication, Authorization, Accounting

- ##### **Authentication** - will ensure you are the right person. 
  
  **Factors of Authentication

  **Something you should know - Such as username & password

	**Passwords**
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
  
- ##### **Authorization** - will grant the right permissions between subjects and objects.

  ###### **Something you have - Such as a smart card**
	
	- Smart cards - CACs and PIVs
	- Tokens or Key fobs - Commonly combined with something you know (MFA)
	- HOTP and TOTP used in hardware tokens
	- HOTP: HMAC-based one-time password algorithm
	- HMAC-based One-Time Password
	- TOTP: Time-based One-Time Password Algorithm
	- Time-based One-Time Password
	- Expires after 30 seconds
	
	The main difference between HOTP and TOTP is that the HOTP passwords can be valid for an unknown amount of time, while the TOTP passwords keep on changing and are only valid for a short window in time. Because of this difference generally speaking the TOTP is considered as a more secure One-Time Password.
	
	###### **Something you are - Such as a fingerprint or other biometric identification

  **Biometrics**
	- Fingerprint, thumbprint, or handprints
	- Retinal scanners (scans the retina of one or both eyes)
	- Iris scanners (scans the iris of one or both eyes)
	- Issues with Biometrics
	- False acceptance - Allows the wrong person
	- False rejection - Rejects the correct person
	- Crossover error rate - This measures the accuracy and the inaccuracy. The lower the CER the better the accuracy.
	- CER measures the overall accuracy of the biometric systems including the false positive and the false negative.

- ###### Somewhere you are - Such as your location obtained using geolocation
- ###### Something you do - Such as gestures on a touch screen

- ##### **Accounting** - is keeping track of what you are doing once you are given the access. (log data)
  
  ###### **Logs
	- Logs keep track of all the activity and events on the system (Windows, Linux, VM, Firewalls, IDS
	- Logs are read only
	- Impossible Travel Time Policy - Logs show a user in a location that is too far to find


  

