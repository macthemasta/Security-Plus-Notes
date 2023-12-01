##### RAID Redundant Array of Independent Disk

- **RAID 0 (Striping)** - Distributes data across multiple disk to enhance performance, offers no data redundancy, meaning the failure of one drive results in the loss of all data  

	- Ex: We have 2 disks, if Disk1 fails so will every other disk.  
		- ![[Raid 0.png]]

- **RAID 1 (Mirroring)** - Mirror data on two or more drives to provide redundancy, ensuring that if one drive fails, the data is still accessible from the mirrored drive(s).  

	- Ex: We have 2 disks. If Disk1 fails a copy is available on Disk2 to pick up the slack.  
		- ![[Raid 1.png]]

- **RAID 5 (Striping and Parity)** - Stripes data across multiple drives like RAID 0, but also includes distributed parity for fault tolerance, allowing the array to withstand the failure of one drive without data loss.  

	- Ex: We have 3 disks although they are different they have the parity so that failure at each level is reduced. 
	-       ![[Raid 5.png]]

- **RAID 1+0/10 (Mirrored Stripes)** - Combines mirroring and striping by creating a mirrored set of striped drives, offering both performance improvement and data redundancy, requiring a minimum of four drives.   ^RAID10

	- Ex: We have 4 disks two of which are mirrored to provide data redundancy and two which are striped to provide enhanced performance.  
	-       ![[Raid 10.png]]
