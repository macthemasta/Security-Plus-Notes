#VM
#### Virtualization Concepts  
  
- Host - A physical Machine/Physical Hardware.
- Guest
- Patch compatibility
- Host availability/elasticity [[Elasticity and Scalability#^elasticity]]
- Snapshots are like a point-in-time picture of your VM. Can be used as a backup/copy to test other applications on the VM.
- Used for Sandboxing to test applications and vulnerabilities.
- User Experience Virtual Desktop OS, Data, Apps
- This Client Availability & Backup OS, Provisioning & Update
- Desktop Disaster Recovery User Data & Personalization
- Laptop Security Application Virtualization
#### Hypervisor 
- A software that allows me to create and manage virtual machines on a physical host. Such as VMware.
##### Type 1 & 2 Hypervisor:

Type 1 is the most secure due a smaller attack surface. There are less areas of attack. This would be bare metal as there is no host operating system on the hardware. 
###### Examples of Type 1 Hypervisors:
- Virtual PC & Virtual Server Hyper-V
- VMware Workstation Xen
- KVM VMware ESX
- ![[HyperV1.png]]
###### Examples of Type 2 Hypervisors:
- Hyper-V
- Xen
- VMware ESX
- ![[HyperV2.png]]
#### Virtual Machines vs. Containers

- The key differentiator between containers and virtual machines is that virtual machines virtualize an entire machine down to the hardware layers and containers only virtualize software layers above the operating system level.

- If your OS goes down your Containers go down. Where as with your Hypervisor, if the OS outside your hyper-v goes down all running OSs go down.
#### Containers

- Containers give you flexibility and mobility to move your workloads from one platform to another. Containers are like virtual machines but they do not have a dedicated operating system inside each container. Instead they use a shared OS for multiple containers. Containers Host the Application.

- Containers sit on top of a physical server and its host OS–-for example, Linux or Windows. Each container shares the host OS kernel and, usually, the binaries and libraries, too. Shared components are read-only. Containers are thus exceptionally “light”--they are only megabytes in size and take just seconds to start, versus gigabytes and minutes for a VM.    

- Containers Run on your OS and they can contain multiple binaries and libraries.  

- Containers also reduce management overhead. Because they share a common operating system, only a single operating system needs care and feeding for bug fixes, patches, and so on.
#### Virtual Machines - Guest Machines

- VMs allow you to create guest computers on your physical computers. You can use them to test and create outside of your regular OS.

- Within each virtual machine runs a unique guest operating system. VMs with different operating systems can run on the same physical server –a UNIX VM can sit alongside a Linux VM, and so on. Each VM has its own binaries, libraries, and applications that it services, and the VM may be many gigabytes in size.  


#### Mobile App Containerization

Containers are used to create an authenticated and encrypted area of an employee’s device that separates sensitive corporate information from the owner’s personal data and apps.

MDM 
	- Is a software to delete and manage the mobile device data.

#### App Container vs App Wrapper

App Container: It’s a lightweight, standalone, and executable software package that includes everything needed to run a piece of software, including the code, runtime, libraries, and system tools. It provides consistency and isolation for applications across different environments.  

App wrapper: It’s a tool or framework used to encapsulate and modify an existing application, adding functionalities like security features, access controls, or integration with a specific platform. It wraps around the original app without altering its core functionality.


  

#### VDI Desktop Infrastructure (VDI)

VDI - Virtual Desktop Infrastructure: It’s a technology that allows desktop operating systems to run and be managed in a virtualized environment on a centralized server. Instead of running on individual physical computers, each user’s desktop environment is hosted on a virtual machine in a data center.

Simply put, VDI lets you access your desktop, complete with all your applications and files, from a remote server using a device like a thin client, laptop, or even a tablet. It provides flexibility, scalability, and centralized management for organizations, making it easier to deploy, maintain, and secure desktop environment