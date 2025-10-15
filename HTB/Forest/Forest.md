<p align="center">
  <img src="img/Forest.png" alt="Description de l'image" width="300"/>
</p>

# Intro

Forest was my first AD machine after completed the CPTS path of HTB.
It's a well known machine for getting started with Active Directory environments. It is an easy-rated machine. The pentest is performed in a black box context as we have no credentials, only the machine's IP address.
I started by a ASREP-Roasting and found that `svc_alfresco` do not requirer Kerberos pre-auth and succesfuly cracked offline his TGT.
After that I used his account to harvest all the domain ACLs and discovered that `svc_alfresco` is a part of the `Account Operators` which has the `GenericAll` over the `Exchange Windows Permissions`.
This group has the `DCSync` ACL over the domain. So I performed a DCSync attack to recover the `Administrator` NT hash and fully compromised the domain

# Walkthough

## Enumeration

I began to enumerate services on the host with the `nmap` tool.

#### Nmap
```bash
# nmap -sV -T 4 -p- 10.10.10.161

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-09-17 11:08:58Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49686/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49831/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows
```


