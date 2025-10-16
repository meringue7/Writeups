<p align="center">
  <img src="img/Tombwatcherbadge.png" alt="Description de l'image" width="300"/>
</p>

# Intro

Forest was my first AD machine after completing the CPTS path of HTB.
It's a well-known machine for getting started with Active Directory environments. It is an easy-rated machine. The pentest was performed in a black box context as I had no credentials, only the machine's IP address.
I started with an **ASREP-Roasting** and discovered that the `svc_alfresco` user did not require Kerberos pre-authentication.  I was able to successfully crack its TGT offline.
Using this account, I enumerated the domain's ACLs and found that svc_alfresco, through several groups, was a member of the `Account Operators` group. This group held `GenericAll` privileges over the `Exchange Windows Permissions` group and had permission to add users in the domain. Since the Exchange Windows Permissions group has DCSync rights, I leveraged my Account Operators privileges to create a new user and add it to that group. This allowed me to perform a DCSync attack with the new user's credentials, retrieve the Administrator's NTLM hash, and fully compromise the domain.

# Walkthough

## Enumeration

I start to enumerate services on the host with nmap

```bash
# nmap -sV -sC -p- -oA nmap/target 10.10.11.72

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-11 15:01:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-11T15:03:05+00:00; +3h59m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-11T15:03:05+00:00; +3h59m49s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-06-11T15:03:05+00:00; +3h59m49s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-06-11T15:03:05+00:00; +3h59m49s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 3h59m48s, deviation: 0s, median: 3h59m48s
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-06-11T15:02:28
|_  start_date: N/A
```

This is a domain controler as there are LDAP and Kerberos services on this host.
Also there is a website on the port 80.

## Enumerating ACLs with Bloodhound

As I found nothing interesting in SMB, HTTP nor lDAP, I start to enumerate ACLs with bloodhound-python.
I use the give user account `henry`.

```bash
 bloodhound.py --zip -c All -d tombwatcher.htb -u 'henry' -p 'H3nry_987TGV!' -dc tombwatcher.htb -ns 10.10.11.72
```

Bloodhound show me a clear path to a foothold on the DC.




