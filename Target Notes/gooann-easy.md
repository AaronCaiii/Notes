# gooann-easy
## NMAP
```
└─$ sudo nmap -A -sV -T4 -p- 192.168.146.51                      
Starting Nmap 7.91 ( https://nmap.org ) at 2022-07-15 15:41 HKT
Nmap scan report for www.insanityhosting.vm (192.168.146.51)
Host is up (0.00018s latency).
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
1   0.17 ms 192.168.146.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.63 seconds


└─$ sudo nmap 192.168.146.51 --script ssh-hostkey --script-args ssh_hostkey=all                                                            255 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2022-07-15 15:49 HKT
Nmap scan report for 192.168.146.51
Host is up (0.000083s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   1024 06:cb:9e:a3:af:f0:10:48:c4:17:93:4a:2c:45:d9:48 (DSA)
| 1024 SHA256:U8TomE/biDpPMHf6LG9Vr/BnCESUBMQN2DUeU9sIb9k (DSA)
| 1024 xoroh-sorab-dysez-tozur-kahih-vacog-nakuf-nogug-dulab-nedov-tuxix (DSA)
| 
| +--[ DSA 1024]----+
| |o=E*o            |
| |o+ooo            |
| |o.o   .          |
| |.o   . o         |
| |. .   o S        |
| |   . . o         |
| |  o   +          |
| |   + . .         |
| |    +o.          |
| +-----------------+
| 
| ssh-dss AAAAB3NzaC1kc3MAAACBAO7z5YzRXLGqibzkX44TJn616aaDE3rvYcPwMiyWE3/J+WrJNkyMIRfqggIho1dxtYOA5xXP+UCk3osMe5XlMlocy3McGlmqhSrMFbQOOFrvm/PMAF649Xq/rDm2M/m+sXgxvQmJyLV36DqwbxxCL1wrICNk4cxfDG1K2yTGVw/rAAAAFQDa/l4YfWS1CNCRhv0XZbwXkGdxfwAAAIEAnMQzPH7CGQKfsHXgyFl3lsOMpj0ddXHG/rWZvFn+8NdAh48do0cN88Bti8C4Asibcp0zbEEga9KgxeR+dQi2lg3nHRzHFTPTnjybfUZqST4fU1VE9oJFCL3Q1cWHPfcvQzXNqbVDwMLSqpRYAbexXET64DgwX4fw8FSV6efKaQQAAACAVGZB5+2BdywfhdFT0HqANuHvcLfjGPQ8XkNTcO+XFSWxNFwTnLOzZE8FVNsTIBdMjXKjbWOwLMkzb4EHhkeyJglqDWvBoVTiDpXbRxctFiGt0Z83EvTJJSEAGYDCMHkux/dcVYe0WNjJYX9GBjXB2yhL/2kZuH0lzoNx9fITQ/U=
|   2048 b7:c5:42:7b:ba:ae:9b:9b:71:90:e7:47:b4:a4:de:5a (RSA)
| 2048 SHA256:Z/yyRtN729kDcVqF7qEnSRKSYl+RZwVGVqghkYy0qSY (RSA)
| 2048 xusil-papul-tihyh-cakul-kadot-nebyk-sebar-divyr-fufih-zotid-tuxix (RSA)
| 
| +--[ RSA 2048]----+
| |                 |
| |                 |
| |          . o    |
| |         o * .   |
| |        S * *    |
| |         * O     |
| |        . * E    |
| |         = =     |
| |        *=+      |
| +-----------------+
| 
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCwlghTOhfNbdMRHJF0N2ho6RlE8HR+wVE5aoFt/PPu6dveDLV7xt7GLS8Q849r1tAScErRUVryrD6gwQ0DB45hGrw8POQlnUHggTjyNp3+sshrWqRs5Dp93LL3NvhpBXl6YD9bJEC3e2qXY3Vwm+Wc/GE/9SxlB+aHL/ekjgNVWgpMT1y/fCKAWlF4TLKUl7Xc21GGWnQptGyYweSbefo4TPa7neg+YdpZkqMWaoK/eEbG+Ze5ocSEWrmB3jQMDHhgeZDO/gB3iuxSDrOToSZmsNcW6TtgqyVyo1q26VIjVRWZPlm9wyR1YB4M85uXZG2DSYu4TFKDwKhXBCqgnSHx
|   256 fa:81:cd:00:2d:52:66:0b:70:fc:b8:40:fa:db:18:30 (ECDSA)
| 256 SHA256:G8HZXu6SUrixt/obia/CUlTgdJK9JaFKXwulm6uUrbQ (ECDSA)
| 256 xipih-loben-gaped-fefiv-bocap-rykef-maveb-pebyp-human-topot-dixox (ECDSA)
| 
| +--[ECDSA  256]----+
| |.oo +            |
| | o.= o           |
| |o .o+ .          |
| |E ...o           |
| | = .  . S        |
| |  +    *         |
| |   =  o +        |
| |  o .  . .       |
| |        .        |
| +-----------------+
| 
|_ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAf1vV7lVrnTZwOIFZj7gvuahGAK2YAv8dBxFD5jV7Ho5nXHPCulaGcA9aYW9z2ih2JL/0+3zfdPfk3JBYVyrM8=
80/tcp open  http
MAC Address: 00:0C:29:7B:31:42 (VMware)

Nmap done: 1 IP address (1 host up) scanned in 7.02 seconds

```
