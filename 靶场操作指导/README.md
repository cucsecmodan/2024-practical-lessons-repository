# 3.12-Practical-利用Hashcat爆破各类密码

-----
# 简介
Hashcat是自称世界上最快的密码恢复工具。它在2015年之前拥有专有代码库，但现在作为免费软件发布。适用于Linux，OS X和Windows的版本可以使用基于CPU或基于GPU的变体。支持hashcat的散列算法有Microsoft LM哈希，MD4，MD5，SHA系列，Unix加密格式，MySQL和Cisco PIX等。  

hashcat支持多种计算核心：  

```
GPU
CPU
APU
DSP
FPGA
Coprocessor
```   

GPU的驱动要求:

```
AMD GPUs on Linux require "RadeonOpenCompute (ROCm)" Software Platform (1.6.180 or later)
AMD GPUs on Windows require "AMD Radeon Software Crimson Edition" (15.12 or later)
Intel CPUs require "OpenCL Runtime for Intel Core and Intel Xeon Processors" (16.1.1 or later)
Intel GPUs on Linux require "OpenCL 2.0 GPU Driver Package for Linux" (2.0 or later)
Intel GPUs on Windows require "OpenCL Driver for Intel Iris and Intel HD Graphics"
NVIDIA GPUs require "NVIDIA Driver" (367.x or later)
```

------

# 基础知识
密码破解是一种尝试获取未经授权访问的信息或系统的活动，通常包括尝试破解密码以便进入受保护的账户或系统。以下是密码破解的基础知识。

### 哈希值（Hash Value）：
定义： 哈希值是通过哈希函数将输入数据转换为固定长度的字符串的过程。哈希函数是一种单向函数，即无法从哈希值反推出原始输入。更为详细的关于hash的介绍可以参考文章[什么是 hash](https://www.zhihu.com/question/26762707/answer/890181997)。  
应用： 存储密码时，通常会存储其哈希值而不是明文密码。这样，即使数据库泄露，攻击者也无法直接获得用户的密码。

### 盐值（Salt）
定义： 盐是一个随机值，与密码结合后再进行哈希。每个用户都有不同的盐，即使两个用户使用相同的密码，由于盐的不同，其哈希值也会不同。  
作用： 防止彩虹表攻击，使相同的密码在数据库中不产生相同的哈希值。

### 迭代哈希（Iterative Hashing）
定义： 对密码进行多次迭代哈希，增加破解的计算复杂度。`BCrypt` 、 `PBKDF2` 和 `Scrypt` 是常用的迭代哈希函数。  
作用： 增加破解密码的时间和计算成本。

# 密码哈希破解：

### 字典攻击
使用预先生成的密码哈希值的字典（包含常见密码、词典单词等），与目标哈希进行比对，寻找匹配。

### 彩虹表攻击
预先计算并存储哈希链，以加速对哈希值的破解。但彩虹表攻击的空间复杂度较大，需要大量存储空间。

### 暴力攻击（Brute Force Attack）
定义： 尝试所有可能的密码组合，直到找到正确的密码。


-------

# Hashcat的安装和使用

## macOS
Mac可以直接使用brew安装：  
```bash
#安装hashcat
brew install hashcat

#查看版本
hashcat --version
```

## Linux
Kali Linux内置Hashcat,ubuntu可以使用apt安装：  
```bash
#安装hashcat
apt update && apt install hashcat

#查看版本
hashcat --version
```
或者到[hashcat官网](https://hashcat.net/hashcat)下载最新版压缩包，这里以6.2.6版为例：
```bash
#解压
tar zxvf hashcat-6.2.6.7z
cd hashcat-6.2.6

#执行二进制文件
./hashcat.bin
```

## Windows
到[hashcat官网](https://hashcat.net/hashcat)下载最新版压缩包，解压运行hashcat.exe

------

# Hashcat的攻击模式
## 常用参数
下面使常见的参数，想了解更多的参数可以hashcat --help查看
```
-a  指定要使用的破解模式，其值参考后面对参数。“-a 0”字典攻击，“-a 1” 组合攻击；“-a 3”掩码攻击。
-m  指定要破解的hash类型，如果不指定类型，则默认是MD5
-o  指定破解成功后的hash及所对应的明文密码的存放位置,可以用它把破解成功的hash写到指定的文件中
--force 忽略破解过程中的警告信息,跑单条hash可能需要加上此选项
--show  显示已经破解的hash及该hash所对应的明文
--increment  启用增量破解模式,你可以利用此模式让hashcat在指定的密码长度范围内执行破解过程
--increment-min  密码最小长度,后面直接等于一个整数即可,配置increment模式一起使用
--increment-max  密码最大长度,同上
--outfile-format 指定破解结果的输出格式id,默认是3
--username   忽略hash文件中的指定的用户名,在破解linux系统用户密码hash可能会用到
--remove     删除已被破解成功的hash
-r       使用自定义破解规则
```

## 参数-a 攻击模式
```
# | Mode
 ===+======
  0 | Straight（字段破解）
  1 | Combination（组合破解）
  3 | Brute-force（掩码暴力破解）
  6 | Hybrid Wordlist + Mask（字典+掩码破解）
  7 | Hybrid Mask + Wordlist（掩码+字典破解）
```

## 参数-m hash类型对照表
部分常见的hash类型如下,如果不指定类型，则默认是MD5，要想了解所有的参数可到[hashcat wiki](https://hashcat.net/wiki/doku.php?id=hashcat)上去看，或者直接hashcat --help查看hash对照表

## 参数-d 指定设备类型

```
 # | Device Type
 ===+=============
  1 | CPU
  2 | GPU
  3 | FPGA, DSP, Co-Processor

```


## 掩码破解
常见掩码字符如下：
```
  ? | Charset
 ===+=========
  l | abcdefghijklmnopqrstuvwxyz [a-z]          纯小写字母
  u | ABCDEFGHIJKLMNOPQRSTUVWXYZ [A-Z]          纯大写字母
  d | 0123456789                 [0-9]          纯数字
  h | 0123456789abcdef           [0-9a-f]       常见小写子目录和数字
  H | 0123456789ABCDEF           [0-9A-F]       常见大写字母和数字
  s |  !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~         特殊字符
  a | ?l?u?d?s                                  键盘上所有可见的字符
  b | 0x00 - 0xff                               可能是用来匹配像空格这种密码的
```

掩码设置举例：
```
八位数字密码：?d?d?d?d?d?d?d?d
八位未知密码：?a?a?a?a?a?a?a?a
前四位为大写字母，后面四位为数字：?u?u?u?u?d?d?d?d
前四位为数字或者是小写字母，后四位为大写字母或者数字：?h?h?h?h?H?H?H?H
前三个字符未知，中间为admin，后三位未知：?a?a?aadmin?a?a?a
6-8位数字密码：--increment --increment-min 6 --increment-max 8 ?d?d?d?d?d?d?d?d
6-8位数字+小写字母密码：--increment --increment-min 6 --increment-max 8 ?h?h?h?h?h?h?h?h
```

自定义掩码规则：
```
--custom-charset1 [chars]等价于 -1
--custom-charset2 [chars]等价于 -2
--custom-charset3 [chars]等价于 -3
--custom-charset4 [chars]等价于 -4
```

自定义掩码设置举例：
```
--custom-charset1 abcd123456!@-+。然后我们就可以用"?1"去表示这个字符集了
--custom-charset2 ?l?d，这里和?2就等价于?h
-1 ?d?l?u，?1就表示数字+小写字母+大写字母
-3 abcdef -4 123456 那么?3?3?3?3?4?4?4?4就表示为前四位可能是“abcdef”，后四位可能是“123456”
```
## 字典破解
#### 单个破解
`546ax2` 的MD5值是 `9ca5485734555ce5ea3c1d1141e7c41d`

```bash
#-a 0是指定字典破解模式，-m 0是指破解类型为MD5，rockyou.txt是一个用于破解的字典
hashcat -a 0 -m 0 9ca5485734555ce5ea3c1d1141e7c41d rockyou.txt 
```
#### 批量破解
```bash
#hash.txt为要破解的密码，rockyou.txt为字典，导出的结果输出到success.txt
hashcat -a 0 hash.txt rockyou.txt -o success.txt
```

## 组合破解
#### 字典组合破解
```bash
hashcat -a 1 9ca5485734555ce5ea3c1d1141e7c41d pwd1.txt pwd2.txt
```
pwd1.txt字典为：
```
admin
test
root
```
pwd2.txt字典为：
```
@2024
123
```
pwd1.txt和pwd2.txt组合后的字典：
```
admin@2024
admin123
test@2024
test123
root@2024
root123
```
#### 字典+掩码组合破解
```bash
#将其中一个字典换成掩码
hashcat -a 6 9ca5485734555ce5ea3c1d1141e7c41d pwd1.txt ?l?l?l
```

------

# Hashcat的实战
实战环境：VMware kali-linux-2023
## MD5
#### 8位MD5加密的数字破解
```bash
#对 22222222 进行 MD5 加密：
$ echo -n 22222222 |openssl md5
bae5e3208a3c700e3db642b6631e95b9
#使用 Hashcat 来进行破解：
hashcat -a 3 -m 0 --force 'bae5e3208a3c700e3db642b6631e95b9' '?d?d?d?d?d?d?d?d'
```

#### 8位MD5加密的大小写字母破解
```bash
$ echo -n PassWord |openssl md5
a9d402bfcde5792a8b531b3a82669585
#使用 Hashcat 来进行破解：
hashcat -a 3 -m 0 -1 '?l?u' --force  'a9d402bfcde5792a8b531b3a82669585' '?1?1?1?1?1?1?1?1'
```
#### 5-7位MD5加密的大小写字母+数字破解
```bash
#Admin88 的 MD5 值为 2792e40d60bac94b4b163b93566e65a9,这里面定义了个自定义规则 -1，此时 ?1 就表示 ?l?u?d，即大小写字母 + 数字
hashcat -a 3 -m 0 -1 '?l?u?d' --force  '2792e40d60bac94b4b163b93566e65a9' --increment --increment-min 5 --increment-max 7 '?1?1?1?1?1?1?1'
```
#### 不知道目标密码的构成情况下使用?a进行破解
```bash
hashcat -a 3 '19b9a36f0cab6d89cd4d3c21b2aa15be' --increment --increment-min 1 --increment-max 8 ?a?a?a?a?a?a?a?a
```
#### 使用字典破解
```bash
hashcat -a 0 'e10adc3949ba59abbe56e057f20f883e' password.txt
```
## Mysql4.1/Mysql5

```bash
#select authentication_string from mysql.user 查看当前数据库中的密码哈希值
hashcat -a 3 -m 300 --force '6BB4837EB74329105EE4568DDA7DC67ED2CA2AD9' ?d?d?d?d?d?d
```
## sha512crypt$6$,SHA512(Unix)
```bash
#cat /etc/shadow 获取哈希值
hashcat -a 3 -m 1800 --force '$6$mxuA5cdy$XZRk0CvnPFqOgVopqiPEFAFK72SogKVwwwp7gWaUOb7b6tVwfCpcSUsCEk64ktLLYmzyew/xd0O0hPG/yrm2X.' ?l?l?l?l
#-username参数不删除用户名
hashcat -a 3 -m 1800 --force 'qiyou:$6$QDq75ki3$jsKm7qTDHz/xBob0kF1Lp170Cgg0i5Tslf3JW/sm9k9Q916mBTyilU3PoOsbRdxV8TAmzvdgNjrCuhfg3jKMY1' ?l?l?l?l?l --username
```
## NTLM
#### 掩码破解Windows LM Hash
```bash
hashcat -a 3 -m 3000 'F0D412BD764FFE81AAD3B435B51404EE' ?l?l?l?l?l
```

#### 字典破解Windows NTLM Hash
```bash
hashcat -a 0 -m 1000 --force 'e19ccf75ee54e06b06a5907af13cef42' password.txt
```
## MSSQL
```bash
hashcat -a 3 -m 132 --force '0x01008c8006c224f71f6bf0036f78d863c3c4ff53f8c3c48edafb' ?l?l?l?l?l?d?d?d
```
## WordPress
```bash
#具体加密脚本在 ./wp-includes/class-phpass.php 的 HashPassword 函数
hashcat -a 3 -m 400 --force '$P$BYEYcHEj3vDhV1lwGBv6rpxurKOEWY/' ?d?d?d?d?d?d
```
## Discuz
```bash
#其密码加密方式 md5(md5($pass).$salt)
hashcat -a 3 -m 2611 --force '14e1b600b1fd579f47433b88e8d85291:' ?d?d?d?d?d?d
```
## RAR压缩密码
下载哈希破解工具[John](http://openwall.info/wiki/_media/john/johntheripper-v1.8.0.12-jumbo-1-bleeding-e6214ceab-2018-02-07-win-x64.7z)，此工具用于提取文件的hash值

```bash
#使用rar2john，提取rar的哈希值
rar2john.exe 1.rar
#类型为RAR5
hashcat -a 3 -m 13000 --force '$rar5$16$b06f5f2d4c973d6235e1a88b8d5dd594$15$a520dddcc53dd4e3930b8489b013f273$8$733969e5bda903e4' ?d?d?d?d?d?d
#类型为RAR3
hashcat -a 3 -m 12500 --force '$RAR3$*0*5ba3dd697a8706fa*919ad1d7a1c42bae4a8d462c8537c9cb' ?d?d?d?d
```

## ZIP压缩密码
使用zip2john，提取zip的哈希值：
```bash
zip2john.exe 1.zip
#这里 ZIP 的加密算法使用的 AES256
hashcat -a 3 -m 13600 '$zip2$*0*3*0*18b1a7e7ad39cb3624e54622849b23c7*5b99*3*5deee7*a418cee1a98710adce9a*$/zip2$' --force ?d?d?d?d?d?d
```

## office密码
提取office文件的哈希值：
```bash
# 获取 office 文件 hash
python office2john.py 1.docx
#哈希头为 2013 ,使用 9600 破解模式，2010 使用 9500 破解模式，2007使用 9400 破解模式。
hashcat -a 3 -m 9600 '$office$*2013*100000*256*16*cd8856416b1e14305a0e8aa8eba6ce5c*18cada7070f1410f3a836c0dfc4b9643*befcde69afeafb3e652719533c824413b00ce4a499589e5ac5bd7a7a0d3c4f3d' --force ?d?d?d?d?d?d
```

## WIFI密码

要破解 WIFI 密码，首先要抓到 WIFI 的握手包，要想得到 WIFI 的握手包，就需要在监听时刚好有设备连接了该 WIFI，但这就需要运气加成，因此可以我们可以主动将该 WIFI 的设备踢下去，一般设备就会自动连接该 WIFI，此时我们就抓到握手包了。在此，省略抓包过程。

### 握手包转码
将 `cap` 后缀文件转换成hashcat支持破解的后缀，使用 [hashcat 在线转换器](https://hashcat.net/cap2hashcat/)将 `cap` 文件转换为 `22000` ， `hccapx` 后缀的旧哈希模式 `2500` 已弃用，详情见[参考文档](https://hashcat.net/forum/thread-10253.html)。

### 破解密码
转换好的文件为 `test.hc22000` 根据实际情况进行掩码设置，也可以使用字典进行破解:
```bash
hashcat -a 3 -m 22000 test.hc22000 ?d?d?d?d?d?d?d?d --force
```


-------

# 总结
总结Hashcat的优缺点和使用注意事项